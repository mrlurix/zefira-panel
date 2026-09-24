import base64
import hashlib
import io
import json
import re
import secrets as pysecrets
import uuid as uuidlib
import zipfile
from datetime import datetime, timedelta, timezone

import qrcode
import qrcode.image.svg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import NameOID

from config import INSTANCE_DIR

PROTOCOLS = ["vless", "reality", "vmess", "trojan", "ss", "hysteria2", "wireguard", "openvpn", "l2tp", "cisco", "socks5"]
V2RAY_FAMILY = {"vless", "vmess", "trojan", "ss"}
# Relay-style protocols that accept extra per-port endpoints (inbounds).
INBOUND_PROTOCOLS = ["vless", "reality", "vmess", "trojan", "ss", "hysteria2"]
# BackPack reverse-tunnel transports accepted by tunnel nodes.
TUNNEL_TRANSPORTS = ["tcp", "tcp-mux", "tcp-stealth", "tcp-pck", "udp", "kcp", "quic", "ws", "ws-mux", "wss", "wss-mux", "icmp", "ip-spoof"]
# Protocols served without per-inbound endpoints (single server-wide
# endpoint, like WireGuard/OpenVPN): no inbound variants are generated.
SINGLE_ENDPOINT = {"wireguard", "openvpn", "l2tp", "cisco", "socks5"}
PENDING_SENTINEL = datetime(2099, 1, 1)

CA_CERT_PATH = INSTANCE_DIR / "ca.crt"
CA_KEY_PATH = INSTANCE_DIR / "ca.key"


DEFAULT_SRV = {
    "domain": "",
    "sub_port": 443,
    "hy2_port": 8443,
    "wg_port": 51820,
    "wg_pub": "",
    "dns": "1.1.1.1",
    "ovpn_port": 1194,
    "ovpn_proto": "udp",
    "l2tp_port": 1701,
    "cisco_port": 443,
    "socks5_port": 1080,
    "reality_port": 443,
    "reality_sni": "www.yahoo.com,www.samsung.com,www.microsoft.com",
    "reality_pub": "",
    "obfuscated_host": "",
    "per_user_subdomain": "0",
    "cdn_enabled": "0",
    "cdn_sni": "",
    "block_direct_ip": "0",
}


_HOST_RE = re.compile(r"\A[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\Z")


def _safe_host(host, fallback):
    """Builder-level hostname allowlist (defense in depth).

    API + restore layers already validate hosts, but builders also run on
    hand-edited DB rows and env values. Never interpolate a hostile
    hostname (spaces, newlines, @, :, /) into links or configs: fall back
    to a validated value instead of emitting corrupt output.
    """
    h = (host or "").strip()
    if h and _HOST_RE.fullmatch(h):
        return h
    f = (fallback or "").strip()
    if f and _HOST_RE.fullmatch(f):
        return f
    return "localhost"


def _safe_filename(username: str) -> str:
    """Filenames reach Content-Disposition headers and zip entries: strip
    everything outside [A-Za-z0-9_-] (same idiom as _issue_client_cert)."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", username or "")[:32] or "client"


def _effective_host(secret: str, srv: dict) -> str:
    if srv.get("_is_inbound_variant"):
        base = _safe_host(srv.get("domain"), "localhost")
        per_user = str(srv.get("per_user_subdomain", "0")).lower() in ("1", "true", "yes", "on")
        if per_user:
            prefix = hashlib.sha256(secret.encode()).hexdigest()[:8]
            return _safe_host(f"{prefix}.{base}", base)
        return base
    obf = (srv.get("obfuscated_host") or "").strip()
    if not obf:
        return _safe_host(srv.get("domain"), "localhost")
    if "://" in obf:
        try:
            from urllib.parse import urlparse

            host = urlparse(obf).hostname
            if host:
                obf = host
        except Exception:
            pass
    obf = obf.strip().strip("/")
    if not obf:
        return _safe_host(srv.get("domain"), "localhost")
    per_user = str(srv.get("per_user_subdomain", "0")).lower() in ("1", "true", "yes", "on")
    if per_user:
        prefix = hashlib.sha256(secret.encode()).hexdigest()[:8]
        return _safe_host(f"{prefix}.{obf}", _safe_host(srv.get("domain"), "localhost"))
    return _safe_host(obf, _safe_host(srv.get("domain"), "localhost"))


def _cdn_sni(srv: dict) -> str | None:
    if str(srv.get("cdn_enabled", "0")).lower() not in ("1", "true", "yes", "on"):
        return None
    cdn = (srv.get("cdn_sni") or "").strip()
    if not cdn:
        return None
    if "://" in cdn:
        try:
            from urllib.parse import urlparse

            h = urlparse(cdn).hostname
            if h:
                cdn = h
        except Exception:
            pass
    cdn = cdn.strip().strip("/")
    cdn = _safe_host(cdn, "")
    return cdn or None


def generate_reality_keypair() -> tuple:
    priv = x25519.X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    return b64u(raw_priv), b64u(raw_pub)


def resolve_srv(db_values: dict) -> dict:
    from config import DOMAIN, OVPN_PORT_DEFAULT, SUB_PORT

    srv = dict(DEFAULT_SRV)
    srv["domain"] = DOMAIN
    srv["sub_port"] = int(SUB_PORT)
    srv["ovpn_port"] = int(OVPN_PORT_DEFAULT)
    for k, v in (db_values or {}).items():
        if k in srv and v not in (None, ""):
            if k.endswith("_port"):
                try:
                    srv[k] = int(v)
                except (TypeError, ValueError):
                    pass
            else:
                srv[k] = v
    if not srv.get("domain"):
        srv["domain"] = DOMAIN
    return srv


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def provision_map(protocols: list, username: str) -> dict:
    out = {}
    for p in protocols:
        if p in ("vless", "reality", "vmess", "trojan"):
            out[p] = str(uuidlib.uuid4())
        elif p == "ss":
            out[p] = pysecrets.token_urlsafe(21)
        elif p == "hysteria2":
            out[p] = pysecrets.token_urlsafe(18)
        elif p == "wireguard":
            priv = x25519.X25519PrivateKey.generate()
            raw = priv.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            out[p] = base64.b64encode(raw).decode()
        elif p == "openvpn":
            cert_pem, key_pem = _issue_client_cert(username)
            out[p] = f"<ZEFIRA-CERT>{cert_pem}<ZEFIRA-KEY>{key_pem}"
        elif p == "l2tp":
            # L2TP/IPsec needs a user password plus an IPsec pre-shared
            # key. Stored as one JSON blob so reset-token rotates both.
            out[p] = json.dumps({
                "password": pysecrets.token_urlsafe(16),
                "psk": pysecrets.token_urlsafe(24),
            }, separators=(",", ":"))
        elif p == "cisco":
            # Cisco AnyConnect / OpenConnect password auth.
            out[p] = pysecrets.token_urlsafe(16)
        elif p == "socks5":
            out[p] = pysecrets.token_urlsafe(16)
        else:
            raise ValueError(p)
    return out


def serialize_secrets(secret_map: dict) -> str:
    return json.dumps(secret_map, separators=(",", ":"))


def _v2ray_link(protocol: str, secret: str, username: str, index: int, srv: dict) -> str | None:
    from urllib.parse import quote as _q

    host = _effective_host(secret, srv)
    cdn = _cdn_sni(srv)
    # Query values are percent-encoded (no-op for valid hosts/SNIs, fatal
    # for smuggled &/#/spaces from hand-edited rows).
    sni = _q(cdn or host, safe="")
    # Remark is exactly the username (plus inbound label when present) so
    # client apps show a clean, familiar name instead of a generated one.
    name = username
    if protocol == "vless":
        return (
            f"vless://{secret}@{host}:{srv['sub_port']}?encryption=none&security=tls"
            f"&sni={sni}&fp=chrome&type=ws&host={host}&path=%2Fzefira#{name}"
        )
    if protocol == "vmess":
        obj = {
            "v": "2",
            "ps": name,
            "add": host,
            "port": str(srv["sub_port"]),
            "id": secret,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": "/zefira",
            "tls": "tls",
            "sni": sni,
        }
        return "vmess://" + _b64(json.dumps(obj, separators=(",", ":")))
    if protocol == "trojan":
        return (
            f"trojan://{secret}@{host}:{srv['sub_port']}?security=tls&sni={sni}"
            f"&type=ws&host={host}&path=%2Fzefira&allowInsecure=0#{name}"
        )
    if protocol == "ss":
        # SIP002 mandates URL-safe base64 without padding (strict clients
        # misparse the +/= of standard base64).
        userinfo = base64.urlsafe_b64encode(f"aes-256-gcm:{secret}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{srv['sub_port']}#{username}"
    if protocol == "hysteria2":
        return (
            f"hysteria2://{secret}@{host}:{srv['hy2_port']}"
            f"?sni={sni}&insecure=0#{username}"
        )
    return None


def _reality_link(secret: str, username: str, index: int, srv: dict) -> str | None:
    from urllib.parse import quote as _q

    host = _effective_host(secret, srv)
    pub = srv.get("reality_pub") or ""
    # Hand-edited DB could smuggle extra link params via the public key
    # (generated keys are always 43-char base64url): skip output entirely
    # rather than ship a guaranteed-dead link to the customer.
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", pub or ""):
        return None
    sni_list = [s.strip() for s in (srv.get("reality_sni") or "").split(",") if s.strip()]
    sni = sni_list[(index - 1) % len(sni_list)] if sni_list else host
    sni = _q(sni, safe="")
    sid = hashlib.sha1(f"{secret}:{index}".encode()).hexdigest()[:8]
    name = username
    return (
        f"vless://{secret}@{host}:{srv['reality_port']}?"
        f"encryption=none&security=reality&pbk={pub}&sid={sid}"
        f"&sni={sni}&fp=chrome&type=tcp&flow=xtls-rprx-vision"
        f"&headerType=none#{name}"
    )


def _socks5_link(username: str, password: str, srv: dict) -> str | None:
    from urllib.parse import quote as _q

    host = _effective_host(password, srv)
    if not host:
        return None
    try:
        port = int(srv.get("socks5_port", 1080))
    except (TypeError, ValueError):
        port = 1080
    user = _q(username, safe="")
    pw = _q(password, safe="")
    return f"socks5://{user}:{pw}@{host}:{port}#{_q(username, safe='')}"


def _parse_l2tp_secret(blob: str) -> tuple:
    try:
        data = json.loads(blob)
        pw, psk = data.get("password", ""), data.get("psk", "")
    except (ValueError, AttributeError):
        raise ValueError("invalid l2tp secret")
    if not pw or not psk or len(pw) > 200 or len(psk) > 200:
        raise ValueError("invalid l2tp secret")
    return pw, psk


def _l2tp_config(u: dict, srv: dict, blob: str) -> str:
    password, psk = _parse_l2tp_secret(blob)
    host = _effective_host(psk, srv)
    try:
        port = int(srv.get("l2tp_port", 1701))
    except (TypeError, ValueError):
        port = 1701
    username = u.get("username", "")
    return "\n".join([
        f"# Zefira L2TP/IPsec - user: {username}",
        f"Server (L2TP): {host}:{port}",
        "IPsec: pre-shared key (PSK) mode, UDP 500/4500 must reach the server",
        f"Username: {username}",
        f"Password: {password}",
        f"IPsec PSK: {psk}",
        "",
        "Windows: Settings > Network > VPN > Add (L2TP/IPsec with pre-shared key).",
        "Android: Settings > Network > VPN > Add L2TP/IPsec PSK profile.",
        "iOS: Settings > General > VPN > Add L2TP (enter server, account, password, shared secret).",
        "Linux (strongSwan): right=<server> rightauth=psk, leftauth=xauth with the credentials above.",
        "",
        "# Ask the server operator to create the matching L2TP user entry",
        "# (username/password) and IPsec PSK before connecting.",
        "",
    ])


def _cisco_config(u: dict, srv: dict, password: str) -> str:
    if not password or len(password) > 200:
        raise ValueError("invalid cisco secret")
    host = _effective_host(password, srv)
    try:
        port = int(srv.get("cisco_port", 443))
    except (TypeError, ValueError):
        port = 443
    username = u.get("username", "")
    server = f"{host}:{port}" if port != 443 else host
    return "\n".join([
        f"# Zefira Cisco AnyConnect / OpenConnect - user: {username}",
        f"Server: {server}",
        f"Username: {username}",
        f"Password: {password}",
        "",
        f"OpenConnect:  openconnect --user={username} {server}",
        "AnyConnect app: add the server above, sign in with username + password.",
        "",
    ])


def _json_scalar(v) -> str:
    return json.dumps(v, ensure_ascii=False)


PORN_DOMAINS = [
    "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com",
    "youporn.com", "tube8.com", "beeg.com", "spankbang.com", "tnaflix.com",
    "xvideos2.com", "hclips.com", "empflix.com", "porntrex.com", "hdzog.com",
]

def clash_yaml(u: dict, srv: dict, blocked: list = None, inbounds: list = None) -> str:
    protos = u.get("protocols") or []
    secrets_map = u.get("secret_map") or {}
    proxies = []
    names = []

    def ws_opts(h, path="/zefira"):
        return {"path": path, "headers": {"Host": h}}

    def _hs(sec, vsrv):
        h = _effective_host(sec, vsrv)
        c = _cdn_sni(vsrv)
        return h, (c or h)

    def _each(p):
        # Same inbound variants (and offline-node filtering) as raw links:
        # Clash must neither miss endpoints nor serve dead ones.
        return _srvs_for(p, srv, inbounds)

    def _sfx(ilabel):
        return f"-{ilabel}" if ilabel else ""

    if "vmess" in protos and secrets_map.get("vmess"):
        sec = secrets_map["vmess"]
        for vsrv, ilabel in _each("vmess"):
            host_eff, sni_eff = _hs(sec, vsrv)
            n = f"Zefira-{u['username']}-VMess{_sfx(ilabel)}"
            names.append(n)
            proxies.append({
                "name": n, "type": "vmess", "server": host_eff, "port": int(vsrv["sub_port"]),
                "uuid": sec, "alterId": 0, "cipher": "auto",
                "tls": True, "servername": sni_eff, "network": "ws", "ws-opts": ws_opts(host_eff),
            })
    if "vless" in protos and secrets_map.get("vless"):
        sec = secrets_map["vless"]
        for vsrv, ilabel in _each("vless"):
            host_eff, sni_eff = _hs(sec, vsrv)
            n = f"Zefira-{u['username']}-VLESS{_sfx(ilabel)}"
            names.append(n)
            proxies.append({
                "name": n, "type": "vless", "server": host_eff, "port": int(vsrv["sub_port"]),
                "uuid": sec, "tls": True, "servername": sni_eff,
                "network": "ws", "ws-opts": ws_opts(host_eff), "client-fingerprint": "chrome",
            })
    if "reality" in protos and secrets_map.get("reality"):
        sec = secrets_map["reality"]
        for vsrv, ilabel in _each("reality"):
            host_eff = _effective_host(sec, vsrv)
            sni_list = [s.strip() for s in (vsrv.get("reality_sni") or "").split(",") if s.strip()]
            sni = sni_list[0] if sni_list else host_eff
            sid = hashlib.sha1(f"{sec}:1".encode()).hexdigest()[:8]
            # Same 43-char allowlist as the link builder: skip misconfigured
            # REALITY here too instead of shipping a dead proxy.
            rpub = vsrv.get("reality_pub") or ""
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", rpub):
                continue
            n = f"Zefira-{u['username']}-REALITY{_sfx(ilabel)}"
            names.append(n)
            proxies.append({
                "name": n, "type": "vless", "server": host_eff, "port": int(vsrv["reality_port"]),
                "uuid": sec, "flow": "xtls-rprx-vision",
                "tls": True, "servername": sni, "client-fingerprint": "chrome",
                "reality-opts": {"public-key": rpub, "short-id": sid},
            })
    if "trojan" in protos and secrets_map.get("trojan"):
        sec = secrets_map["trojan"]
        for vsrv, ilabel in _each("trojan"):
            host_eff, sni_eff = _hs(sec, vsrv)
            n = f"Zefira-{u['username']}-Trojan{_sfx(ilabel)}"
            names.append(n)
            proxies.append({
                "name": n, "type": "trojan", "server": host_eff, "port": int(vsrv["sub_port"]),
                "password": sec, "sni": sni_eff, "udp": True,
                "network": "ws", "ws-opts": ws_opts(host_eff),
            })
    if "ss" in protos and secrets_map.get("ss"):
        sec = secrets_map["ss"]
        for vsrv, ilabel in _each("ss"):
            host_eff = _effective_host(sec, vsrv)
            n = f"Zefira-{u['username']}-SS{_sfx(ilabel)}"
            names.append(n)
            proxies.append({
                "name": n, "type": "ss", "server": host_eff, "port": int(vsrv["sub_port"]),
                "cipher": "aes-256-gcm", "password": sec, "udp": True,
            })
    if "hysteria2" in protos and secrets_map.get("hysteria2"):
        sec = secrets_map["hysteria2"]
        for vsrv, ilabel in _each("hysteria2"):
            host_eff, sni_eff = _hs(sec, vsrv)
            n = f"Zefira-{u['username']}-Hy2{_sfx(ilabel)}"
            names.append(n)
            proxies.append({
                "name": n, "type": "hysteria2", "server": host_eff, "port": int(vsrv["hy2_port"]),
                "password": sec, "sni": sni_eff,
            })
    if "socks5" in protos and secrets_map.get("socks5"):
        sec = secrets_map["socks5"]
        host_eff = _effective_host(sec, srv)
        n = f"Zefira-{u['username']}-SOCKS5"
        names.append(n)
        proxies.append({
            "name": n, "type": "socks5", "server": host_eff, "port": int(srv.get("socks5_port", 1080)),
            "username": u["username"], "password": sec, "udp": True,
        })

    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
    ]
    try:
        _dev_lim = u.get("device_limit")
        if _dev_lim:
            lines.append(f"# zefira-device-limit: {int(_dev_lim)}")
    except (TypeError, ValueError):
        pass
    lines.append("proxies:")
    for p in proxies:
        lines.append("  - " + _json_scalar(p))
    lines.append("proxy-groups:")
    # An empty proxy list (e.g. only misconfigured REALITY) must still
    # parse: fall back to DIRECT so clients never choke on `proxies: []`.
    group_proxies = names if names else ["DIRECT"]
    lines.append("  - " + _json_scalar({"name": "Zefira", "type": "select", "proxies": group_proxies}))
    lines.append("rules:")
    if blocked:
        # Builder-level filter (defense in depth): only plain hostnames
        # become rules, capped — a hand-edited DB row with newlines or
        # commas must not inject extra YAML rules. Live + restore paths
        # already validate, this is the last gate before client output.
        clean_blocked = [
            d for d in blocked
            if isinstance(d, str) and _HOST_RE.fullmatch(d.strip().lower())
        ][:600]
        for d in clean_blocked:
            lines.append(f"  - DOMAIN-SUFFIX,{d.strip().lower()},REJECT")
    lines.append('  - MATCH,Zefira')
    return "\n".join(lines) + "\n"


def true_val():
    return True


FILE_EXT = {
    "vless": ".txt", "reality": ".txt", "vmess": ".txt", "trojan": ".txt", "ss": ".txt",
    "hysteria2": ".txt", "wireguard": ".conf", "openvpn": ".ovpn",
    "l2tp": ".txt", "cisco": ".txt", "socks5": ".txt",
}
def _valid_wg_pubkey(v: str | None) -> str:
    try:
        if not v:
            return ""
        vv = v.strip()
        if len(vv) != 44:
            return ""
        if len(base64.b64decode(vv, validate=True)) != 32:
            return ""
        return vv
    except Exception:
        return ""


def _wg_config(u: dict, srv: dict, secret: str) -> str:
    try:
        raw = base64.b64decode(secret, validate=True)
        if len(raw) != 32:
            raise ValueError("bad key length")
        priv_obj = x25519.X25519PrivateKey.from_private_bytes(raw)
    except Exception:
        raise ValueError("invalid wireguard secret")
    pub = priv_obj.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    peer_valid = _valid_wg_pubkey(srv.get("wg_pub"))
    peer = peer_valid or base64.b64encode(b"\x01" + b"\x00" * 31).decode()
    uid = int(u.get("id", 0) or 0)
    # /32 pool: first octet stays 10.7.* for the first 62500 ids (backward
    # compatible), then rolls into 10.8/10.9... so churn past the id cap
    # never aliases two users onto the same address.
    addr = f"10.{7 + (uid // 62500) % 249}.{(uid // 250) % 250}.{(uid % 250) + 2}"
    host = _effective_host(secret, srv)
    dns = _safe_host(srv.get("dns"), "1.1.1.1")
    lines = [
        "[Interface]",
        f"PrivateKey = {secret}",
        f"Address = {addr}/32",
        f"DNS = {dns}",
        "MTU = 1420",
        f"# Client PublicKey = {base64.b64encode(pub).decode()}",
        "",
    ]
    if not peer_valid:
        lines.append("# WARNING: Replace PublicKey below with your WireGuard server public key")
        lines.append("# (Panel -> Settings -> Server / Hosts Settings -> WireGuard server public key)")
    lines.extend([
        "[Peer]",
        f"PublicKey = {peer}",
        f"Endpoint = {host}:{srv['wg_port']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
        "",
    ])
    return "\n".join(lines)


def _ensure_ca():
    key = None
    if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        return cert, key
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Zefira-CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    CA_KEY_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        import os

        os.chmod(CA_KEY_PATH, 0o600)
        os.chmod(CA_CERT_PATH, 0o644)
    except OSError:
        pass
    return cert, key


def _issue_client_cert(username: str):
    ca_cert, ca_key = _ensure_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    safe = "".join(ch for ch in username if ch.isascii() and (ch.isalnum() or ch in "-_"))[:32] or "client"
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, safe)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _ovpn_config(u: dict, srv: dict, blob: str) -> str:
    marker_c = "<ZEFIRA-CERT>"
    marker_k = "<ZEFIRA-KEY>"
    try:
        cert_pem = blob.split(marker_c)[1].split(marker_k)[0].strip()
        key_pem = blob.split(marker_k)[1].strip()
    except (IndexError, AttributeError):
        raise ValueError("invalid openvpn secret")
    if "-----BEGIN CERTIFICATE-----" not in cert_pem or "-----BEGIN PRIVATE KEY-----" not in key_pem:
        raise ValueError("invalid openvpn secret")
    host = _effective_host(blob, srv)
    proto = srv.get("ovpn_proto", "udp")
    if proto not in ("udp", "tcp"):
        proto = "udp"
    lines = [
        "client",
        "dev tun",
        f"proto {proto}",
        f"remote {host} {srv['ovpn_port']}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        "verify-x509-name Zefira-CA name",
        "auth SHA256",
        "cipher AES-256-GCM",
        "data-ciphers AES-256-GCM:AES-128-GCM",
        "verb 3",
        "",
        "<ca>",
        CA_CERT_PATH.read_text().strip(),
        "</ca>",
        "<cert>",
        cert_pem.strip(),
        "</cert>",
        "<key>",
        key_pem.strip(),
        "</key>",
        "",
    ]
    return "\n".join(lines)


def _variant_srv(srv: dict, inbound: dict) -> dict:
    v = dict(srv)
    v["sub_port"] = int(inbound["port"])
    v["reality_port"] = int(inbound["port"])
    v["hy2_port"] = int(inbound["port"])
    if inbound.get("host"):
        v["domain"] = inbound["host"]
        v["_is_inbound_variant"] = True
    return v


def _srvs_for(proto: str, srv: dict, inbounds: list) -> list:
    if proto in SINGLE_ENDPOINT:
        return [(srv, "")]
    out = [(srv, "")]
    for i in (inbounds or []):
        if i.get("enabled") and i.get("protocol") == proto:
            # Inbounds pinned to an explicitly offline/disabled server node
            # are skipped so users never get dead endpoints. Unchecked
            # nodes (unknown) still serve links: monitoring is advisory
            # until the first check runs.
            if i.get("node_id") and (not i.get("node_enabled", True) or i.get("node_status") == "offline"):
                continue
            out.append((_variant_srv(srv, i), i["name"]))
    return out


def build_files(u: dict, srv: dict, inbounds: list = None) -> list:
    protos = u.get("protocols") or ["vless"]
    secrets_map = u.get("secret_map") or {}
    # Filenames land in Content-Disposition headers and zip entries: keep
    # them to a strict charset even if a legacy/hand-edited row carries a
    # username outside USERNAME_RE (header injection / zip-slip class).
    safe_user = _safe_filename(u.get("username", ""))
    files = []
    links = []
    for p in protos:
        sec = secrets_map.get(p)
        if not sec:
            continue
        if p in V2RAY_FAMILY:
            # One link per endpoint: _v2ray_link ignores `index`, so looping
            # only emitted byte-identical duplicates (3 indistinguishable
            # profiles per endpoint in every client).
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                link = _v2ray_link(p, sec, u["username"] + suffix, 1, vsrv)
                if link:
                    links.append(link)
        elif p == "reality":
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                for i in range(1, 4):
                    link = _reality_link(sec, u["username"] + suffix, i, vsrv)
                    if link:
                        links.append(link)
        elif p == "hysteria2":
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                link = _v2ray_link("hysteria2", sec, u["username"] + suffix, 1, vsrv)
                if link:
                    links.append(link)
        elif p == "wireguard":
            try:
                files.append((f"{safe_user}-wg.conf", _wg_config(u, srv, sec)))
            except (ValueError, OSError):
                continue
        elif p == "openvpn":
            try:
                files.append((f"{safe_user}.ovpn", _ovpn_config(u, srv, sec)))
            except (ValueError, OSError):
                continue
        elif p == "l2tp":
            try:
                files.append((f"{safe_user}-l2tp.txt", _l2tp_config(u, srv, sec)))
            except (ValueError, OSError):
                continue
        elif p == "cisco":
            try:
                files.append((f"{safe_user}-cisco.txt", _cisco_config(u, srv, sec)))
            except (ValueError, OSError):
                continue
        elif p == "socks5":
            link = _socks5_link(u["username"], sec, srv)
            if link:
                links.append(link)
    if links:
        files.insert(0, (f"{safe_user}-subscription.txt", "\n".join(links) + "\n"))
    return files


PROTO_LABELS = {
    "vless": "VLESS", "reality": "REALITY", "vmess": "VMess",
    "trojan": "Trojan", "ss": "Shadowsocks", "hysteria2": "Hysteria2",
    "wireguard": "WireGuard", "openvpn": "OpenVPN",
    "l2tp": "L2TP/IPsec", "cisco": "Cisco AnyConnect", "socks5": "SOCKS5",
}


def user_links(u: dict, srv: dict, inbounds: list = None) -> dict:
    """Per-protocol shareables for the user dashboard.

    Returns {label: {"links": [...], "config": str | None}} using the exact
    same builders as subscription files, so dashboard and sub never drift.
    """
    protos = u.get("protocols") or ["vless"]
    secrets_map = u.get("secret_map") or {}
    out = {}
    for p in protos:
        sec = secrets_map.get(p)
        if not sec:
            continue
        label = PROTO_LABELS.get(p, p)
        if p in V2RAY_FAMILY:
            links = []
            # One link per endpoint (see build_files: the index is unused).
            for vsrv, ilabel in _srvs_for(p, srv, inbounds):
                suffix = f"-{ilabel}" if ilabel else ""
                link = _v2ray_link(p, sec, u["username"] + suffix, 1, vsrv)
                if link:
                    links.append(link)
            if links:
                out[label] = {"links": links, "config": None}
        elif p == "reality":
            links = []
            for vsrv, ilabel in _srvs_for(p, srv, inbounds):
                suffix = f"-{ilabel}" if ilabel else ""
                for i in range(1, 4):
                    link = _reality_link(sec, u["username"] + suffix, i, vsrv)
                    if link:
                        links.append(link)
            if links:
                out[label] = {"links": links, "config": None}
        elif p == "hysteria2":
            links = []
            for vsrv, ilabel in _srvs_for(p, srv, inbounds):
                suffix = f"-{ilabel}" if ilabel else ""
                link = _v2ray_link("hysteria2", sec, u["username"] + suffix, 1, vsrv)
                if link:
                    links.append(link)
            if links:
                out[label] = {"links": links, "config": None}
        elif p == "wireguard":
            try:
                out[label] = {"links": [], "config": _wg_config(u, srv, sec)}
            except (ValueError, OSError):
                continue
        elif p == "openvpn":
            try:
                out[label] = {"links": [], "config": _ovpn_config(u, srv, sec)}
            except (ValueError, OSError):
                continue
        elif p == "l2tp":
            try:
                out[label] = {"links": [], "config": _l2tp_config(u, srv, sec)}
            except (ValueError, OSError):
                continue
        elif p == "cisco":
            try:
                out[label] = {"links": [], "config": _cisco_config(u, srv, sec)}
            except (ValueError, OSError):
                continue
        elif p == "socks5":
            link = _socks5_link(u["username"], sec, srv)
            if link:
                out[label] = {"links": [link], "config": None}
    return out


def subscription_body(u: dict, srv: dict, inbounds: list = None) -> tuple[str, str]:
    protos = u.get("protocols") or ["vless"]
    secrets_map = u.get("secret_map") or {}
    links = []
    extras = []
    for p in protos:
        sec = secrets_map.get(p)
        if not sec:
            continue
        if p in V2RAY_FAMILY:
            # One link per endpoint: _v2ray_link ignores `index`, so looping
            # only emitted byte-identical duplicates (3 indistinguishable
            # profiles per endpoint in every client).
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                link = _v2ray_link(p, sec, u["username"] + suffix, 1, vsrv)
                if link:
                    links.append(link)
        elif p == "reality":
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                for i in range(1, 4):
                    link = _reality_link(sec, u["username"] + suffix, i, vsrv)
                    if link:
                        links.append(link)
        elif p == "hysteria2":
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                link = _v2ray_link("hysteria2", sec, u["username"] + suffix, 1, vsrv)
                if link:
                    links.append(link)
        elif p == "wireguard":
            try:
                extras.append("### WireGuard ###\n" + _wg_config(u, srv, sec))
            except (ValueError, OSError):
                continue
        elif p == "openvpn":
            try:
                extras.append("### OpenVPN ###\n" + _ovpn_config(u, srv, sec))
            except (ValueError, OSError):
                continue
        elif p == "l2tp":
            try:
                extras.append("### L2TP/IPsec ###\n" + _l2tp_config(u, srv, sec))
            except (ValueError, OSError):
                continue
        elif p == "cisco":
            try:
                extras.append("### Cisco AnyConnect ###\n" + _cisco_config(u, srv, sec))
            except (ValueError, OSError):
                continue
        elif p == "socks5":
            link = _socks5_link(u.get("username", ""), sec, srv)
            if link:
                links.append(link)
    only_links = bool(links) and not extras
    if only_links:
        encoded = base64.b64encode("\n".join(links).encode()).decode()
        return encoded, "text/plain"
    parts = []
    if links:
        parts.append("\n".join(links))
    parts.extend(extras)
    return ("\n\n".join(parts) + "\n"), "text/plain"


BACKPACK_VERSION = "v1.8.2"
# Pinned, hash-verified BackPack installer (white-hat: piping a floating
# branch to bash turns an upstream compromise into RCE-as-root on both
# tunnel servers). Bump deliberately per BackPack release: take the commit
# SHA, download install.sh at that commit, record its sha256 here.
BACKPACK_PIN_COMMIT = "5e1d15734550c7133fe512ab62475ce1482cf1da"
BACKPACK_PIN_SHA256 = "478789edc3ca702724ca643bfc3785123da0d4983e80f060726d8e258d82ab18"


def backpack_guide(node: dict, token: str) -> str:
    transport_labels = {
        "tcp": "TCP", "tcp-mux": "TCP Mux", "tcp-stealth": "TCP + Stealth",
        "tcp-pck": "TCP + PCK", "udp": "UDP",
        "kcp": "UDP + KCP + FEC", "quic": "UDP + QUIC",
        "ws": "WS", "ws-mux": "WS Mux", "wss": "WSS", "wss-mux": "WSS Mux",
        "icmp": "xDi (ICMP)", "ip-spoof": "IP Spoofing",
    }
    tlabel = transport_labels.get(node["transport"], node["transport"])
    ports = node.get("forwarded_ports") or "e.g. 443:8000"
    udp = "yes" if node.get("udp_forward") else "no"
    return f"""================================================================
 ZEFIRA x BACKPACK - Tunnel Setup Guide (for BackPack {BACKPACK_VERSION}+)
 Tunnel name : {node['name']}
 Transport   : {tlabel}
================================================================

STEP 0 - Install BackPack {BACKPACK_VERSION} on BOTH servers (Iran + Kharej).
NEVER pipe an unpinned URL to bash (upstream compromise = RCE as root).
Download the pinned copy, verify its hash, then run it:
    curl -fsSL -o /tmp/bp-install.sh https://raw.githubusercontent.com/AminMGMT/BackPack/{BACKPACK_PIN_COMMIT}/install.sh
    echo "{BACKPACK_PIN_SHA256}  /tmp/bp-install.sh" | sha256sum -c -
    sudo bash /tmp/bp-install.sh

----------------------------------------------------------------
STEP 1 - IRAN SERVER (entry point):  {node['iran_ip']}
----------------------------------------------------------------
Run:  sudo backpack   ->   1. Setup Iran
Answer the wizard exactly like this:
    Transport      : {tlabel}
    Tunnel port    : {node['tunnel_port']}
    Tunnel name    : {node['name']}
    TOKEN          : {token}
    Exposed ports  : {ports}
    Forward UDP    : {udp}
    Preset         : Turbo
=> COPY THE TOKEN shown by the wizard (it must match the one above).

----------------------------------------------------------------
STEP 2 - KHAREJ SERVER (exit / origin):  {node['kharej_ip']}
----------------------------------------------------------------
Run:  sudo backpack   ->   2. Setup Kharej
Answer with the SAME values:
    Transport      : {tlabel}
    Iran address   : {node['iran_ip']}
    Tunnel port    : {node['tunnel_port']}
    Tunnel name    : {node['name']}
    TOKEN          : {token}   (same as Iran!)
    Preset         : Turbo

----------------------------------------------------------------
STEP 3 - Verify
----------------------------------------------------------------
On both servers:  sudo backpack  ->  Manage  ->  Status
If something looks wrong: Manage -> Health Check (it prints the fix).
From Zefira panel press "Check now" to probe {node['iran_ip']}:{node['tunnel_port']}.

NOTES
-----
* Keep the token secret - anyone holding it can join your tunnel.
* On tcp/udp/kcp the token travels as-is: on untrusted paths prefer an
  encrypted transport (Stealth, PCK, KCP, QUIC, WSS).
* TCP + Stealth or WSS are the best anti-DPI transports on dirty routes.
* WSS needs a certificate configured and answers probes with a decoy site.
* If Iran cannot accept inbound, use Direct mode instead (wizard ->
  Direct -> carrier): Iran dials out, no inbound port needed.
* Not sure which transport fits? BackPack Manage -> Link Test measures
  the route and recommends one.
* Open/forward the tunnel port ({node['tunnel_port']}/{'udp+tcp' if udp == 'yes' else 'tcp'}) on the Iran firewall.
* Tunnel port can be pinned to one address (IP:port) in the wizard.
================================================================
"""


def zip_files(files: list) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files:
            z.writestr(name, content)
    return buf.getvalue()


def qr_svg_b64(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, border=2)
    b = io.BytesIO()
    img.save(b)
    return base64.b64encode(b.getvalue()).decode()
