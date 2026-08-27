import base64
import hashlib
import io
import json
import secrets as pysecrets
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

import qrcode
import qrcode.image.svg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import NameOID

from config import INSTANCE_DIR

PROTOCOLS = ["vless", "reality", "vmess", "trojan", "ss", "hysteria2", "wireguard", "openvpn"]
V2RAY_FAMILY = {"vless", "vmess", "trojan", "ss"}
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
    "reality_port": 443,
    "reality_sni": "www.yahoo.com,www.samsung.com,www.microsoft.com",
    "reality_pub": "",
}


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
        else:
            raise ValueError(p)
    return out


def serialize_secrets(secret_map: dict) -> str:
    return json.dumps(secret_map, separators=(",", ":"))


def _v2ray_link(protocol: str, secret: str, username: str, index: int, srv: dict) -> str | None:
    host = srv["domain"]
    name = f"Zefira-{username}-{index}"
    if protocol == "vless":
        return (
            f"vless://{secret}@{host}:{srv['sub_port']}?encryption=none&security=tls"
            f"&sni={host}&fp=chrome&type=ws&host={host}&path=%2Fzefira#{name}"
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
            "sni": host,
        }
        return "vmess://" + _b64(json.dumps(obj, separators=(",", ":")))
    if protocol == "trojan":
        return (
            f"trojan://{secret}@{host}:{srv['sub_port']}?security=tls&sni={host}"
            f"&type=ws&host={host}&path=%2Fzefira&allowInsecure=0#{name}"
        )
    if protocol == "ss":
        userinfo = _b64(f"aes-256-gcm:{secret}")
        return f"ss://{userinfo}@{host}:{srv['sub_port']}#Zefira-{username}-{index}"
    if protocol == "hysteria2":
        return (
            f"hysteria2://{secret}@{host}:{srv['hy2_port']}"
            f"?sni={host}&insecure=0#Zefira-{username}-{index}"
        )
    return None


def _reality_link(secret: str, username: str, index: int, srv: dict) -> str | None:
    host = srv["domain"]
    pub = srv.get("reality_pub") or "REPLACE_WITH_REALITY_PUBLIC_KEY"
    sni_list = [s.strip() for s in (srv.get("reality_sni") or "").split(",") if s.strip()]
    sni = sni_list[(index - 1) % len(sni_list)] if sni_list else host
    sid = hashlib.sha1(f"{secret}:{index}".encode()).hexdigest()[:8]
    name = f"Zefira-{username}-REALITY-{index}"
    return (
        f"vless://{secret}@{host}:{srv['reality_port']}?"
        f"encryption=none&security=reality&pbk={pub}&sid={sid}"
        f"&sni={sni}&fp=chrome&type=tcp&flow=xtls-rprx-vision"
        f"&headerType=none#{name}"
    )


def _json_scalar(v) -> str:
    return json.dumps(v, ensure_ascii=False)


def clash_yaml(u: dict, srv: dict) -> str:
    protos = u.get("protocols") or []
    secrets_map = u.get("secret_map") or {}
    host = srv["domain"]
    proxies = []
    names = []

    def ws_opts(path="/zefira"):
        return {"path": path, "headers": {"Host": host}}

    if "vmess" in protos and secrets_map.get("vmess"):
        n = f"Zefira-{u['username']}-VMess"
        names.append(n)
        proxies.append({
            "name": n, "type": "vmess", "server": host, "port": int(srv["sub_port"]),
            "uuid": secrets_map["vmess"], "alterId": 0, "cipher": "auto",
            "tls": True, "servername": host, "network": "ws", "ws-opts": ws_opts(),
        })
    if "vless" in protos and secrets_map.get("vless"):
        n = f"Zefira-{u['username']}-VLESS"
        names.append(n)
        proxies.append({
            "name": n, "type": "vless", "server": host, "port": int(srv["sub_port"]),
            "uuid": secrets_map["vless"], "tls": True, "servername": host,
            "network": "ws", "ws-opts": ws_opts(), "client-fingerprint": "chrome",
        })
    if "reality" in protos and secrets_map.get("reality"):
        sni_list = [s.strip() for s in (srv.get("reality_sni") or "").split(",") if s.strip()]
        sni = sni_list[0] if sni_list else host
        sid = hashlib.sha1(f"{secrets_map['reality']}:1".encode()).hexdigest()[:8]
        n = f"Zefira-{u['username']}-REALITY"
        names.append(n)
        proxies.append({
            "name": n, "type": "vless", "server": host, "port": int(srv["reality_port"]),
            "uuid": secrets_map["reality"], "flow": "xtls-rprx-vision",
            "tls": True, "servername": sni, "client-fingerprint": "chrome",
            "reality-opts": {"public-key": srv.get("reality_pub") or "", "short-id": sid},
        })
    if "trojan" in protos and secrets_map.get("trojan"):
        n = f"Zefira-{u['username']}-Trojan"
        names.append(n)
        proxies.append({
            "name": n, "type": "trojan", "server": host, "port": int(srv["sub_port"]),
            "password": secrets_map["trojan"], "sni": host, "udp": True,
            "network": "ws", "ws-opts": ws_opts(),
        })
    if "ss" in protos and secrets_map.get("ss"):
        n = f"Zefira-{u['username']}-SS"
        names.append(n)
        proxies.append({
            "name": n, "type": "ss", "server": host, "port": int(srv["sub_port"]),
            "cipher": "aes-256-gcm", "password": secrets_map["ss"], "udp": True,
        })
    if "hysteria2" in protos and secrets_map.get("hysteria2"):
        n = f"Zefira-{u['username']}-Hy2"
        names.append(n)
        proxies.append({
            "name": n, "type": "hysteria2", "server": host, "port": int(srv["hy2_port"]),
            "password": secrets_map["hysteria2"], "sni": host,
        })

    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "proxies:",
    ]
    for p in proxies:
        lines.append("  - " + _json_scalar(p))
    lines.append("proxy-groups:")
    lines.append("  - " + _json_scalar({"name": "Zefira", "type": "select", "proxies": names}))
    lines.append("rules:")
    lines.append('  - MATCH,Zefira')
    return "\n".join(lines) + "\n"


def true_val():
    return True


FILE_EXT = {
    "vless": ".txt", "reality": ".txt", "vmess": ".txt", "trojan": ".txt", "ss": ".txt",
    "hysteria2": ".txt", "wireguard": ".conf", "openvpn": ".ovpn",
}
def _wg_config(u: dict, srv: dict, secret: str) -> str:
    priv_obj = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(secret))
    pub = priv_obj.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    peer = srv.get("wg_pub") or "SERVER_PUBLIC_KEY_HERE"
    addr = f"10.7.0.{(u['id'] % 250) + 2}"
    lines = [
        "[Interface]",
        f"PrivateKey = {secret}",
        f"Address = {addr}/32",
        f"DNS = {srv.get('dns', '1.1.1.1')}",
        "MTU = 1420",
        "",
        "[Peer]",
        f"# Client PublicKey = {base64.b64encode(pub).decode()}",
        f"PublicKey = {peer}",
        f"Endpoint = {srv['domain']}:{srv['wg_port']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
        "",
    ]
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
    safe = "".join(ch for ch in username if ch.isalnum() or ch in "-_")[:32] or "client"
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
    cert_pem = blob.split(marker_c)[1].split(marker_k)[0].strip()
    key_pem = blob.split(marker_k)[1].strip()
    lines = [
        "client",
        "dev tun",
        f"proto {srv.get('ovpn_proto', 'udp')}",
        f"remote {srv['domain']} {srv['ovpn_port']}",
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
    return v


def _srvs_for(proto: str, srv: dict, inbounds: list) -> list:
    if proto in ("wireguard", "openvpn"):
        return [(srv, "")]
    out = [(srv, "")]
    for i in (inbounds or []):
        if i.get("enabled") and i.get("protocol") == proto:
            out.append((_variant_srv(srv, i), i["name"]))
    return out


def build_files(u: dict, srv: dict, inbounds: list = None) -> list:
    protos = u.get("protocols") or ["vless"]
    secrets_map = u.get("secret_map") or {}
    files = []
    links = []
    for p in protos:
        sec = secrets_map.get(p)
        if not sec:
            continue
        if p in V2RAY_FAMILY:
            count = 3 if p != "ss" else 1
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                for i in range(1, count + 1):
                    link = _v2ray_link(p, sec, u["username"] + suffix, i, vsrv)
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
            files.append((f"{u['username']}-wg.conf", _wg_config(u, srv, sec)))
        elif p == "openvpn":
            files.append((f"{u['username']}.ovpn", _ovpn_config(u, srv, sec)))
    if links:
        files.insert(0, (f"{u['username']}-subscription.txt", "\n".join(links) + "\n"))
    return files


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
            count = 3 if p != "ss" else 1
            for vsrv, label in _srvs_for(p, srv, inbounds):
                suffix = f"-{label}" if label else ""
                for i in range(1, count + 1):
                    link = _v2ray_link(p, sec, u["username"] + suffix, i, vsrv)
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
            extras.append("### WireGuard ###\n" + _wg_config(u, srv, sec))
        elif p == "openvpn":
            extras.append("### OpenVPN ###\n" + _ovpn_config(u, srv, sec))
    only_links = bool(links) and not extras
    if only_links:
        encoded = base64.b64encode("\n".join(links).encode()).decode()
        return encoded, "text/plain"
    parts = []
    if links:
        parts.append("\n".join(links))
    parts.extend(extras)
    return ("\n\n".join(parts) + "\n"), "text/plain"


def backpack_guide(node: dict, token: str) -> str:
    transport_labels = {
        "tcp": "TCP", "tcp-mux": "TCP Mux", "tcp-stealth": "TCP + Stealth",
        "tcp-pck": "TCP + PCK", "kcp": "UDP + KCP + FEC", "quic": "UDP + QUIC",
        "ws": "WS", "ws-mux": "WS Mux", "wss": "WSS", "wss-mux": "WSS Mux",
        "icmp": "xDi (ICMP)", "ip-spoof": "IP Spoofing",
    }
    tlabel = transport_labels.get(node["transport"], node["transport"])
    ports = node.get("forwarded_ports") or "e.g. 443:8000"
    udp = "yes" if node.get("udp_forward") else "no"
    return f"""================================================================
 ZEFIRA x BACKPACK - Tunnel Setup Guide
 Tunnel name : {node['name']}
 Transport   : {tlabel}
================================================================

STEP 0 - Install BackPack on BOTH servers (Iran + Kharej):
    bash <(curl -fsSL https://raw.githubusercontent.com/AminMGMT/BackPack/main/install.sh)

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
* TCP + Stealth or WSS are the best anti-DPI transports on dirty routes.
* Open/forward the tunnel port ({node['tunnel_port']}/{'udp+tcp' if udp == 'yes' else 'tcp'}) on the Iran firewall.
================================================================
"""


def zip_files(files: list) -> bytes:
    buf = io.BytesIO()
    with __import__("zipfile").ZipFile(buf, "w", __import__("zipfile").ZIP_DEFLATED) as z:
        for name, content in files:
            z.writestr(name, content)
    return buf.getvalue()


def qr_svg_b64(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, border=2)
    b = io.BytesIO()
    img.save(b)
    return base64.b64encode(b.getvalue()).decode()
