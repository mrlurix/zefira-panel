import base64
import hashlib
import io
import ipaddress
import logging

log = logging.getLogger(__name__)
import json
import re
import secrets as pysecrets
import threading
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
TUNNEL_TRANSPORTS = ["tcp", "tcp-mux", "tcp-stealth", "tcp-pck", "udp", "kcp", "quic", "ws", "ws-mux", "wss", "wss-mux", "icmp", "ip-spoof", "sni"]
# Protocols served without per-inbound endpoints (single server-wide
# endpoint, like WireGuard/OpenVPN): no inbound variants are generated.
SINGLE_ENDPOINT = {"wireguard", "openvpn", "l2tp", "cisco", "socks5"}
PENDING_SENTINEL = datetime(2099, 1, 1)

# TLS fingerprints a client profile may request. This is the allowlist used by
# the builders as well as the UI list: links and Clash profiles are generated
# from DB rows and restored backups, so a value outside this tuple must never
# reach a query string or a config.
TLS_FINGERPRINTS = (
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
)
# Hysteria2 port hopping is opt-in and server-dependent. 30s is the protocol
# default and 5s its documented minimum.
HY2_HOP_INTERVAL_DEFAULT = 30
HY2_HOP_INTERVAL_MIN = 5
HY2_HOP_INTERVAL_MAX = 300

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
    # Transport hardening. Every default here preserves the links this panel
    # emitted before the options existed; the server-dependent switches are
    # off so an upgrade cannot break a working deployment.
    "tls_fp": "chrome",
    "hy2_obfs_password": "",
    "hy2_hop_ports": "",
    "hy2_hop_interval": HY2_HOP_INTERVAL_DEFAULT,
    "reality_sni_per_user": "0",
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


_PEM_BLOCK_RE = re.compile(
    r"\A-----BEGIN (?P<label>[A-Z0-9 ]+)-----"
    r"(?P<body>[A-Za-z0-9+/=\r\n]+?)"
    r"-----END (?P=label)-----\Z"
)


def pem_block_is_exact(pem: str, label: str) -> bool:
    """True only for a single, complete PEM block of exactly `label`.

    The cryptography loaders are deliberately lenient: they parse the first
    PEM object and ignore everything after it. That is fine for a file on
    disk, wrong for a value that a backup file controls, because the ignored
    tail is emitted verbatim into the generated config. Requiring the block to
    BE the whole string closes that (and also rejects a second <ca>, a rogue
    `remote`, or an `up` script).
    """
    if not isinstance(pem, str) or not pem or len(pem) > 8000:
        return False
    m = _PEM_BLOCK_RE.fullmatch(pem.strip())
    return bool(m) and m.group("label") == label


def _maybe_prefix(secret: str, base: str) -> str:
    """Prepend the per-user label, but only where a label can live.

    A per-user prefix is a DNS label: on an IP literal, "abc123.203.0.113.7"
    is not an address and resolves nowhere, so every emitted link and config
    fails at DNS while the panel reports healthy. On the "localhost" fallback
    a prefix is equally unresolvable. Both cases return the base unchanged -
    an address the client can actually dial beats a "consistent" one it
    cannot.
    """
    try:
        ipaddress.ip_address(base)
        return base
    except ValueError:
        pass
    if base == "localhost":
        return base
    prefix = hashlib.sha256(secret.encode()).hexdigest()[:8]
    candidate = f"{prefix}.{base}"
    return candidate if _HOST_RE.match(candidate) else base


def _effective_host(secret: str, srv: dict) -> str:
    # The per-user prefix applies wherever the old code applied it - but never
    # to an IP literal or the localhost fallback (see _maybe_prefix). The main
    # endpoint WITHOUT obfuscated_host deliberately stays bare even when the
    # checkbox is on: prefixing it here would break deployments that enabled
    # the checkbox without wildcard DNS on the main domain, whose main links
    # work today. A prefixed IP, by contrast, resolves for nobody, so refusing
    # to emit one cannot break a working setup.
    if srv.get("_is_inbound_variant"):
        base = _safe_host(srv.get("domain"), "localhost")
        per_user = str(srv.get("per_user_subdomain", "0")).lower() in ("1", "true", "yes", "on")
        if per_user:
            return _maybe_prefix(secret, base)
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
    base = _safe_host(obf, _safe_host(srv.get("domain"), "localhost"))
    per_user = str(srv.get("per_user_subdomain", "0")).lower() in ("1", "true", "yes", "on")
    return _maybe_prefix(secret, base) if per_user else base


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
    # Every documented ZEFIRA_* port/protocol env must actually reach the
    # generators: only DOMAIN/SUB_PORT/OVPN_PORT were imported before, so
    # ZEFIRA_HY2_PORT / ZEFIRA_WG_PORT / ZEFIRA_DNS / ZEFIRA_OVPN_PROTO were
    # silently ignored and every config came out on the built-in defaults.
    from config import DNS, DOMAIN, HY2_PORT, OVPN_PORT_DEFAULT, OVPN_PROTO, SUB_PORT, WG_PORT

    srv = dict(DEFAULT_SRV)
    env_overrides = {
        "domain": DOMAIN,
        "sub_port": SUB_PORT,
        "hy2_port": HY2_PORT,
        "wg_port": WG_PORT,
        "ovpn_port": OVPN_PORT_DEFAULT,
        "dns": DNS,
        "ovpn_proto": OVPN_PROTO,
    }
    for k, v in env_overrides.items():
        if v in (None, ""):
            continue
        if k.endswith("_port"):
            port = _env_port(v)
            if port is not None:
                srv[k] = port
        else:
            srv[k] = v
    # Range-validate the DB overrides too: a junk value must not become a
    # broken link ("port NaN" / an impossible listen port).
    for k, v in (db_values or {}).items():
        if k in srv and v not in (None, ""):
            if k.endswith("_port"):
                port = _env_port(v)
                if port is not None:
                    srv[k] = port
            else:
                srv[k] = v
    if not srv.get("domain"):
        srv["domain"] = DOMAIN
    if srv.get("ovpn_proto") not in ("udp", "tcp"):
        srv["ovpn_proto"] = "udp"
    # Hand-edited rows and restored backups bypass the API schema. Normalise
    # the hardening values here, at the one place every generator reads, so a
    # hostile or mistyped value cannot be interpolated into a link.
    srv["tls_fp"] = _safe_fp(srv.get("tls_fp"))
    srv["hy2_obfs_password"] = _safe_obfs_password(srv.get("hy2_obfs_password"))
    srv["hy2_hop_ports"] = normalize_hop_ports(srv.get("hy2_hop_ports"))
    srv["hy2_hop_interval"] = _safe_hop_interval(srv.get("hy2_hop_interval"))
    srv["reality_sni_per_user"] = "1" if _truthy(srv.get("reality_sni_per_user")) else "0"
    return srv


def _truthy(value) -> bool:
    """The same switch spelling the rest of the panel accepts."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _safe_fp(value) -> str:
    """A fingerprint from the allowlist, else the shipped default."""
    v = str(value or "").strip().lower()
    return v if v in TLS_FINGERPRINTS else "chrome"


def _tls_fp(srv: dict) -> str:
    return _safe_fp(srv.get("tls_fp"))


def normalize_hop_ports(value) -> str:
    """`20000-50000,443` from a stored value, or "" when it is unusable.

    Hysteria2 clients, sing-box and Mihomo all accept comma-separated single
    ports and inclusive ranges; the Hysteria server spells a range with a
    colon (`listen: :20000-50000`), so that spelling is normalised too.
    Invalid input disables hopping as a whole: emitting half a range would
    send clients to ports nobody opened.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = []
    for chunk in raw.split(","):
        chunk = chunk.strip().replace(":", "-")
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", chunk)
        if not m:
            return ""
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if not (1 <= lo <= hi <= 65535):
            return ""
        parts.append(str(lo) if lo == hi else f"{lo}-{hi}")
    out = ",".join(parts)
    return out if len(out) <= 512 else ""


def _safe_hop_interval(value) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return HY2_HOP_INTERVAL_DEFAULT
    if n < HY2_HOP_INTERVAL_MIN or n > HY2_HOP_INTERVAL_MAX:
        return HY2_HOP_INTERVAL_DEFAULT
    return n


def _safe_obfs_password(value) -> str:
    """The Salamander password, or "" (feature off) when it is unusable.

    Control characters are refused rather than stripped: silently repairing
    the password would hand the client a credential the server does not have,
    and every Hysteria2 connection would fail with no clue why.
    """
    v = str(value or "")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
        return ""
    v = v.strip()
    # Salamander needs a non-trivial shared secret. Four is the floor used by
    # the server implementations this panel targets.
    if len(v) < 4 or len(v) > 128:
        return ""
    return v


def _env_port(value) -> int | None:
    """1-65535 int from env/DB text, else None (0 and 99999 are rejected:
    they produced 'https://host:0/...' links and dead configs)."""
    try:
        if isinstance(value, bool):
            return None
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


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
    """Store the credential bundle encrypted.

    The bundle is the customer's UUID, their WireGuard private key, their
    OpenVPN client keypair and the L2TP PSK. Written as bare JSON it was the
    one thing in the database that had to stay secret and did not: read the
    SQLite file and every customer's connection credentials are in cleartext.
    Fernet under the panel's SECRET_KEY already protects the AI key, the
    Telegram token and the REALITY private key, so this reuses the mechanism
    rather than adding one.

    parse_secret_map() (database.py) still reads the bare-JSON form, because
    every row written before this change keeps that form until the customer is
    re-provisioned or the row is rewritten. Restoring a backup written on an
    older install therefore still works.

    The key is derived per-process from SECRET_KEY at import time, so a
    restored backup is only readable on a host that already holds this panel's
    SECRET_KEY. That is the intended trade: the exported file no longer
    carries working credentials on its own, which is the same property the
    optional encrypted-backup mode has always had.
    """
    plain = json.dumps(secret_map, separators=(",", ":"))
    try:
        from security import encrypt_text

        return encrypt_text(plain)
    except Exception:  # noqa: BLE001
        # Never lose a customer's credentials to a crypto failure: a row that
        # cannot be encrypted must still be readable, or the subscription
        # endpoint would 500 for everyone. Log-worthy, not silent-by-design:
        # the plaintext fallback is strictly worse and is noted as such.
        log.warning("secret bundle could not be encrypted; storing plaintext")
        return plain


def _v2ray_link(protocol: str, secret: str, username: str, index: int, srv: dict) -> str | None:
    from urllib.parse import quote as _q

    host = _effective_host(secret, srv)
    cdn = _cdn_sni(srv)
    # Query values are percent-encoded (no-op for valid hosts/SNIs, fatal
    # for smuggled &/#/spaces from hand-edited rows).
    sni = _q(cdn or host, safe="")
    # Remark is exactly the username (plus inbound label when present) so
    # client apps show a clean, familiar name instead of a generated one.
    # Percent-encoded: USERNAME_RE already forbids #/?/&, so this is a no-op
    # today, but the fragment is the one unencoded interpolation left in the
    # link and a legacy row must not be able to inject a second line.
    name = _q(username, safe="")
    fp = _tls_fp(srv)
    if protocol == "vless":
        return (
            f"vless://{secret}@{host}:{srv['sub_port']}?encryption=none&security=tls"
            f"&sni={sni}&fp={fp}&type=ws&host={host}&path=%2Fzefira#{name}"
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
            # v2rayN's JSON schema carries the uTLS fingerprint here. It was
            # absent before, so every VMess client used its own default and
            # the panel could not make the profile match the other protocols.
            "fp": fp,
        }
        return "vmess://" + _b64(json.dumps(obj, separators=(",", ":")))
    if protocol == "trojan":
        return (
            f"trojan://{secret}@{host}:{srv['sub_port']}?security=tls&sni={sni}"
            f"&fp={fp}&type=ws&host={host}&path=%2Fzefira&allowInsecure=0#{name}"
        )
    if protocol == "ss":
        # SIP002 mandates URL-safe base64 without padding (strict clients
        # misparse the +/= of standard base64).
        userinfo = base64.urlsafe_b64encode(f"aes-256-gcm:{secret}".encode()).decode().rstrip("=")
        # Encoded like vless/trojan above: a remark carrying '#' splits the
        # link into a second fragment and the client reads a truncated name.
        return f"ss://{userinfo}@{host}:{srv['sub_port']}#{_q(username, safe='')}"
    if protocol == "hysteria2":
        # The spec's grammar has the slash before the query ("host:port/?..."):
        # importers that split on "/?" lost the port and SNI.
        query = [f"sni={sni}", "insecure=0"]
        obfs = _safe_obfs_password(srv.get("hy2_obfs_password"))
        if obfs:
            # Official URI parameters (Salamander). The server must be started
            # with the same obfs type and password or every connection dies.
            query.append("obfs=salamander")
            query.append("obfs-password=" + _q(obfs, safe=""))
        hop_ports = normalize_hop_ports(srv.get("hy2_hop_ports"))
        if hop_ports:
            # The official multi-port form lives in the authority, but v2rayN,
            # Xray-core, Shadowrocket and Sub-Store all read `mport`, while a
            # numeric authority port keeps the URL parseable by older clients.
            query.append("mport=" + _q(hop_ports, safe=","))
            query.append(f"hop-interval={_safe_hop_interval(srv.get('hy2_hop_interval'))}")
        return (
            f"hysteria2://{secret}@{host}:{srv['hy2_port']}/?"
            f"{'&'.join(query)}#{_q(username, safe='')}"
        )
    return None


# The panel's documented default REALITY SNI list. Used when the stored value
# is empty (a legacy row, or a backup written before the field was validated):
# an empty list used to fall back to the CONNECT ADDRESS as the SNI, which no
# REALITY deployment can verify - every customer's link was dead while the
# panel reported a healthy save.
DEFAULT_REALITY_SNI = "www.yahoo.com,www.samsung.com,www.microsoft.com"


def _reality_sni(srv: dict, index: int = 1, secret: str = "") -> str:
    """The SNI for REALITY link `index`, rotating through the stored list.

    Both the share links and the Clash config call this, so the two can never
    disagree about which servername a given link uses (the Clash builder used
    to hard-pin the first entry).

    With `reality_sni_per_user` on, a stable per-user choice replaces the
    index rotation: two customers no longer share the same servername, which
    makes traffic correlation harder. The choice is derived from the secret,
    so the share link, the Clash profile and every later subscription fetch
    agree. The option is off by default because every listed SNI must exist in
    the server's REALITY `serverNames`.
    """
    raw = (srv.get("reality_sni") or "").strip() or DEFAULT_REALITY_SNI
    sni_list = [s.strip() for s in raw.split(",") if s.strip()]
    if not sni_list:
        sni_list = [s.strip() for s in DEFAULT_REALITY_SNI.split(",") if s.strip()]
    if secret and _truthy(srv.get("reality_sni_per_user")):
        digest = hashlib.sha256(f"zefira-reality-sni:{secret}".encode()).digest()
        return sni_list[int.from_bytes(digest[:4], "big") % len(sni_list)]
    try:
        i = max(1, int(index or 1))
    except (TypeError, ValueError):
        i = 1
    return sni_list[(i - 1) % len(sni_list)]


def _reality_link(secret: str, username: str, index: int, srv: dict) -> str | None:
    from urllib.parse import quote as _q

    host = _effective_host(secret, srv)
    pub = srv.get("reality_pub") or ""
    # Hand-edited DB could smuggle extra link params via the public key
    # (generated keys are always 43-char base64url): skip output entirely
    # rather than ship a guaranteed-dead link to the customer.
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", pub or ""):
        return None
    sni = _reality_sni(srv, index, secret)
    sni = _q(sni, safe="")
    sid = hashlib.sha1(f"{secret}:{index}".encode()).hexdigest()[:8]
    name = _q(username, safe="")
    return (
        f"vless://{secret}@{host}:{srv['reality_port']}?"
        f"encryption=none&security=reality&pbk={pub}&sid={sid}"
        f"&sni={sni}&fp={_tls_fp(srv)}&type=tcp&flow=xtls-rprx-vision"
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
    # Re-check the charset on the render path: these values are written into a
    # line-oriented instructions file, so a secret carrying a newline (only
    # reachable through a hand-edited row today) would append fake lines.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", password or "") or \
            not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", psk or ""):
        raise ValueError("invalid l2tp secret charset")
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
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", password or ""):
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

# Clash (mihomo) can only carry the proxy types it implements. A plan built
# from WireGuard / OpenVPN / L2TP / Cisco has no Clash representation, and a
# REALITY plan with no generated public key has no link either - so the
# endpoint must say so rather than hand back a profile that routes everything
# through DIRECT.
_NO_CLASH_REASON = (
    "This plan cannot be expressed as a Clash/Mihomo config: the selected "
    "protocols (WireGuard, OpenVPN, L2TP, Cisco) have no Clash proxy type, or "
    "the REALITY keys have not been generated yet. Import the .ovpn/.conf "
    "config from the dashboard, or add a VLESS/Trojan/VMess/SS/Hysteria2 "
    "protocol to this account."
)

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
                "client-fingerprint": _tls_fp(vsrv),
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
                "network": "ws", "ws-opts": ws_opts(host_eff),
                "client-fingerprint": _tls_fp(vsrv),
            })
    if "reality" in protos and secrets_map.get("reality"):
        sec = secrets_map["reality"]
        r_idx = 0
        for vsrv, ilabel in _each("reality"):
            r_idx += 1
            host_eff = _effective_host(sec, vsrv)
            # Same helper as the share links, with the same running index: the
            # Clash entry used to hard-pin the first SNI while the vless://
            # link for the same user rotated, so one customer got two
            # different REALITY servernames.
            sni = _reality_sni(vsrv, r_idx, sec)
            sid = hashlib.sha1(f"{sec}:{r_idx}".encode()).hexdigest()[:8]
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
                "tls": True, "servername": sni, "client-fingerprint": _tls_fp(vsrv),
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
                "client-fingerprint": _tls_fp(vsrv),
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
            proxy = {
                "name": n, "type": "hysteria2", "server": host_eff, "port": int(vsrv["hy2_port"]),
                "password": sec, "sni": sni_eff,
            }
            obfs = _safe_obfs_password(vsrv.get("hy2_obfs_password"))
            if obfs:
                proxy["obfs"] = "salamander"
                proxy["obfs-password"] = obfs
            hop_ports = normalize_hop_ports(vsrv.get("hy2_hop_ports"))
            if hop_ports:
                # Mihomo spells the range `ports` and takes seconds, not a
                # duration string. `port` stays the anchor the server listens
                # on so clients that ignore `ports` still connect.
                proxy["ports"] = hop_ports
                proxy["hop-interval"] = _safe_hop_interval(vsrv.get("hy2_hop_interval"))
            proxies.append(proxy)
    if "socks5" in protos and secrets_map.get("socks5"):
        sec = secrets_map["socks5"]
        host_eff = _effective_host(sec, srv)
        n = f"Zefira-{u['username']}-SOCKS5"
        names.append(n)
        try:
            s5_port = int(srv.get("socks5_port", 1080))
        except (TypeError, ValueError):
            s5_port = 1080
        proxies.append({
            "name": n, "type": "socks5", "server": host_eff, "port": s5_port,
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
    if not proxies:
        # A syntactically valid profile with an empty proxy list is the worst
        # possible outcome: the client imports it happily, MATCH sends every
        # request to the fallback and the customer browses the open internet
        # believing they are tunnelled. Clash cannot express WireGuard,
        # OpenVPN, L2TP or Cisco at all, and a REALITY plan whose keys were
        # never generated has nothing to emit either. Refuse instead, and let
        # the endpoint answer with something the operator can act on.
        raise ValueError(_NO_CLASH_REASON)
    lines.append("proxy-groups:")
    group_proxies = names
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


_CA_LOCK = threading.Lock()


def _atomic_write(path, data: bytes, mode: int) -> None:
    """Write bytes with the final mode from the start, atomically.

    The CA private key used to be written with write_bytes() and chmod'ed
    afterwards: under umask 022 there was a window where the unencrypted
    CA key was world-readable, and a crash between the key and the cert write
    left a half-CA that the next call silently REGENERATED - permanently
    invalidating every .ovpn already handed out.
    """
    import os

    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _ensure_ca():
    with _CA_LOCK:
        if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
            key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
            return cert, key
        if CA_KEY_PATH.exists() != CA_CERT_PATH.exists():
            # Half a CA on disk. Regenerating would silently invalidate every
            # certificate already issued with it, so refuse instead and make
            # the operator look.
            missing = CA_CERT_PATH if CA_KEY_PATH.exists() else CA_KEY_PATH
            raise RuntimeError(
                f"OpenVPN CA is incomplete ({missing.name} missing). "
                "Restore both files or remove them together to mint a new CA."
            )
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
        # Key first (0600 from creation), then the public cert: a reader can
        # never observe a readable private key, and a crash between the two
        # is now detected above instead of silently rotating the CA.
        _atomic_write(CA_KEY_PATH, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ), 0o600)
        _atomic_write(CA_CERT_PATH, cert.public_bytes(serialization.Encoding.PEM), 0o644)
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
    # Second gate, on the render path: the blob is interpolated into a config
    # file, so anything other than exactly one PEM block per field is refused.
    # Without this, a blob carrying `up <script>` / a second <ca> / a rogue
    # `remote` after the key would be handed to the customer's client as
    # directives - and OpenVPN 2.x runs `up` scripts as root.
    if not pem_block_is_exact(cert_pem, "CERTIFICATE"):
        raise ValueError("invalid openvpn certificate block")
    if not pem_block_is_exact(key_pem, "PRIVATE KEY"):
        raise ValueError("invalid openvpn key block")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization as _ser
        x509.load_pem_x509_certificate(cert_pem.encode())
        _ser.load_pem_private_key(key_pem.encode(), password=None)
    except Exception as exc:
        raise ValueError("invalid openvpn credential") from exc
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
        # No verify-x509-name here: that directive checks the *server*
        # certificate's CN, not the CA in <ca>. With a normal service cert
        # (CN=vpn.example.com) every client aborted with
        # VERIFY_X509NAME ERROR. The CA is already pinned via <ca>.
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
    # A hand-edited/legacy inbound row with a NULL or junk port used to raise
    # here and take down the whole subscription/dashboard. Skip the variant
    # instead: the main endpoint still serves.
    port = _env_port(inbound.get("port"))
    if port is None:
        raise ValueError("inbound has no usable port")
    v["sub_port"] = port
    v["reality_port"] = port
    v["hy2_port"] = port
    host = (inbound.get("host") or "").strip() or (inbound.get("node_address") or "").strip()
    if host:
        v["domain"] = host
        v["_is_inbound_variant"] = True
    elif inbound.get("node_id"):
        # Pinned to a node that has since been deleted from the panel: the
        # address is gone, so this endpoint has no reachable host at all.
        # Shipping the panel's own front here would hand the customer a link
        # to the wrong machine that still LOOKS valid.
        raise ValueError("pinned inbound has no address to connect to")
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
            try:
                variant = _variant_srv(srv, i)
            except ValueError:
                # Unusable legacy port: skip that endpoint, keep the rest.
                continue
            out.append((variant, i["name"]))
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
    # SHARE LINKS ONLY. This used to append the file-based config sections
    # ("### OpenVPN ###" + a 90-line .ovpn) to the feed, on the stated belief
    # that clients "skip the ### sections". A client skips the one line that
    # starts with '#'; the other 90 are not URIs and are not comments.
    # Measured: vless+openvpn produced 92 lines of which 91 were unparseable,
    # with the customer's single working link buried among them.
    #
    # The panel already documents the opposite - main.py's own error for a
    # link-less plan says "WireGuard/OpenVPN/L2TP/Cisco plans are served as
    # config files, not link lists" - and the config keeps its own channels:
    # the dashboard card (user_links) and the file/ZIP download (build_files).
    #
    # `extras` is still built above: that path mints nothing, but leaving it
    # alone keeps the generation and its ValueError/OSError handling exactly
    # as it was. A plan with no link at all yields an empty body, and the
    # caller answers 422 with the message quoted above - the branch that was
    # already written for precisely this case.
    body = ("\n".join(links) + "\n").encode()
    return base64.b64encode(body).decode(), "text/plain"


BACKPACK_VERSION = "v1.8.5"
# Pinned, hash-verified BackPack installer (white-hat: piping a floating
# branch to bash turns an upstream compromise into RCE-as-root on both
# tunnel servers). Bump deliberately per BackPack release: take the commit
# SHA, download install.sh at that commit, record its sha256 here.
#
# v1.8.5, released 2026-09-30. The sha256 below was computed over install.sh
# fetched at BACKPACK_PIN_COMMIT, and the method was proved first by
# recomputing the v1.8.2 pair the same way and getting back the hash this
# panel already recorded. Anything older than the pin cannot read the new
# backpack://2. setup link (upstream says so itself), and the guide below
# hands that link out, so the pin and the guide have to move together.
BACKPACK_PIN_COMMIT = "ff86354bcafbd054e7888e48343145323c9b2207"
BACKPACK_PIN_SHA256 = "04681e6744b7d5d9d03a6c9b48910a1fd4bcb908bed83f0bf8ad80607a5e0f6e"

# Named performance presets the v1.8.4+ wizards offer. The guide used to hard
# code Turbo, which left the operator with nothing to choose and no way to ask
# for a gentler profile on a route that punishes an aggressive one.
BACKPACK_PRESETS = ["turbo", "aggressive", "conservative", "custom"]

# Carriers that are set up from the Iran server and carried by the setup link
# (v1.8.4 listed them in this order). Kept as data because the guide, the form
# and the schema all have to agree on which carriers are direct, and three
# copies of that list is how the panel ended up missing `sni`.
BACKPACK_DIRECT_CARRIERS = ["xdi", "pck", "udp", "quic", "ip-spoof", "sni"]


def _bp_optional(node: dict) -> str:
    """The optional sections, each one only when the node sets it.

    A node that uses none of them renders exactly as it did before, which is the
    point: a guide that always shows a quota the tunnel does not have is worse
    than a guide that says nothing.
    """
    out = []
    limit = node.get("traffic_limit_gb") or 0
    if limit:
        out.append(
            "  Traffic limit : %d GB  (no limit is written when this is 0)\n"
            "      the engine enforces it: the tunnel goes offline the moment the\n"
            "      total is reached, and comes back within two seconds of the cap\n"
            "      being raised. Stored as <name>.quota.json beside the config.\n"
            % int(limit))
    hours = node.get("restart_hours") or 0
    if hours:
        out.append(
            "  Restart both  : every %d h, as a systemd timer in UTC\n"
            "      both ends restart together on the same timer, so an Iran box on\n"
            "      +03:30 and a kharej on UTC still line up. 0 is off, which is\n"
            "      upstream's default. (Auto Refresh is different: it runs from cron\n"
            "      in each machine's own timezone, so the two ends drift apart.)\n"
            % int(hours))
    hosts = (node.get("backup_hosts") or "").strip()
    if hosts:
        out.append(
            "  Backup hosts  : %s\n"
            "      these ride in the setup link. A kharej built from that link\n"
            "      fails over to them on its own if the Iran address stops\n"
            "      answering - another IP, a domain, a CDN edge, separated by\n"
            "      commas.\n" % hosts)
    return "".join(out)


def backpack_guide(node: dict, token: str) -> str:
    transport_labels = {
        "tcp": "TCP", "tcp-mux": "TCP Mux", "tcp-stealth": "TCP + Stealth",
        "tcp-pck": "TCP + PCK", "udp": "UDP",
        "kcp": "UDP + KCP + FEC", "quic": "UDP + QUIC",
        "ws": "WS", "ws-mux": "WS Mux", "wss": "WSS", "wss-mux": "WSS Mux",
        "icmp": "xDi (ICMP)", "ip-spoof": "IP Spoofing",
        # Added upstream in v1.8.4 among the direct carriers and moved onto the
        # setup-link wizard in v1.8.5. The panel could not offer it before.
        "sni": "SNI Spoofing",
    }
    tlabel = transport_labels.get(node["transport"], node["transport"])
    # No "e.g." placeholder as config: empty means tunnel-port-only (plus
    # UDP forwarding of it when enabled), stated plainly.
    raw_ports = (node.get("forwarded_ports") or "").strip()
    ports = raw_ports if raw_ports else "(none - tunnel port only)"
    udp = "yes" if node.get("udp_forward") else "no"
    preset = (node.get("preset") or "turbo").strip() or "turbo"
    optional = _bp_optional(node)
    is_direct = node["transport"] in BACKPACK_DIRECT_CARRIERS or \
        node["transport"] in ("icmp", "udp", "quic", "tcp-pck")

    # v1.8.4 moved both wizards onto this question list, and v1.8.5 ended them
    # on a setup link instead of a second round of manual answers.
    wizard_iran = (
        "    Kharej address : %s\n" % node["kharej_ip"]
        if not is_direct else
        "    (Direct carrier: Iran dials OUT, so no Iran inbound port is needed.)\n")
    return f"""================================================================
 ZEFIRA x BACKPACK - Tunnel Setup Guide (for BackPack {BACKPACK_VERSION}+)
 Tunnel name : {node['name']}
 Transport   : {tlabel}
 Preset      : {preset}
================================================================

STEP 0 - Install BackPack {BACKPACK_VERSION} on the IRAN server.
NEVER pipe an unpinned URL to bash (upstream compromise = RCE as root).
The block below is FAIL-CLOSED on purpose: if the download or the hash check
fails, it stops instead of continuing to `sudo bash`. Copy it as ONE block
into an interactive shell (not with `sh -c` on a single line, where a failure
in the middle can be ignored), and run it exactly like this:

    set -e
    d="$(mktemp -d)"
    curl -fsSL -o "$d/bp-install.sh" \\
      https://raw.githubusercontent.com/AminMGMT/BackPack/{BACKPACK_PIN_COMMIT}/install.sh
    echo "{BACKPACK_PIN_SHA256}  $d/bp-install.sh" | sha256sum -c -
    sudo bash "$d/bp-install.sh"
    rm -rf "$d"

If sha256sum reports FAILED, stop: that file is not the one this panel was
tested against. The kharej needs BackPack too - STEP 2 does that for you.

----------------------------------------------------------------
STEP 1 - IRAN SERVER (entry point):  {node['iran_ip']}
----------------------------------------------------------------
Run:  sudo backpack   ->   1. Setup Iran
Answer the wizard like this:
    Transport      : {tlabel}
    Tunnel port    : {node['tunnel_port']}
    Tunnel name    : {node['name']}
    TOKEN          : {token}
{wizard_iran}    Exposed ports  : {ports}
    Forward UDP    : {udp}
    Preset         : {preset}
{optional}=> COPY THE TOKEN shown by the wizard (it must match the one above).
=> COPY THE SETUP LINK it ends with. It starts with backpack:// and carries
   everything the two ends must agree on, including the token - the kharej
   must NOT be given a token of its own, upstream refuses a link that pairs
   two different ones.

----------------------------------------------------------------
STEP 2 - KHAREJ SERVER (exit / origin):  {node['kharej_ip']}
----------------------------------------------------------------
Pick ONE:

  (a) The kharej already runs BackPack:
        sudo backpack link apply '<paste the setup link from STEP 1>'

  (b) The kharej has no BackPack at all - this installs it, builds the
      tunnel, starts it and waits to say whether it connected:

        BP="https://raw.githubusercontent.com/AminMGMT/BackPack/{BACKPACK_PIN_COMMIT}/install.sh"
        bash <(curl -fsSL "$BP") link apply '<paste the setup link from STEP 1>'

  Only a name is asked. Applying the SAME link again UPDATES that tunnel in
  place - new transport, new port, same name - so this is also how you change
  an existing tunnel after editing it here. That is new in {BACKPACK_VERSION};
  older builds refused a link they had already applied.

----------------------------------------------------------------
STEP 3 - Verify
----------------------------------------------------------------
On both servers:  sudo backpack  ->  Manage  ->  Status
If something looks wrong: Manage -> Health Check (it prints the fix).
From Zefira panel press "Check now" to probe {node['iran_ip']}:{node['tunnel_port']}.

NOTES
-----
* Keep the token and the setup link secret - anyone holding the token can join
  your tunnel.
* Not sure which transport fits? Run Connection Test:  sudo backpack  ->  option 0.
  It tries every transport between the two servers for real, groups the result
  as OK / UNSTABLE / DOWN, and ends with a suggested preset, the path MTU and
  the TCP MSS clamp it implies. Nothing is installed and nothing is left behind.
  (This replaced Link Test, and Speed Test and Game Latency Test are gone as of
  upstream v1.8.4.)
* Only WSS proves the far end is really your Iran server: since {BACKPACK_VERSION}
  the server answers the upgrade with X-Backpack-Proof, a MAC of the TLS session
  under the tunnel token. Plain TCP, TCP Mux, WS and UDP authenticate nothing
  about the far end, so on an untrusted path prefer WSS, or Stealth / PCK /
  KCP / QUIC.
* WSS needs a certificate configured, and answers probes with a decoy site.
* If Iran cannot accept inbound, use Direct mode instead (wizard -> Direct ->
  carrier: xDi, PCK, UDP, Quic, IP Spoofing, SNI Spoofing). Iran dials out, so
  no inbound port is needed at all.
* A tunnel can be capped: the panel writes <name>.quota.json beside the config
  and the engine enforces it, taking the tunnel offline when the total is
  reached and bringing it back within two seconds of the cap being raised. No
  limit means infinity.
* The built-in proxy (Manage -> Built-in Proxy, or: backpack proxy enable
  socks5 <port> --user U --pass P) is refused for loopback, link-local,
  unspecified and multicast destinations, so a forwarded port can no longer be
  used to reach the server's own services or cloud metadata.
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
