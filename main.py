import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time as time_mod
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import psutil
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, text as sqltext
from sqlalchemy.exc import IntegrityError

import protocols
from config import BASE_DIR, SESSION_TTL
from database import (
    Admin,
    AuditLog,
    Database,
    Inbound,
    Setting,
    TunnelNode,
    UserTemplate,
    VpnUser,
    utcnow,
)
from schemas import (
    ChangePasswordIn,
    InboundIn,
    InboundPatchIn,
    LoginIn,
    RestoreIn,
    SettingsIn,
    TelegramSettingsIn,
    TelegramTestIn,
    TemplateCreateIn,
    TotpCodeIn,
    TunnelNodeIn,
    TunnelSettingsIn,
    UserCreateIn,
    UserPatchIn,
)
from security import (
    COOKIE_NAME,
    SlidingWindowLimiter,
    create_session,
    decode_session,
    decrypt_text,
    dummy_verify,
    encrypt_text,
    gen_totp_secret,
    hash_password,
    login_limiter,
    login_user_limiter,
    otpauth_uri,
    verify_password,
    verify_totp,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("zefira")

db = Database(BASE_DIR / "instance" / "zefira.db")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
TOKEN_RE = re.compile(r"^[a-f0-9]{32}$")
STRONG_PW_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)\S{10,128}$")
SRV_KEYS = {
    "domain", "sub_port", "hy2_port", "wg_port", "wg_pub", "dns",
    "ovpn_port", "ovpn_proto", "reality_port", "reality_sni", "reality_pub",
    "obfuscated_host", "per_user_subdomain", "cdn_enabled", "cdn_sni",
}
PENDING_YEAR = 2098

sub_limiter = SlidingWindowLimiter(max_events=120, window_seconds=60)
pw_limiter = SlidingWindowLimiter(max_events=6, window_seconds=300)
tfa_limiter = SlidingWindowLimiter(max_events=10, window_seconds=600)
probe_limiter = SlidingWindowLimiter(max_events=20, window_seconds=60)

TUNNEL_KEYS = {"public_url", "trusted_proxies"}
_settings_cache: dict = {}


def cached_setting(key: str, ttl: float = 15.0):
    now = time_mod.monotonic()
    ent = _settings_cache.get(key)
    if ent and now - ent[1] < ttl:
        return ent[0]
    with db.s() as s:
        row = s.get(Setting, key)
    val = row.value if row else None
    _settings_cache[key] = (val, now)
    return val


def trusted_networks() -> list:
    raw = cached_setting("trusted_proxies") or os.environ.get("ZEFIRA_TRUSTED_PROXIES", "") or ""
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return nets


def public_base_url(request: Request) -> str:
    pub = cached_setting("public_url")
    if pub:
        return pub.rstrip("/")
    return str(request.base_url).rstrip("/")


def audit(s, event: str, detail: str = "", ip: str = "", ok: bool = True) -> None:
    s.add(AuditLog(event=event, detail=detail[:500], ip=ip[:64], ok=ok))
    s.flush()
    s.execute(
        sqltext(
            "DELETE FROM audit_logs WHERE id <= "
            "(SELECT COALESCE(MAX(id),0) - 2000 FROM audit_logs)"
        )
    )


def load_srv() -> dict:
    with db.s() as s:
        rows = s.scalars(select(Setting).where(Setting.key.in_(SRV_KEYS))).all()
        values = {r.key: r.value for r in rows}
    return protocols.resolve_srv(values)


def load_inbounds() -> list:
    with db.s() as s:
        rows = s.scalars(select(Inbound).order_by(Inbound.id)).all()
        return [r.to_dict() for r in rows]


TG_KEYS = {"tg_bot_token", "tg_chat_id"}


def notify_async(text: str) -> None:
    def _send():
        try:
            token = decrypt_text(cached_setting("tg_bot_token"))
            chat = cached_setting("tg_chat_id") or ""
            if not token or not chat:
                return
            import urllib.parse
            import urllib.request

            data = urllib.parse.urlencode({"chat_id": chat, "text": text[:500]}).encode()
            req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
            urllib.request.urlopen(req, timeout=6)
        except Exception as e:
            log.debug("telegram notify failed: %s", e)

    threading.Thread(target=_send, daemon=True).start()


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    psutil.cpu_percent(interval=None)
    with db.s() as s:
        if not s.scalar(select(Admin).limit(1)):
            username = os.environ.get("ZEFIRA_ADMIN_USERNAME", "admin")
            password = os.environ.get("ZEFIRA_ADMIN_PASSWORD") or secrets.token_urlsafe(14)
            s.add(Admin(username=username, password_hash=hash_password(password)))
            s.commit()
            print("=" * 58)
            print("  ZEFIRA PANEL - FIRST RUN")
            print(f"  URL:      http://127.0.0.1:8000/")
            print(f"  USERNAME: {username}")
            print(f"  PASSWORD: {password}")
            print("  !! CHANGE THIS PASSWORD FROM SETTINGS AFTER LOGIN !!")
            print("=" * 58)
            log.warning("First-run admin created. Password printed above.")
    yield


app = FastAPI(title="Zefira", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; "
    "object-src 'none'"
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    response.headers["Content-Security-Policy"] = CSP
    if request.url.path.startswith("/api") or request.url.path.startswith("/sub"):
        response.headers.setdefault("Cache-Control", "no-store")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.middleware("http")
async def csrf_and_size_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 1048576:
                return JSONResponse({"detail": "payload too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "bad request"}, status_code=400)
    if request.url.path.startswith("/api") and request.method not in {"GET", "HEAD", "OPTIONS"}:
        if request.headers.get("x-requested-with") != "XMLHttpRequest":
            return JSONResponse({"detail": "forbidden"}, status_code=403)
    return await call_next(request)


def client_ip(request: Request) -> str:
    sock_host = request.client.host if request.client else "?"
    try:
        sock_ip = ipaddress.ip_address(sock_host)
    except ValueError:
        return sock_host
    nets = trusted_networks()
    if any(sock_ip in n for n in nets):
        xff = request.headers.get("x-forwarded-for", "")
        for candidate in reversed([c.strip() for c in xff.split(",") if c.strip()]):
            try:
                cip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not any(cip in n for n in nets):
                return str(cip)
    return str(sock_ip)


async def require_admin(request: Request) -> Admin:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Session expired")
    payload = decode_session(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Session expired")
    with db.s() as s:
        admin = s.get(Admin, int(payload.get("sub", 0)))
        if not admin or payload.get("ver") != admin.token_version:
            raise HTTPException(status_code=401, detail="Session expired")
        request.state.admin_id = admin.id
        return admin


def set_session_cookie(response: Response, request: Request, admin_id: int, version: int) -> None:
    token = create_session(admin_id, version)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )


@app.get("/")
def root():
    return RedirectResponse("/panel")


@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"title": "Sign in | Zefira"})


@app.get("/panel")
def panel_page(request: Request):
    return templates.TemplateResponse(request, "panel.html", {"title": "Zefira Panel"})


@app.post("/api/login")
def api_login(data: LoginIn, request: Request, response: Response):
    ip = client_ip(request)
    ukey = f"u|{data.username.lower()}"
    key = f"{ip}|{data.username.lower()}"
    if not login_user_limiter.hit(ukey) or not login_limiter.hit(key):
        log.warning("Rate-limited login attempt ip=%s user=%s", ip, data.username)
        notify_async(f"\u26a0 Zefira: brute-force lockout triggered from IP {ip} (user: {data.username})")
        raise HTTPException(status_code=429, detail="Too many attempts, try again in a few minutes")
    fail_msg = "Invalid username or password"
    with db.s() as s:
        admin = s.scalar(select(Admin).where(Admin.username == data.username.lower()))
        if admin is None:
            dummy_verify(data.password)
            audit(s, "LOGIN_FAIL", f"user={data.username}", ip, ok=False)
            s.commit()
            log.warning("Failed login (unknown user) ip=%s user=%s", ip, data.username)
            raise HTTPException(status_code=401, detail=fail_msg)
        if not verify_password(data.password, admin.password_hash):
            audit(s, "LOGIN_FAIL", f"user={admin.username}", ip, ok=False)
            s.commit()
            log.warning("Failed login ip=%s user=%s", ip, admin.username)
            raise HTTPException(status_code=401, detail=fail_msg)
        if admin.totp_enabled:
            totp_secret = decrypt_text(admin.totp_secret)
            if not data.code or not verify_totp(totp_secret, data.code):
                audit(s, "LOGIN_2FA_FAIL", f"user={admin.username}", ip, ok=False)
                s.commit()
                log.warning("2FA failed ip=%s user=%s", ip, admin.username)
                if not data.code:
                    raise HTTPException(
                        status_code=401,
                        detail={"message": "Two-factor code required", "code": "totp_required"},
                    )
                raise HTTPException(status_code=401, detail="Invalid two-factor code")
        login_limiter.reset(key)
        login_user_limiter.reset(ukey)
        set_session_cookie(response, request, admin.id, admin.token_version)
        audit(s, "LOGIN_OK", f"user={admin.username}", ip)
        s.commit()
        log.info("Login success user=%s ip=%s", admin.username, ip)
        return {"ok": True}


@app.post("/api/logout")
def api_logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/me")
def api_me(admin: Admin = Depends(require_admin)):
    return {
        "username": admin.username,
        "created_at": admin.created_at.isoformat(timespec="seconds") + "Z",
        "totp_enabled": admin.totp_enabled,
    }


@app.post("/api/change-password")
def api_change_password(
    data: ChangePasswordIn, request: Request, response: Response, admin: Admin = Depends(require_admin)
):
    if not pw_limiter.hit(f"pw|{admin.id}"):
        log.warning("Password change throttled user=%s", admin.username)
        raise HTTPException(status_code=429, detail="Too many attempts, wait a few minutes")
    if not verify_password(data.current_password, admin.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if not STRONG_PW_RE.match(data.new_password):
        raise HTTPException(
            status_code=400,
            detail="New password must be at least 10 characters and contain letters AND digits (no spaces)",
        )
    if data.current_password == data.new_password:
        raise HTTPException(status_code=400, detail="New password must be different")
    with db.s() as s:
        row = s.get(Admin, admin.id)
        row.password_hash = hash_password(data.new_password)
        row.token_version += 1
        audit(s, "PW_CHANGE", f"user={row.username}", client_ip(request))
        s.commit()
        version = row.token_version
    pw_limiter.reset(f"pw|{admin.id}")
    login_limiter.reset(f"{client_ip(request)}|{row.username.lower()}")
    set_session_cookie(response, request, admin.id, version)
    log.info("Password changed user=%s ip=%s", admin.username, client_ip(request))
    return {"ok": True}


@app.get("/api/2fa/status")
def api_2fa_status(admin: Admin = Depends(require_admin)):
    return {"enabled": admin.totp_enabled}


@app.post("/api/2fa/setup")
def api_2fa_setup(request: Request, admin: Admin = Depends(require_admin)):
    if admin.totp_enabled:
        raise HTTPException(status_code=400, detail="Two-factor auth is already enabled")
    secret_plain = gen_totp_secret()
    with db.s() as s:
        row = s.get(Admin, admin.id)
        row.totp_pending = encrypt_text(secret_plain)
        audit(s, "TFA_SETUP", f"user={admin.username}", client_ip(request))
        s.commit()
    uri = otpauth_uri(admin.username, secret_plain)
    return {"uri": uri, "qr_b64": protocols.qr_svg_b64(uri)}


@app.post("/api/2fa/enable")
def api_2fa_enable(data: TotpCodeIn, request: Request, admin: Admin = Depends(require_admin)):
    if not tfa_limiter.hit(f"tfa|{admin.id}"):
        raise HTTPException(status_code=429, detail="Too many attempts, wait a few minutes")
    pending = decrypt_text(admin.totp_pending)
    if not pending:
        raise HTTPException(status_code=400, detail="Start the setup first")
    if not verify_totp(pending, data.code):
        raise HTTPException(status_code=400, detail="The code is not valid")
    with db.s() as s:
        row = s.get(Admin, admin.id)
        row.totp_secret = row.totp_pending
        row.totp_pending = None
        row.totp_enabled = True
        audit(s, "TFA_ENABLE", f"user={row.username}", client_ip(request))
        s.commit()
    log.info("2FA enabled user=%s", admin.username)
    return {"ok": True, "enabled": True}


@app.post("/api/2fa/disable")
def api_2fa_disable(data: TotpCodeIn, request: Request, admin: Admin = Depends(require_admin)):
    if not tfa_limiter.hit(f"tfa|{admin.id}"):
        raise HTTPException(status_code=429, detail="Too many attempts, wait a few minutes")
    active = decrypt_text(admin.totp_secret)
    if not admin.totp_enabled or not verify_totp(active, data.code):
        raise HTTPException(status_code=400, detail="The code is not valid")
    tfa_limiter.reset(f"tfa|{admin.id}")
    with db.s() as s:
        row = s.get(Admin, admin.id)
        row.totp_enabled = False
        row.totp_secret = None
        row.totp_pending = None
        audit(s, "TFA_DISABLE", f"user={row.username}", client_ip(request))
        s.commit()
    log.info("2FA disabled user=%s", admin.username)
    return {"ok": True, "enabled": False}


@app.get("/api/audit")
def api_audit(admin: Admin = Depends(require_admin)):
    with db.s() as s:
        rows = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(50)).all()
        return [r.to_dict() for r in rows]


@app.get("/api/system")
def api_system(admin: Admin = Depends(require_admin)):
    try:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage(str(BASE_DIR)).percent
        boot = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        uptime_h = round((datetime.now(timezone.utc) - boot).total_seconds() / 3600, 1)
        return {
            "available": True,
            "cpu": round(cpu, 1),
            "mem": round(mem, 1),
            "disk": round(disk, 1),
            "uptime_hours": uptime_h,
        }
    except Exception:
        return {"available": False}


@app.get("/api/settings")
def api_settings_get(admin: Admin = Depends(require_admin)):
    srv = load_srv()
    return {k: srv[k] for k in sorted(SRV_KEYS)}


@app.put("/api/settings")
def api_settings_put(data: SettingsIn, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        for k in ("domain", "sub_port", "hy2_port", "wg_port", "wg_pub", "dns", "ovpn_port", "ovpn_proto", "reality_port", "reality_sni", "obfuscated_host", "per_user_subdomain", "cdn_enabled", "cdn_sni"):
            v = getattr(data, k)
            if k in ("per_user_subdomain", "cdn_enabled"):
                v = "1" if v else "0"
            row = s.get(Setting, k)
            if row is None:
                s.add(Setting(key=k, value=str(v)))
            else:
                row.value = str(v)
        audit(s, "SETTINGS_UPDATE", f"by {admin.username}", client_ip(request))
        s.commit()
    log.info("Server settings updated by %s", admin.username)
    srv = load_srv()
    return {k: srv[k] for k in sorted(SRV_KEYS)}


@app.post("/api/reality/generate")
def api_reality_generate(request: Request, admin: Admin = Depends(require_admin)):
    priv, pub = protocols.generate_reality_keypair()
    with db.s() as s:
        for k, v in (("reality_pub", pub), ("reality_priv_enc", encrypt_text(priv))):
            row = s.get(Setting, k)
            if row is None:
                s.add(Setting(key=k, value=v))
            else:
                row.value = v
        audit(s, "REALITY_GENERATE", f"by {admin.username}", client_ip(request))
        s.commit()
    log.info("REALITY keypair generated by %s", admin.username)
    return {"public_key": pub, "private_key": priv}


@app.get("/api/reality/private")
def api_reality_private(request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        row = s.get(Setting, "reality_priv_enc")
        enc = row.value if row else None
    priv = decrypt_text(enc)
    if not priv:
        raise HTTPException(status_code=404, detail="No REALITY private key stored yet")
    with db.s() as s:
        audit(s, "REALITY_REVEAL", f"private key viewed by {admin.username}", client_ip(request))
        s.commit()
    return {"private_key": priv}


@app.get("/api/templates")
def api_templates_list(admin: Admin = Depends(require_admin)):
    with db.s() as s:
        rows = s.scalars(select(UserTemplate).order_by(UserTemplate.name)).all()
        return [t.to_dict() for t in rows]


@app.post("/api/templates")
def api_templates_create(data: TemplateCreateIn, request: Request, admin: Admin = Depends(require_admin)):
    proto_list = list(dict.fromkeys(data.protocols))
    with db.s() as s:
        exists = s.scalar(select(UserTemplate.id).where(UserTemplate.name == data.name))
        if exists:
            row = s.get(UserTemplate, exists)
            row.protocols = ",".join(proto_list)
            row.volume_gb = data.volume_gb
            row.days = data.days
            row.start_on_first_use = data.start_on_first_use
            action = "updated"
        else:
            s.add(UserTemplate(
                name=data.name,
                protocols=",".join(proto_list),
                volume_gb=data.volume_gb,
                days=data.days,
                start_on_first_use=data.start_on_first_use,
            ))
            action = "created"
        audit(s, "TEMPLATE_SAVE", f"{data.name} {action} by {admin.username}", client_ip(request))
        s.commit()
    return {"ok": True}


@app.delete("/api/templates/{template_id}")
def api_templates_delete(template_id: int, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        t = s.get(UserTemplate, template_id)
        if not t:
            raise HTTPException(status_code=404, detail="Template not found")
        name = t.name
        s.delete(t)
        audit(s, "TEMPLATE_DELETE", f"{name} by {admin.username}", client_ip(request))
        s.commit()
    return {"ok": True}


@app.get("/api/tunnel-settings")
def api_tunnel_get(admin: Admin = Depends(require_admin)):
    return {
        "public_url": cached_setting("public_url") or "",
        "trusted_proxies": cached_setting("trusted_proxies") or "",
    }


@app.put("/api/tunnel-settings")
def api_tunnel_put(data: TunnelSettingsIn, request: Request, admin: Admin = Depends(require_admin)):
    for part in (data.trusted_proxies or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP/CIDR in trusted proxies: {part}")
    with db.s() as s:
        for k, v in (
            ("public_url", data.public_url),
            ("trusted_proxies", data.trusted_proxies),
        ):
            row = s.get(Setting, k)
            if row is None:
                s.add(Setting(key=k, value=v))
            else:
                row.value = v
        audit(s, "TUNNEL_SETTINGS", f"by {admin.username}", client_ip(request))
        s.commit()
    for k in TUNNEL_KEYS:
        _settings_cache.pop(k, None)
    log.info("Tunnel settings updated by %s", admin.username)
    return {"ok": True}


@app.get("/api/nodes")
def api_nodes_list(admin: Admin = Depends(require_admin)):
    with db.s() as s:
        rows = s.scalars(select(TunnelNode).order_by(TunnelNode.id.desc())).all()
        return [n.to_dict() for n in rows]


@app.post("/api/nodes")
def api_nodes_create(data: TunnelNodeIn, request: Request, admin: Admin = Depends(require_admin)):
    token_plain = secrets.token_urlsafe(24)
    with db.s() as s:
        exists = s.scalar(select(TunnelNode.id).where(TunnelNode.name == data.name))
        if exists:
            raise HTTPException(status_code=409, detail="A tunnel with this name already exists")
        node = TunnelNode(
            name=data.name,
            transport=data.transport,
            iran_ip=data.iran_ip,
            kharej_ip=data.kharej_ip,
            tunnel_port=data.tunnel_port,
            forwarded_ports=", ".join(p.strip() for p in data.forwarded_ports.split(",") if p.strip()),
            udp_forward=data.udp_forward,
            token_enc=encrypt_text(token_plain),
        )
        s.add(node)
        try:
            s.commit()
        except IntegrityError:
            s.rollback()
            raise HTTPException(status_code=409, detail="A tunnel with this name already exists")
        out = node.to_dict()
        out["token_once"] = token_plain
        audit(s, "NODE_CREATE", f"{data.name} {data.transport} by {admin.username}", client_ip(request))
        s.commit()
    log.info("BackPack tunnel created %s by %s", data.name, admin.username)
    return out


def _get_node_or_404(s, node_id: int) -> TunnelNode:
    node = s.get(TunnelNode, node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    return node


@app.post("/api/nodes/{node_id}/reveal-token")
def api_node_reveal_token(node_id: int, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        node = _get_node_or_404(s, node_id)
        token = decrypt_text(node.token_enc)
        name = node.name
        audit(s, "NODE_TOKEN_REVEAL", f"{name} by {admin.username}", client_ip(request))
        s.commit()
    return {"token": token}


@app.post("/api/nodes/{node_id}/regen-token")
def api_node_regen_token(node_id: int, request: Request, admin: Admin = Depends(require_admin)):
    token_plain = secrets.token_urlsafe(24)
    with db.s() as s:
        node = _get_node_or_404(s, node_id)
        node.token_enc = encrypt_text(token_plain)
        node.status = "unknown"
        audit(s, "NODE_TOKEN_REGEN", f"{node.name} by {admin.username}", client_ip(request))
        s.commit()
        name = node.name
    log.info("Tunnel token regenerated %s by %s", name, admin.username)
    return {"token": token_plain}


@app.get("/api/nodes/{node_id}/guide")
def api_node_guide(node_id: int, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        node = _get_node_or_404(s, node_id)
        token = decrypt_text(node.token_enc)
        ndict = node.to_dict()
        name = node.name
        audit(s, "NODE_GUIDE_DL", f"{name} by {admin.username}", client_ip(request))
        s.commit()
    guide = protocols.backpack_guide(ndict, token)
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", name) or "tunnel"
    return PlainTextResponse(
        guide,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="backpack-setup-{safe}.txt"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/nodes/{node_id}/check")
def api_node_check(node_id: int, request: Request, admin: Admin = Depends(require_admin)):
    import socket

    if not probe_limiter.hit(f"probe|{admin.id}"):
        raise HTTPException(status_code=429, detail="Too many checks, wait a minute")
    with db.s() as s:
        node = _get_node_or_404(s, node_id)
        host = node.iran_ip
        port = node.tunnel_port
        node_id_val = node.id
    online = False
    try:
        addrinfos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        addrinfos = []
    for family, socktype, proto, _canonname, sa in addrinfos[:3]:
        conn = socket.socket(family, socktype, proto)
        conn.settimeout(3.0)
        try:
            conn.connect(sa)
            online = True
        except OSError:
            pass
        finally:
            conn.close()
        if online:
            break
    with db.s() as s:
        node = s.get(TunnelNode, node_id_val)
        node.status = "online" if online else "offline"
        node.last_check = utcnow()
        out = node.to_dict()
        audit(s, "NODE_CHECK", f"{node.name} -> {out['status']} by {admin.username}", client_ip(request), ok=online)
        s.commit()
    return out


@app.get("/api/backup")
def api_backup(request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        users = [u.to_backup_dict() for u in s.scalars(select(VpnUser)).all()]
        admins = [a.to_backup_dict() for a in s.scalars(select(Admin)).all()]
        settings = {
            r.key: r.value
            for r in s.scalars(select(Setting).where(Setting.key.in_(SRV_KEYS | TUNNEL_KEYS | {"reality_priv_enc"}))).all()
        }
        tpl_rows = s.scalars(select(UserTemplate)).all()
        templates_out = [
            {"name": t.name, "protocols": t.protocols, "volume_gb": t.volume_gb,
             "days": t.days, "start_on_first_use": t.start_on_first_use}
            for t in tpl_rows
        ]
    payload = {
        "zefira_backup": True,
        "version": 5,
        "exported_at": utcnow().isoformat(timespec="seconds") + "Z",
        "settings": settings,
        "admins": admins,
        "users": users,
        "templates": templates_out,
    }
    body = json.dumps(payload, indent=2)
    with db.s() as s:
        audit(s, "BACKUP_DL", f"{len(users)} users by {admin.username}", client_ip(request))
        s.commit()
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    return PlainTextResponse(
        body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="zefira-backup-{stamp}.json"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/restore")
def api_restore(data: RestoreIn, request: Request, admin: Admin = Depends(require_admin)):
    if not verify_password(data.password_confirm, admin.password_hash):
        with db.s() as s:
            audit(s, "RESTORE_FAIL", f"wrong confirm password by {admin.username}", client_ip(request), ok=False)
            s.commit()
        raise HTTPException(status_code=400, detail="Confirm password is incorrect")
    now = utcnow()
    added_users = skipped = restored_settings = restored_admins = restored_templates = 0
    prepared_users = []
    for ru in data.users:
        try:
            expires = datetime.fromisoformat(ru.expires_at.replace("Z", "+00:00")).replace(tzinfo=None)
            created = (
                datetime.fromisoformat(ru.created_at.replace("Z", "+00:00")).replace(tzinfo=None)
                if ru.created_at
                else now
            )
        except ValueError:
            skipped += 1
            continue
        prepared_users.append(
            VpnUser(
                username=ru.username,
                protocol=ru.protocol,
                protocols=ru.protocols or ru.protocol,
                note=ru.note or "",
                volume_gb=ru.volume_gb,
                used_gb=ru.used_gb,
                token=ru.token,
                secret_data=ru.secret_data or "",
                is_active=ru.is_active,
                created_at=created,
                expires_at=expires,
            )
        )
    seen_names = set()
    deduped = []
    for pu in prepared_users:
        if pu.username in seen_names:
            skipped += 1
            continue
        seen_names.add(pu.username)
        deduped.append(pu)
    prepared_users = deduped
    with db.s() as s:
        for u in s.scalars(select(VpnUser)).all():
            s.delete(u)
        s.flush()
        for pu in prepared_users:
            s.add(pu)
            added_users += 1
        if data.settings:
            for k, v in data.settings.items():
                if k not in SRV_KEYS and k not in TUNNEL_KEYS and k not in {"reality_priv_enc", "wg_self_priv_enc"}:
                    continue
                sval = str(v)
                if len(sval) > 500:
                    continue
                ok = True
                if k in ("domain", "obfuscated_host", "cdn_sni"):
                    if sval and not re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?", sval):
                        ok = False
                elif k == "dns":
                    if sval and not re.fullmatch(r"[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?", sval):
                        ok = False
                elif k.endswith("_port"):
                    try:
                        ok = 1 <= int(sval) <= 65535
                    except (TypeError, ValueError):
                        ok = False
                elif k in ("ovpn_proto",):
                    ok = sval in ("udp", "tcp")
                elif k in ("per_user_subdomain", "cdn_enabled"):
                    ok = sval.lower() in ("0", "1", "true", "false", "yes", "no", "on", "off", "")
                    if ok:
                        sval = "1" if sval.lower() in ("1", "true", "yes", "on") else "0"
                elif k == "reality_sni":
                    if not re.fullmatch(r"[a-zA-Z0-9.,\- ]{0,300}", sval):
                        ok = False
                elif k == "wg_pub":
                    if len(sval) > 200:
                        ok = False
                elif k in ("public_url",):
                    if sval and not re.fullmatch(r"https?://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:[0-9]{1,5})?", sval):
                        ok = False
                elif k in ("trusted_proxies",):
                    if len(sval) > 500:
                        ok = False
                    else:
                        for part in sval.split(","):
                            part = part.strip()
                            if not part:
                                continue
                            try:
                                ipaddress.ip_network(part, strict=False)
                            except ValueError:
                                ok = False
                                break
                if not ok:
                    continue
                row = s.get(Setting, k)
                if row is None:
                    s.add(Setting(key=k, value=sval))
                else:
                    row.value = sval
                restored_settings += 1
        if data.admins:
            for ra in data.admins:
                existing = s.scalar(select(Admin).where(Admin.username == ra.username.lower()))
                if existing:
                    existing.password_hash = ra.password_hash
                    existing.totp_enabled = ra.totp_enabled
                    existing.totp_secret = ra.totp_secret
                    existing.token_version += 1
                else:
                    s.add(
                        Admin(
                            username=ra.username.lower(),
                            password_hash=ra.password_hash,
                            totp_enabled=ra.totp_enabled,
                            totp_secret=ra.totp_secret,
                            token_version=1,
                        )
                    )
                restored_admins += 1
        current = s.get(Admin, admin.id)
        current.token_version += 1
        fresh_version = current.token_version
        audit(
            s,
            "RESTORE",
            f"+{added_users} users (-{skipped} skipped), settings={restored_settings}, admins={restored_admins} by {admin.username}",
            client_ip(request),
        )
        s.commit()
    response = JSONResponse(
        {
            "ok": True,
            "added_users": added_users,
            "skipped": skipped,
            "restored_settings": restored_settings,
            "restored_admins": restored_admins,
        }
    )
    set_session_cookie(response, request, admin.id, fresh_version)
    log.info("Restore done +%s users by %s", added_users, admin.username)
    return response


@app.get("/api/inbounds")
def api_inbounds_list(admin: Admin = Depends(require_admin)):
    return load_inbounds()


@app.post("/api/inbounds")
def api_inbounds_create(data: InboundIn, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        exists = s.scalar(select(Inbound.id).where(Inbound.name == data.name))
        if exists:
            raise HTTPException(status_code=409, detail="An inbound with this name already exists")
        ib = Inbound(
            name=data.name,
            protocol=data.protocol,
            port=data.port,
            host=data.host or "",
            enabled=data.enabled,
        )
        s.add(ib)
        try:
            s.commit()
        except IntegrityError:
            s.rollback()
            raise HTTPException(status_code=409, detail="An inbound with this name already exists")
        out = ib.to_dict()
        audit(s, "INBOUND_CREATE", f"{data.name} {data.protocol}:{data.port} by {admin.username}", client_ip(request))
        s.commit()
    log.info("Inbound created %s by %s", data.name, admin.username)
    return out


@app.patch("/api/inbounds/{inbound_id}")
def api_inbounds_patch(
    inbound_id: int, data: InboundPatchIn, request: Request, admin: Admin = Depends(require_admin)
):
    with db.s() as s:
        ib = s.get(Inbound, inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="Inbound not found")
        if data.enabled is not None:
            ib.enabled = data.enabled
        if data.port is not None:
            ib.port = data.port
        if data.host is not None:
            ib.host = data.host
        s.commit()
        out = ib.to_dict()
        audit(s, "INBOUND_PATCH", f"{ib.name} by {admin.username}", client_ip(request))
        s.commit()
    return out


@app.delete("/api/inbounds/{inbound_id}")
def api_inbounds_delete(inbound_id: int, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        ib = s.get(Inbound, inbound_id)
        if not ib:
            raise HTTPException(status_code=404, detail="Inbound not found")
        name = ib.name
        s.delete(ib)
        audit(s, "INBOUND_DELETE", f"{name} by {admin.username}", client_ip(request))
        s.commit()
    log.info("Inbound deleted %s by %s", name, admin.username)
    return {"ok": True}



@app.get("/api/telegram")
def api_telegram_get(admin: Admin = Depends(require_admin)):
    return {
        "chat_id": cached_setting("tg_chat_id") or "",
        "has_token": bool(decrypt_text(cached_setting("tg_bot_token"))),
    }


@app.put("/api/telegram")
def api_telegram_put(data: TelegramSettingsIn, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        row = s.get(Setting, "tg_bot_token")
        val = encrypt_text(data.bot_token) if data.bot_token else ""
        if row is None:
            if val:
                s.add(Setting(key="tg_bot_token", value=val))
        elif val:
            row.value = val
        crow = s.get(Setting, "tg_chat_id")
        if crow is None:
            s.add(Setting(key="tg_chat_id", value=data.chat_id))
        else:
            crow.value = data.chat_id
        audit(s, "TG_SETTINGS", f"by {admin.username}", client_ip(request))
        s.commit()
    _settings_cache.pop("tg_bot_token", None)
    _settings_cache.pop("tg_chat_id", None)
    return {"ok": True}


@app.post("/api/telegram/test")
def api_telegram_test(data: TelegramTestIn, request: Request, admin: Admin = Depends(require_admin)):
    token = decrypt_text(cached_setting("tg_bot_token"))
    chat = cached_setting("tg_chat_id") or ""
    if not token or not chat:
        raise HTTPException(status_code=400, detail="Save a bot token and chat id first")
    import urllib.parse
    import urllib.request

    try:
        payload = urllib.parse.urlencode({"chat_id": chat, "text": data.message}).encode()
        r = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=payload)
        resp = urllib.request.urlopen(r, timeout=8)
        ok_code = resp.status == 200
        err = "" if ok_code else f"HTTP {resp.status}"
    except Exception as exc:
        ok_code = False
        err = str(exc)[:150]
    with db.s() as s:
        audit(s, "TG_TEST", f"by {admin.username} -> {'ok' if ok_code else err}", client_ip(request), ok=ok_code)
        s.commit()
    if not ok_code:
        raise HTTPException(status_code=502, detail=f"Telegram send failed: {err}")
    return {"ok": True}



@app.get("/api/stats")
def api_stats(admin: Admin = Depends(require_admin)):
    now = utcnow()
    soon = now + timedelta(days=7)
    with db.s() as s:
        rows = s.execute(
            select(VpnUser.is_active, VpnUser.expires_at, VpnUser.volume_gb, VpnUser.used_gb, VpnUser.start_on_first_use)
        ).all()
    active = expired = disabled = expiring_soon = pending_start = limited = 0
    volume_total = used_total = 0.0
    for is_active, expires_at, vol, used, sof in rows:
        volume_total += vol
        used_total += used
        if not is_active:
            disabled += 1
            continue
        pending = sof and expires_at is not None and expires_at.year >= PENDING_YEAR
        if pending:
            pending_start += 1
            continue
        if used >= vol:
            limited += 1
        if expires_at <= now:
            expired += 1
        else:
            active += 1
            if expires_at <= soon:
                expiring_soon += 1
    return {
        "total_users": len(rows),
        "active_users": active,
        "expired_users": expired,
        "disabled_users": disabled,
        "expiring_soon": expiring_soon,
        "pending_start": pending_start,
        "limited_users": limited,
        "volume_total_gb": round(volume_total, 2),
        "used_total_gb": round(used_total, 2),
    }


@app.get("/api/users")
def api_users(q: str = "", admin: Admin = Depends(require_admin)):
    q = q.strip()[:64]
    q_esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    stmt = select(VpnUser).order_by(VpnUser.id.desc()).limit(500)
    if q_esc:
        like = f"%{q_esc}%"
        stmt = (
            select(VpnUser)
            .where(VpnUser.username.like(like, escape="\\") | VpnUser.note.like(like, escape="\\"))
            .order_by(VpnUser.id.desc())
            .limit(500)
        )
    with db.s() as s:
        items = [u.to_dict() for u in s.scalars(stmt)]
    return {"items": items}


@app.post("/api/users")
def api_create_user(data: UserCreateIn, request: Request, admin: Admin = Depends(require_admin)):
    if not USERNAME_RE.match(data.username):
        raise HTTPException(status_code=400, detail="Username: English letters, digits and _ only (3-32 chars)")
    proto_list = list(dict.fromkeys(data.protocols))
    now = utcnow()
    expires = (
        datetime(PENDING_YEAR + 10, 1, 1)
        if data.start_on_first_use
        else now + timedelta(days=data.days)
    )
    with db.s() as s:
        exists = s.scalar(select(VpnUser.id).where(VpnUser.username == data.username))
        if exists:
            raise HTTPException(status_code=409, detail="This username is already taken")
        try:
            secret_map = protocols.provision_map(proto_list, data.username)
        except Exception:
            log.exception("provision failed protos=%s", proto_list)
            raise HTTPException(status_code=500, detail="Config generation failed")
        user = VpnUser(
            username=data.username,
            protocol=proto_list[0],
            protocols=",".join(proto_list),
            note=data.note,
            volume_gb=data.volume_gb,
            token=secrets.token_hex(16),
            secret_data=protocols.serialize_secrets(secret_map),
            start_on_first_use=data.start_on_first_use,
            duration_days=data.days if data.start_on_first_use else None,
            created_at=now,
            expires_at=expires,
        )
        s.add(user)
        try:
            s.commit()
        except IntegrityError:
            s.rollback()
            raise HTTPException(status_code=409, detail="This username is already taken")
        out = user.to_dict()
        flags = f" [{','.join(proto_list)}]"
        if data.start_on_first_use:
            flags += " starts-on-first-use"
        audit(s, "USER_CREATE", f"{data.username}{flags} by {admin.username}", client_ip(request))
        s.commit()
    notify_async(f"\u2713 Zefira: user <b>{data.username}</b> created [{','.join(proto_list)}] by {admin.username}")
    log.info("User created %s %s by %s", data.username, proto_list, admin.username)
    return out


def _get_user_or_404(s, user_id: int) -> VpnUser:
    user = s.get(VpnUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.patch("/api/users/{user_id}")
def api_patch_user(user_id: int, data: UserPatchIn, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        user = _get_user_or_404(s, user_id)
        changes = []
        if data.is_active is not None:
            user.is_active = data.is_active
        if data.extend_days is not None:
            base = user.expires_at if (user.expires_at and user.expires_at.year < PENDING_YEAR) else utcnow()
            user.expires_at = base + timedelta(days=data.extend_days)
            changes.append(f"+{data.extend_days}d")
        if data.add_volume_gb is not None:
            user.volume_gb = max(0.01, user.volume_gb + data.add_volume_gb)
            changes.append(f"vol+{data.add_volume_gb}")
        if data.add_used_gb is not None:
            user.used_gb = max(0.0, user.used_gb + data.add_used_gb)
            changes.append(f"used{data.add_used_gb:+g}")
        if data.set_note is not None:
            user.note = data.set_note
            changes.append("note")
        if data.set_volume_gb is not None:
            user.volume_gb = data.set_volume_gb
            changes.append(f"vol={data.set_volume_gb:g}")
        if data.reset_used:
            user.used_gb = 0.0
            changes.append("used=0")
        if data.set_expires_at:
            try:
                explicit = datetime.strptime(data.set_expires_at, "%Y-%m-%dT%H:%M").replace(tzinfo=None)
            except ValueError:
                raise HTTPException(status_code=422, detail="Invalid expiry datetime")
            user.expires_at = explicit
            user.start_on_first_use = False
            user.duration_days = None
            changes.append(f"expire={data.set_expires_at}")
        s.commit()
        out = user.to_dict()
        audit(
            s,
            "USER_PATCH",
            f"{user.username} ({', '.join(changes) or 'no-op'}) by {admin.username}",
            client_ip(request),
        )
        s.commit()
    log.info("User patched id=%s %s by %s", user_id, changes, admin.username)
    return out


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: int, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        user = _get_user_or_404(s, user_id)
        name = user.username
        s.delete(user)
        s.commit()
        audit(s, "USER_DELETE", f"{name} by {admin.username}", client_ip(request))
        s.commit()
    notify_async(f"\u2715 Zefira: user <b>{name}</b> deleted by {admin.username}")
    log.info("User deleted %s by %s", name, admin.username)
    return {"ok": True}


@app.post("/api/users/{user_id}/reset-token")
def api_reset_token(user_id: int, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        user = _get_user_or_404(s, user_id)
        user.token = secrets.token_hex(16)
        proto_list = user.protocols_list()
        user.secret_data = protocols.serialize_secrets(protocols.provision_map(proto_list, user.username))
        s.commit()
        out = user.to_dict()
        audit(s, "TOKEN_RESET", f"{user.username} by {admin.username}", client_ip(request))
        s.commit()
    log.info("Token+secrets reset id=%s by %s", user_id, admin.username)
    return out


@app.get("/api/users/{user_id}/qr")
def api_user_qr(user_id: int, request: Request, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        user = _get_user_or_404(s, user_id)
        token = user.token
    base = public_base_url(request)
    sub_url = f"{base}/sub/{token}"
    return {"url": sub_url, "qr_b64": protocols.qr_svg_b64(sub_url)}


@app.get("/api/users/{user_id}/config")
def api_user_config(user_id: int, admin: Admin = Depends(require_admin)):
    with db.s() as s:
        user = _get_user_or_404(s, user_id)
        udict = user.to_full_dict()
    uname = udict["username"]
    files = protocols.build_files(udict, load_srv(), load_inbounds())
    if not files:
        raise HTTPException(status_code=500, detail="Config generation failed")
    if len(files) == 1:
        fname, content = files[0]
        log.info("Config downloaded %s by %s", uname, admin.username)
        return PlainTextResponse(
            content,
            headers={
                "Content-Disposition": f'attachment; filename="{fname}"',
                "Cache-Control": "no-store",
            },
        )
    zipbytes = protocols.zip_files(files)
    log.info("Config bundle downloaded %s (%d files) by %s", uname, len(files), admin.username)
    return Response(
        content=zipbytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="zefira-{uname}-configs.zip"',
            "Cache-Control": "no-store",
        },
    )


def _sub_info(u: dict) -> str:
    used = int(float(u.get("used_gb", 0)) * 1073741824)
    total = int(float(u.get("volume_gb", 0)) * 1073741824)
    expires = u.get("expires_at")
    exp_ts = int(datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()) if expires else 0
    return f"upload=0; download={used}; total={total}; expire={exp_ts}"


@app.get("/sub/{token}")
def subscription(token: str, request: Request):
    ip = client_ip(request)
    if not sub_limiter.hit(f"sub|{ip}"):
        raise HTTPException(status_code=429, detail="Too many requests")
    if not TOKEN_RE.fullmatch(token or ""):
        raise HTTPException(status_code=404, detail="Not Found")
    fmt = (request.query_params.get("format") or "").lower()
    ua = (request.headers.get("user-agent") or "").lower()
    want_clash = fmt in ("clash", "clashmeta") or "clash" in ua
    with db.s() as s:
        user = s.scalar(select(VpnUser).where(VpnUser.token == token))
        if not user or not user.is_active:
            raise HTTPException(status_code=404, detail="Not Found")
        if user.start_on_first_use and user.expires_at is not None and user.expires_at.year >= PENDING_YEAR:
            duration = user.duration_days or 30
            user.expires_at = utcnow() + timedelta(days=duration)
            audit(s, "USER_START", f"{user.username} activated on first connection (+{duration}d)", ip)
            s.commit()
        if user.expires_at <= utcnow():
            raise HTTPException(status_code=404, detail="Not Found")
        udict = user.to_full_dict()
    srv = load_srv()
    info = _sub_info(udict)
    if want_clash:
        yaml_text = protocols.clash_yaml(udict, srv)
        return PlainTextResponse(
            yaml_text,
            media_type="text/yaml; charset=utf-8",
            headers={"Cache-Control": "no-store", "subscription-userinfo": info},
        )
    body, ct = protocols.subscription_body(udict, srv, load_inbounds())
    return PlainTextResponse(body, media_type=ct, headers={"Cache-Control": "no-store", "subscription-userinfo": info})


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, proxy_headers=False)
