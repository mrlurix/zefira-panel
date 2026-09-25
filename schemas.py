from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

USERNAME_RE = r"^[a-zA-Z0-9_]{3,32}\z"


def _reject_bool_str(v):
    """Accept int/float numbers only: reject bool (subclass of int) and
    numeric strings (\"30\", \"0x10\", \"1e3\") that lax coercion would
    otherwise silently accept. Lets int 30 through for float fields."""
    if isinstance(v, bool) or isinstance(v, str):
        raise ValueError("must be a number")
    return v
Protocol = Literal[
    "vless", "reality", "vmess", "trojan", "ss", "hysteria2", "wireguard", "openvpn",
    "l2tp", "cisco", "socks5",
]
# Inbounds only exist for relay-style protocols with per-port endpoints.
# Single-endpoint protocols (WireGuard/OpenVPN/L2TP/Cisco/SOCKS5) are
# served from global server settings and reject inbound assignment.
InboundProtocol = Literal[
    "vless", "reality", "vmess", "trojan", "ss", "hysteria2",
]
HOST_RE = r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\z"
HOST_CORE = r"[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?"
SNI_RE = r"^[a-zA-Z0-9.,\- ]{0,300}\z"


class LoginIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class UserCreateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(pattern=USERNAME_RE)
    protocols: List[Protocol] = Field(min_length=1, max_length=11)
    note: str = Field(default="", max_length=200)
    volume_gb: float = Field(ge=0.01, le=100000)
    days: StrictInt = Field(ge=1, le=3650)
    start_on_first_use: bool = False
    device_limit: Optional[StrictInt] = Field(default=None, ge=1, le=1000)

    @field_validator("volume_gb", mode="before")
    @classmethod
    def _num_volume(cls, v):
        return _reject_bool_str(v)

    @field_validator("note", mode="before")
    @classmethod
    def _strip_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


class UserPatchIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    is_active: Optional[bool] = None
    extend_days: Optional[StrictInt] = Field(default=None, ge=1, le=3650)
    # `days` is the create-time name; a renewal bot that reuses its create
    # payload would otherwise get a silent no-op.
    days: Optional[StrictInt] = Field(default=None, ge=1, le=3650)
    add_volume_gb: Optional[float] = Field(default=None, ge=0.01, le=100000)
    add_used_gb: Optional[float] = Field(default=None, ge=-1000000, le=1000000)
    set_note: Optional[str] = Field(default=None, max_length=200)
    set_volume_gb: Optional[float] = Field(default=None, ge=0.01, le=100000)
    set_expires_at: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}\z")
    set_device_limit: Optional[StrictInt] = Field(default=None, ge=-1, le=1000)
    reset_used: bool = False
    # Absolute aliases. PATCH is "set this field", so the plain field names are
    # what an integrator reaches for first - and until now they were silently
    # dropped (200 with no effect), which for `used_gb` means a bot that thinks
    # it capped a customer leaves them uncapped. Equivalent to the set_*
    # variants; sending both forms of the same field is a 422.
    used_gb: Optional[float] = Field(default=None, ge=0, le=1000000)
    volume_gb: Optional[float] = Field(default=None, ge=0.01, le=100000)
    expires_at: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}\z")
    note: Optional[str] = Field(default=None, max_length=200)
    device_limit: Optional[StrictInt] = Field(default=None, ge=-1, le=1000)

    @field_validator(
        "add_volume_gb", "add_used_gb", "set_volume_gb", "used_gb", "volume_gb", mode="before"
    )
    @classmethod
    def _num_patch(cls, v):
        return _reject_bool_str(v) if v is not None else v

    @field_validator("set_note", "note", mode="before")
    @classmethod
    def _strip_set_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v

    @model_validator(mode="after")
    def _no_duplicate_intent(self):
        dupes = [
            absolute
            for absolute, prefixed in (
                ("used_gb", "add_used_gb"),
                ("volume_gb", "set_volume_gb"),
                ("volume_gb", "add_volume_gb"),
                ("expires_at", "set_expires_at"),
                ("note", "set_note"),
                ("device_limit", "set_device_limit"),
                ("days", "extend_days"),
            )
            if getattr(self, absolute) is not None and getattr(self, prefixed) is not None
        ]
        if dupes:
            raise ValueError(
                "send either the absolute field or its add/set variant, not both: "
                + ", ".join(sorted(set(dupes)))
            )
        return self

    def touches_anything(self) -> bool:
        """False when nothing in the request maps to a real operation.

        A patch made only of unknown keys used to return 200 and change
        nothing, so a caller (or a typo) could believe a quota was applied.
        """
        return any(
            getattr(self, f) is not None
            for f in (
                "is_active", "extend_days", "days", "add_volume_gb", "add_used_gb",
                "set_note", "set_volume_gb", "set_expires_at", "set_device_limit",
                "used_gb", "volume_gb", "expires_at", "note", "device_limit",
            )
        ) or self.reset_used


class UserResetIn(BaseModel):
    """Developer reset: one call zeroes usage and/or rotates token+secrets.

    At least one flag must be true, otherwise there is nothing to do (400).
    Bots use it for renew/top-up flows without juggling two endpoints.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    reset_usage: bool = True
    reset_token: bool = False


class TelegramSettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    bot_token: str = Field(default="", max_length=120, pattern=r"^(?:|\d+:[A-Za-z0-9_-]{1,100})\z")
    chat_id: str = Field(default="", max_length=40, pattern=r"^(?:|@?[a-zA-Z0-9_]{4,64}|[-0-9]{3,25})\z")


class TelegramTestIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    message: str = Field(default="Zefira test notification \u2713", max_length=200)


class ChangePasswordIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


HEX_COLOR_RE = r"^(?:|#[0-9a-fA-F]{6})\z"
BRAND_RE = r"^(?:|[a-zA-Z0-9 _-]{1,24})\z"


class AppearanceIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    theme_accent: str = Field(default="", max_length=7, pattern=HEX_COLOR_RE)
    theme_bg: str = Field(default="", max_length=7, pattern=HEX_COLOR_RE)
    theme_card: str = Field(default="", max_length=7, pattern=HEX_COLOR_RE)
    theme_text: str = Field(default="", max_length=7, pattern=HEX_COLOR_RE)
    theme_muted: str = Field(default="", max_length=7, pattern=HEX_COLOR_RE)
    brand_name: str = Field(default="", max_length=24, pattern=BRAND_RE)
    dash_note: str = Field(default="", max_length=300)
    menu_layout: str = Field(default="", max_length=2000)
    dash_layout: str = Field(default="", max_length=2000)

    @field_validator("dash_note", mode="before")
    @classmethod
    def _strip_dash_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


AI_PROVIDERS = ("groq", "openai", "anthropic", "gemini")
AI_URL_RE = r"^(?:|https?://[^/\s]+(:[0-9]{1,5})?(/.*)?)\z"
AI_MODEL_RE = r"^[A-Za-z0-9_.\-/:]{1,100}\z"


class AiMsgIn(BaseModel):
    role: Literal["user", "assistant"]
    # 4000 to match the server's own reply cap: a long assistant reply
    # stored in history must not 422 the next turn.
    content: str = Field(min_length=1, max_length=4000)


class AiChatIn(BaseModel):
    messages: List[AiMsgIn] = Field(min_length=1, max_length=12)


class AiSettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    enabled: bool = False
    provider: Literal["groq", "openai", "anthropic", "gemini"] = "groq"
    base_url: str = Field(default="", max_length=300, pattern=AI_URL_RE)
    model: str = Field(default="", max_length=100, pattern=r"^(?:|[A-Za-z0-9_.\-/:]{1,100})\z")
    api_key: str = Field(default="", max_length=500)
    extra: str = Field(default="", max_length=500)

    @field_validator("extra", mode="before")
    @classmethod
    def _strip_extra(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v

    @field_validator("base_url", mode="after")
    @classmethod
    def _reject_url_userinfo(cls, v):
        # SSRF hardening at the schema layer: reject userinfo
        # (http://user:pass@host) which urllib would otherwise honor,
        # plus explicit cloud-metadata targets. Deeper checks
        # (DNS-resolved IP filtering, no-redirect fetch) live in main.py.
        if not v:
            return v
        try:
            from urllib.parse import urlparse as _up

            p = _up(v)
            if p.username or p.password or "@" in (p.netloc or ""):
                raise ValueError("userinfo not allowed in base URL")
            host = (p.hostname or "").lower()
            if host in (
                "metadata.google.internal", "metadata.google",
                "instance-data", "instance-data-compute",
            ):
                raise ValueError("metadata host blocked")
            if host in ("0.0.0.0", "::", "[::]"):
                raise ValueError("invalid host")
        except ValueError:
            raise
        except Exception:
            pass
        return v


class SettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    domain: str = Field(default="", max_length=253, pattern=r"^(?:[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?)?\z")
    sub_port: StrictInt = Field(ge=1, le=65535)
    hy2_port: StrictInt = Field(ge=1, le=65535)
    wg_port: StrictInt = Field(ge=1, le=65535)
    wg_pub: str = Field(default="", max_length=200)
    dns: str = Field(default="1.1.1.1", max_length=100, pattern=HOST_RE)
    ovpn_port: StrictInt = Field(ge=1, le=65535)
    ovpn_proto: Literal["udp", "tcp"] = "udp"
    l2tp_port: StrictInt = Field(ge=1, le=65535, default=1701)
    cisco_port: StrictInt = Field(ge=1, le=65535, default=443)
    socks5_port: StrictInt = Field(ge=1, le=65535, default=1080)
    reality_port: StrictInt = Field(ge=1, le=65535, default=443)
    reality_sni: str = Field(
        default="www.yahoo.com,www.samsung.com,www.microsoft.com",
        max_length=300,
        pattern=SNI_RE,
    )
    obfuscated_host: str = Field(default="", max_length=253, pattern=r"^(?:" + HOST_CORE + r")?\z")
    per_user_subdomain: bool = False
    cdn_enabled: bool = False
    cdn_sni: str = Field(default="", max_length=253, pattern=r"^(?:" + HOST_CORE + r")?\z")
    block_direct_ip: bool = False


class SslIssueIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    domain: str = Field(min_length=3, max_length=253, pattern=HOST_RE)
    subdomain: str = Field(default="", max_length=253, pattern=r"^(?:" + HOST_CORE + r")?\z")
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+\z")


class ApiTokenCreateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9 _\-]+\z")
    scopes: Literal["full", "bot"] = "full"


class TemplateCreateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9 _\-]+\z")
    protocols: List[Protocol] = Field(min_length=1, max_length=11)
    volume_gb: float = Field(ge=0.01, le=100000)
    days: StrictInt = Field(ge=1, le=3650)
    start_on_first_use: bool = False
    device_limit: Optional[StrictInt] = Field(default=None, ge=1, le=1000)

    @field_validator("volume_gb", mode="before")
    @classmethod
    def _num_tvolume(cls, v):
        return _reject_bool_str(v)


class TunnelSettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    public_url: str = Field(
        default="",
        max_length=253,
        pattern=r"^(?:|https?://" + HOST_CORE + r"(:[0-9]{1,5})?)\z",
    )
    trusted_proxies: str = Field(default="", max_length=500)


class BlockedSiteIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    domain: str = Field(min_length=1, max_length=253, pattern=HOST_RE)
    enabled: bool = True


class BlockToggleIn(BaseModel):
    porn_enabled: bool = False


HOST_PORT_PAIRS_RE = r"^(?:|[0-9]{1,5}:[0-9]{1,5}(\s*,\s*[0-9]{1,5}:[0-9]{1,5})*)\z"
Transport = Literal[
    "tcp", "tcp-mux", "tcp-stealth", "tcp-pck", "udp", "kcp", "quic",
    "ws", "ws-mux", "wss", "wss-mux", "icmp", "ip-spoof",
]


class TunnelNodeIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9 _\-]+\z")
    transport: Transport = "tcp"
    iran_ip: str = Field(min_length=3, max_length=253, pattern=r"^" + HOST_CORE + r"\z")
    kharej_ip: str = Field(min_length=3, max_length=253, pattern=r"^" + HOST_CORE + r"\z")
    tunnel_port: StrictInt = Field(ge=1, le=65535)
    forwarded_ports: str = Field(default="", max_length=200, pattern=HOST_PORT_PAIRS_RE)
    udp_forward: bool = False

    @field_validator("forwarded_ports", mode="after")
    @classmethod
    def _check_ports(cls, v: str) -> str:
        # Range check as a real validator (not __init__): a ValueError here
        # becomes a 422 with the offending pair, not a 500. The regex allows
        # [0-9]{1,5}, so 99999:1 would otherwise slip through.
        if not v:
            return v
        seen = set()
        for pair in v.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if ":" not in pair:
                raise ValueError("forwarded_ports must be like 443:8000")
            a, b = pair.split(":", 1)
            if not (a.isdigit() and b.isdigit() and 1 <= int(a) <= 65535 and 1 <= int(b) <= 65535):
                raise ValueError(f"port out of range in {pair!r}")
            if a in seen:
                raise ValueError(f"duplicate Iran port in {pair!r}")
            seen.add(a)
        return v


class InboundIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9_\-]+\z")
    protocol: InboundProtocol
    port: StrictInt = Field(ge=1, le=65535)
    host: str = Field(default="", max_length=253, pattern=r"^(?:" + HOST_CORE + r")?\z")
    enabled: bool = True
    node_id: Optional[StrictInt] = Field(default=None, ge=1)


class InboundPatchIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    enabled: Optional[bool] = None
    port: Optional[StrictInt] = Field(default=None, ge=1, le=65535)
    host: Optional[str] = Field(default=None, max_length=253, pattern=r"^(?:" + HOST_CORE + r")?\z")
    node_id: Optional[StrictInt] = Field(default=None, ge=1)


class ServerNodeIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9 _\-]+\z")
    address: str = Field(min_length=3, max_length=253, pattern=r"^" + HOST_CORE + r"\z")
    check_port: StrictInt = Field(default=443, ge=1, le=65535)
    note: str = Field(default="", max_length=200)

    @field_validator("note", mode="before")
    @classmethod
    def _strip_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


class ServerNodePatchIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    enabled: Optional[bool] = None
    address: Optional[str] = Field(default=None, min_length=3, max_length=253, pattern=r"^" + HOST_CORE + r"\z")
    check_port: Optional[StrictInt] = Field(default=None, ge=1, le=65535)
    note: Optional[str] = Field(default=None, max_length=200)

    @field_validator("note", mode="before")
    @classmethod
    def _strip_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


class RestoreUserIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(pattern=USERNAME_RE)
    protocol: Protocol = "vless"
    protocols: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=200)
    volume_gb: float = Field(ge=0, le=100000)
    used_gb: float = Field(default=0, ge=0, le=1000000)
    token: str = Field(pattern=r"^[a-f0-9]{32}\z")
    secret_data: str = Field(default="", max_length=40000)
    is_active: bool = True
    device_limit: Optional[StrictInt] = Field(default=None, ge=1, le=1000)
    start_on_first_use: bool = False
    duration_days: Optional[StrictInt] = Field(default=None, ge=1, le=3650)
    created_at: Optional[str] = None
    expires_at: str

    @field_validator("volume_gb", "used_gb", mode="before")
    @classmethod
    def _num_restore(cls, v):
        return _reject_bool_str(v)

    @field_validator("note", mode="before")
    @classmethod
    def _strip_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


class RestoreAdminIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(pattern=USERNAME_RE)
    password_hash: str = Field(min_length=10, max_length=256)
    token_version: StrictInt = Field(default=0, ge=0, le=999999999)


class RestoreConfirmIn(BaseModel):
    password_confirm: str = Field(min_length=8, max_length=128)


class BackupIn(RestoreConfirmIn):
    # encrypt=True returns a Fernet-encrypted blob (key derived from
    # password_confirm via scrypt) instead of plaintext JSON. Use it when
    # storing backups off-server: the file then reveals nothing without
    # the admin password that created it.
    encrypt: bool = False


class RestoreEncryptedIn(RestoreConfirmIn):
    # Encrypted backup produced by POST /api/backup {"encrypt": true}.
    salt: str = Field(min_length=16, max_length=64, pattern=r"^[a-f0-9]+\z")
    payload: str = Field(min_length=10, max_length=100000000)
    # Password that encrypted the backup. Defaults to password_confirm
    # (common case: same admin password). Provide separately when the
    # backup was made under an older password.
    backup_password: str = Field(default="", max_length=128)


class RestoreIn(RestoreConfirmIn):
    zefira_backup: Literal[True]
    users: List[RestoreUserIn] = Field(max_length=10000)
    admins: Optional[List[RestoreAdminIn]] = None
    settings: Optional[dict] = None
    templates: Optional[List[dict]] = Field(default=None, max_length=500)
    blocked_sites: Optional[List[dict]] = Field(default=None, max_length=600)
    api_tokens: Optional[List[dict]] = Field(default=None, max_length=100)
    inbounds: Optional[List[dict]] = Field(default=None, max_length=200)
    server_nodes: Optional[List[dict]] = Field(default=None, max_length=100)
    tunnel_nodes: Optional[List[dict]] = Field(default=None, max_length=100)
