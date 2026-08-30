from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_RE = r"^[a-zA-Z0-9_]{3,32}$"
Protocol = Literal[
    "vless", "reality", "vmess", "trojan", "ss", "hysteria2", "wireguard", "openvpn"
]
HOST_RE = r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$"
HOST_CORE = r"[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?"
SNI_RE = r"^[a-zA-Z0-9.,\- ]{0,300}$"


class LoginIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    code: Optional[str] = Field(default=None, pattern=r"^[0-9]{6}$")


class UserCreateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(pattern=USERNAME_RE)
    protocols: List[Protocol] = Field(min_length=1, max_length=8)
    note: str = Field(default="", max_length=200)
    volume_gb: float = Field(gt=0, le=100000)
    days: int = Field(ge=1, le=3650)
    start_on_first_use: bool = False

    @field_validator("note", mode="before")
    @classmethod
    def _strip_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


class UserPatchIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    is_active: Optional[bool] = None
    extend_days: Optional[int] = Field(default=None, ge=1, le=3650)
    add_volume_gb: Optional[float] = Field(default=None, ge=0.01, le=100000)
    add_used_gb: Optional[float] = Field(default=None, ge=-1000000, le=1000000)
    set_note: Optional[str] = Field(default=None, max_length=200)
    set_volume_gb: Optional[float] = Field(default=None, gt=0, le=100000)
    set_expires_at: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
    reset_used: bool = False

    @field_validator("set_note", mode="before")
    @classmethod
    def _strip_set_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


class TelegramSettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    bot_token: str = Field(default="", max_length=120)
    chat_id: str = Field(default="", max_length=40, pattern=r"^$|^@?[a-zA-Z0-9_]{4,64}$|^[-0-9]{3,25}$")


class TelegramTestIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    message: str = Field(default="Zefira test notification \u2713", max_length=200)


class ChangePasswordIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class TotpCodeIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    code: str = Field(pattern=r"^[0-9]{6}$")


class SettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    domain: str = Field(default="", max_length=253, pattern=r"^$|" + HOST_RE)
    sub_port: int = Field(ge=1, le=65535)
    hy2_port: int = Field(ge=1, le=65535)
    wg_port: int = Field(ge=1, le=65535)
    wg_pub: str = Field(default="", max_length=200)
    dns: str = Field(default="1.1.1.1", max_length=100, pattern=HOST_RE)
    ovpn_port: int = Field(ge=1, le=65535)
    ovpn_proto: Literal["udp", "tcp"] = "udp"
    reality_port: int = Field(ge=1, le=65535, default=443)
    reality_sni: str = Field(
        default="www.yahoo.com,www.samsung.com,www.microsoft.com",
        max_length=300,
        pattern=SNI_RE,
    )
    obfuscated_host: str = Field(default="", max_length=253, pattern=r"^(?:$|" + HOST_CORE + r")$")
    per_user_subdomain: bool = False
    cdn_enabled: bool = False
    cdn_sni: str = Field(default="", max_length=253, pattern=r"^(?:$|" + HOST_CORE + r")$")
    block_direct_ip: bool = False


class TemplateCreateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=40)
    protocols: List[Protocol] = Field(min_length=1, max_length=8)
    volume_gb: float = Field(gt=0, le=100000)
    days: int = Field(ge=1, le=3650)
    start_on_first_use: bool = False


class TunnelSettingsIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    public_url: str = Field(
        default="",
        max_length=253,
        pattern=r"^$|^https?://" + HOST_CORE + r"(:[0-9]{1,5})?$",
    )
    trusted_proxies: str = Field(default="", max_length=500)


class BlockedSiteIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    domain: str = Field(min_length=1, max_length=253, pattern=HOST_RE)
    enabled: bool = True


class BlockToggleIn(BaseModel):
    porn_enabled: bool = False


HOST_PORT_PAIRS_RE = r"^$|^[0-9]{1,5}:[0-9]{1,5}(\s*,\s*[0-9]{1,5}:[0-9]{1,5})*$"
Transport = Literal[
    "tcp", "tcp-mux", "tcp-stealth", "tcp-pck", "kcp", "quic",
    "ws", "ws-mux", "wss", "wss-mux", "icmp", "ip-spoof",
]


class TunnelNodeIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9 _\-]+$")
    transport: Transport = "tcp"
    iran_ip: str = Field(min_length=3, max_length=253, pattern=r"^" + HOST_CORE + r"$")
    kharej_ip: str = Field(min_length=3, max_length=253, pattern=r"^" + HOST_CORE + r"$")
    tunnel_port: int = Field(ge=1, le=65535)
    forwarded_ports: str = Field(default="", max_length=200, pattern=HOST_PORT_PAIRS_RE)
    udp_forward: bool = False

    @classmethod
    def _check_ports(cls, v: str) -> str:
        if not v:
            return v
        for pair in v.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if ":" not in pair:
                raise ValueError("forwarded_ports must be like 443:8000")
            a, b = pair.split(":", 1)
            if not (a.isdigit() and b.isdigit() and 1 <= int(a) <= 65535 and 1 <= int(b) <= 65535):
                raise ValueError(f"port out of range in {pair!r}")
        return v

    def __init__(self, **data):
        if "forwarded_ports" in data and isinstance(data["forwarded_ports"], str):
            data["forwarded_ports"] = self._check_ports(data["forwarded_ports"])
        super().__init__(**data)


class InboundIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9_\-]+$")
    protocol: Protocol
    port: int = Field(ge=1, le=65535)
    host: str = Field(default="", max_length=253, pattern=r"^(?:$|" + HOST_CORE + r")$")
    enabled: bool = True


class InboundPatchIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    enabled: Optional[bool] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    host: Optional[str] = Field(default=None, max_length=253, pattern=r"^(?:$|" + HOST_CORE + r")$")


class RestoreUserIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(pattern=USERNAME_RE)
    protocol: Protocol = "vless"
    protocols: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=200)
    volume_gb: float = Field(ge=0, le=100000)
    used_gb: float = Field(default=0, ge=0, le=1000000)
    token: str = Field(pattern=r"^[a-f0-9]{32}$")
    secret_data: str = Field(default="", max_length=40000)
    is_active: bool = True
    start_on_first_use: bool = False
    duration_days: Optional[int] = Field(default=None, ge=1, le=3650)
    created_at: Optional[str] = None
    expires_at: str

    @field_validator("note", mode="before")
    @classmethod
    def _strip_note(cls, v):
        if isinstance(v, str):
            return "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\r\t")
        return v


class RestoreAdminIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=64)
    password_hash: str = Field(min_length=10, max_length=256)
    token_version: int = Field(default=0, ge=0, le=999999999)
    totp_enabled: bool = False
    totp_secret: Optional[str] = None


class RestoreConfirmIn(BaseModel):
    password_confirm: str = Field(min_length=8, max_length=128)


class RestoreIn(RestoreConfirmIn):
    zefira_backup: Literal[True]
    users: List[RestoreUserIn] = Field(max_length=10000)
    admins: Optional[List[RestoreAdminIn]] = None
    settings: Optional[dict] = None
    templates: Optional[List[dict]] = None
