from dataclasses import dataclass


@dataclass
class User:
    name: str
    ip: str
    pvkey: str
    pskey: str
    pbkey: str
    last_handshake: str | None = None
    groups: list[str] | None = None


@dataclass
class Service:
    name: str
    directory: str
    ip: str
    pvkey: str
    pskey: str
    pbkey: str
    ports: dict[str]
    last_handshake: str | None = None
    groups: list[str] | None = None


@dataclass
class Permission:
    user_name: str
    service_name: str
    allowed: bool
