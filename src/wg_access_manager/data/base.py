from dataclasses import dataclass


@dataclass
class User:
    name: str
    ip: str
    private_key: str
    preshared_key: str
    public_key: str
    last_handshake: str | None = None


@dataclass
class Service:
    name: str
    folder: str
    ip: str
    private_key: str
    preshared_key: str
    public_key: str
    ports: dict[str]
    last_handshake: str | None = None
