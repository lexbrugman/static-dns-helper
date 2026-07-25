import json
import os
from dataclasses import dataclass

import dns.name

_REVERSE_ROOTS = (
    dns.name.from_text("in-addr.arpa"),
    dns.name.from_text("ip6.arpa"),
)


def _required_env(name):
    value = os.environ.get(name)
    if value is None or value == "":
        raise RuntimeError(f"{name} is required")
    return value


def _bool_env(name, default):
    value = os.environ.get(name, "")
    if value == "":
        return default
    if value.lower() in ("1", "true", "yes"):
        return True
    if value.lower() in ("0", "false", "no"):
        return False
    raise RuntimeError(f"{name} must be a boolean (true/false)")


def _json_env(name):
    try:
        parsed = json.loads(_required_env(name))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{name} is not valid JSON: {e}") from e
    if not isinstance(parsed, dict) or not parsed:
        raise RuntimeError(f"{name} must be a non-empty JSON object of key name to secret")
    return parsed


def _zone_name(text, source):
    try:
        zone = dns.name.from_text(text)
    except Exception as e:
        raise RuntimeError(f"{source}: {text!r} is not a valid zone name: {e}") from e
    if zone == dns.name.root:
        raise RuntimeError(f"{source} must not be the root zone")
    return zone


def _reverse_zones(text):
    zones = []
    for entry in text.split(","):
        entry = entry.strip()
        if not entry:
            continue
        zone = _zone_name(entry, "REVERSE_ZONES")
        if not any(zone.is_subdomain(root) and zone != root for root in _REVERSE_ROOTS):
            raise RuntimeError(f"REVERSE_ZONES: {entry!r} is not under in-addr.arpa or ip6.arpa")
        zones.append(zone)
    if not zones:
        raise RuntimeError("REVERSE_ZONES must list at least one reverse zone")
    if len(set(zones)) != len(zones):
        raise RuntimeError("REVERSE_ZONES contains duplicates")
    return tuple(zones)


@dataclass(frozen=True)
class Settings:
    zone: dns.name.Name
    nameserver: str
    port: int
    reverse_zones: tuple
    ttl: int
    records_file: str
    marker_prefix: str
    reconcile_interval: int
    allow_empty: bool
    dry_run: bool
    heartbeat_file: str
    keyring: dict

    @classmethod
    def from_env(cls):
        return cls(
            zone=_zone_name(_required_env("ZONE"), "ZONE"),
            nameserver=_required_env("NAMESERVER"),
            port=int(os.environ.get("DNS_PORT", "53")),
            reverse_zones=_reverse_zones(_required_env("REVERSE_ZONES")),
            ttl=int(os.environ.get("TTL", "3600")),
            records_file=os.environ.get("RECORDS_FILE", "/config/records.yaml"),
            marker_prefix=os.environ.get("MARKER_PREFIX", "x-dyn:"),
            reconcile_interval=int(os.environ.get("RECONCILE_INTERVAL", "900")),
            allow_empty=_bool_env("ALLOW_EMPTY", False),
            dry_run=_bool_env("DRY_RUN", False),
            heartbeat_file=os.environ.get("HEARTBEAT_FILE", "/run/last-reconcile"),
            keyring=_json_env("KEYRING_JSON"),
        )
