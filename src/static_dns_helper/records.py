import ipaddress
from dataclasses import dataclass

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import yaml

FORWARD_TYPES = ("A", "AAAA", "CNAME", "MX", "SRV", "TXT")
_ALLOWED_KEYS = {"name", "type", "value", "ttl", "ptr"}
_TXT_CHUNK = 255


class RecordsError(Exception):
    """The records file is missing, unreadable, or invalid; fail closed."""


@dataclass(frozen=True)
class RRset:
    ttl: int
    rdatas: frozenset


def quote_txt(value):
    chunks = [value[i : i + _TXT_CHUNK] for i in range(0, len(value), _TXT_CHUNK)] or [""]
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)


def load_desired(path, settings):
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except OSError as e:
        raise RecordsError(f"cannot read records file {path}: {e}") from e
    except yaml.YAMLError as e:
        raise RecordsError(f"records file {path} is not valid YAML: {e}") from e
    return build_desired(raw, settings)


def build_desired(raw, settings):
    """Turn the parsed YAML document into per-zone desired RRsets.

    Returns (desired, record_count) where desired maps each configured zone
    (forward and every reverse zone) to {(owner_name, rdtype): RRset}.
    Raises RecordsError listing every validation problem found.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get("records"), list):
        raise RecordsError("records file must be a mapping with a 'records' list")

    desired = {zone: {} for zone in (settings.zone, *settings.reverse_zones)}
    errors = []
    seen_values = set()  # (owner, rdtype, rdata) for duplicate detection
    ptr_owners = {}  # derived reverse owner -> source address

    for index, entry in enumerate(raw["records"]):
        where = f"records[{index}]"
        problems = _entry_problems(entry, where)
        if problems:
            errors.extend(problems)
            continue

        rdtype_text = entry["type"].upper()
        ttl = entry.get("ttl", settings.ttl)
        try:
            owner = _owner_name(entry["name"], settings.zone)
        except ValueError as e:
            errors.append(f"{where}: {e}")
            continue

        value = str(entry["value"])
        try:
            rd = _parse_value(rdtype_text, value, settings.zone)
        except ValueError as e:
            errors.append(f"{where}: {e}")
            continue

        key = (owner, rd.rdtype)
        if (owner, rd.rdtype, rd) in seen_values:
            errors.append(f"{where}: duplicate record {entry['name']} {rdtype_text} {value}")
            continue
        seen_values.add((owner, rd.rdtype, rd))

        if not _merge(desired[settings.zone], key, ttl, rd):
            errors.append(f"{where}: conflicting ttl for rrset {entry['name']} {rdtype_text}")
            continue

        if rdtype_text in ("A", "AAAA") and entry.get("ptr", True):
            try:
                _derive_ptr(desired, ptr_owners, owner, value, ttl, settings, where)
            except ValueError as e:
                errors.append(f"{where}: {e}")

    errors.extend(_rrset_problems(desired[settings.zone], settings.zone))

    if errors:
        raise RecordsError("invalid records file:\n" + "\n".join(errors))
    return desired, len(raw["records"])


def _entry_problems(entry, where):
    if not isinstance(entry, dict):
        return [f"{where}: each record must be a mapping"]
    problems = []
    unknown = set(entry) - _ALLOWED_KEYS
    if unknown:
        problems.append(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
    for required in ("name", "type", "value"):
        if required not in entry:
            problems.append(f"{where}: missing required key '{required}'")
    if problems:
        return problems
    if not isinstance(entry["name"], str) or not entry["name"]:
        problems.append(f"{where}: 'name' must be a non-empty string")
    if not isinstance(entry["type"], str) or entry["type"].upper() not in FORWARD_TYPES:
        problems.append(f"{where}: 'type' must be one of {', '.join(FORWARD_TYPES)}")
    if not isinstance(entry["value"], (str, int)) or isinstance(entry["value"], bool):
        problems.append(f"{where}: 'value' must be a string")
    if "ttl" in entry and (not isinstance(entry["ttl"], int) or isinstance(entry["ttl"], bool) or entry["ttl"] <= 0):
        problems.append(f"{where}: 'ttl' must be a positive integer")
    if "ptr" in entry:
        if not isinstance(entry["ptr"], bool):
            problems.append(f"{where}: 'ptr' must be a boolean")
        elif isinstance(entry["type"], str) and entry["type"].upper() not in ("A", "AAAA"):
            problems.append(f"{where}: 'ptr' only applies to A/AAAA records")
    return problems


def _owner_name(name, zone):
    if name.endswith("."):
        raise ValueError(f"name {name!r} must be relative to the zone (no trailing dot)")
    try:
        if name == "@":
            return zone
        return dns.name.from_text(name, origin=zone)
    except dns.exception.DNSException as e:
        raise ValueError(f"name {name!r} is not a valid DNS name: {e}") from e


def _parse_value(rdtype_text, value, zone):
    if rdtype_text == "A":
        _check_address(value, ipaddress.IPv4Address, "IPv4")
    elif rdtype_text == "AAAA":
        _check_address(value, ipaddress.IPv6Address, "IPv6")
    text = quote_txt(value) if rdtype_text == "TXT" else value
    try:
        return dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.from_text(rdtype_text), text, origin=zone, relativize=False
        )
    except (dns.exception.DNSException, ValueError) as e:
        raise ValueError(f"invalid {rdtype_text} value {value!r}: {e}") from e


def _check_address(value, address_class, family):
    try:
        address_class(value)
    except ValueError as e:
        raise ValueError(f"{value!r} is not a valid {family} address") from e


def _merge(zone_desired, key, ttl, rd):
    existing = zone_desired.get(key)
    if existing is None:
        zone_desired[key] = RRset(ttl=ttl, rdatas=frozenset({rd}))
        return True
    if existing.ttl != ttl:
        return False
    zone_desired[key] = RRset(ttl=existing.ttl, rdatas=existing.rdatas | {rd})
    return True


def _derive_ptr(desired, ptr_owners, owner, address, ttl, settings, where):
    reverse_owner = dns.name.from_text(ipaddress.ip_address(address).reverse_pointer)
    matches = [zone for zone in settings.reverse_zones if reverse_owner.is_subdomain(zone)]
    if not matches:
        raise ValueError(f"reverse name for {address} matches no REVERSE_ZONES entry")
    reverse_zone = max(matches, key=len)

    previous = ptr_owners.get(reverse_owner)
    if previous is not None:
        raise ValueError(
            f"address {address} already has a PTR (from {previous}); mark extra records with ptr: false"
        )
    ptr_owners[reverse_owner] = where

    rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR, owner.to_text(), relativize=False)
    desired[reverse_zone][(reverse_owner, dns.rdatatype.PTR)] = RRset(ttl=ttl, rdatas=frozenset({rd}))


def _rrset_problems(forward_desired, zone):
    problems = []
    owners_with_cname = {owner for owner, rdtype in forward_desired if rdtype == dns.rdatatype.CNAME}
    for owner in sorted(owners_with_cname):
        types_at_owner = {rdtype for o, rdtype in forward_desired if o == owner}
        cname = forward_desired[(owner, dns.rdatatype.CNAME)]
        if len(types_at_owner) > 1 or len(cname.rdatas) > 1:
            problems.append(f"{owner.relativize(zone)}: CNAME must not coexist with any other record")
    return problems
