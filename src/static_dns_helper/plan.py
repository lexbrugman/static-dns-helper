from dataclasses import dataclass

import dns.rdatatype


@dataclass(frozen=True)
class Replace:
    zone: object
    name: object
    rdtype: int
    ttl: int
    rdatas: frozenset


@dataclass(frozen=True)
class Delete:
    zone: object
    name: object
    rdtype: int
    rdatas: frozenset  # the exact records observed via AXFR; the delete guard


_ADDRESS_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


def diff_zone(zone_name, desired, managed):
    """Diff desired vs managed RRsets for one zone into an ordered action list.

    Deletes come first: converting a name between CNAME and other types only
    applies cleanly when the old RRset is removed before the new one is added
    (RFC2136 servers silently ignore CNAME/non-CNAME collisions). Within the
    adds, A/AAAA come before the types that may reference them: BIND's
    check-integrity refuses an MX/SRV whose in-zone target has no address
    records yet. Deletes run in the mirrored order.
    """
    deletes = []
    replaces = []
    for key in sorted(set(desired) | set(managed), key=lambda k: (k[0], k[1])):
        name, rdtype = key
        d = desired.get(key)
        m = managed.get(key)
        if d is None:
            deletes.append(Delete(zone=zone_name, name=name, rdtype=rdtype, rdatas=frozenset(m)))
        elif m is None or frozenset(m) != d.rdatas or m.ttl != d.ttl:
            replaces.append(Replace(zone=zone_name, name=name, rdtype=rdtype, ttl=d.ttl, rdatas=d.rdatas))
    deletes.sort(key=lambda a: a.rdtype in _ADDRESS_TYPES)
    replaces.sort(key=lambda a: a.rdtype not in _ADDRESS_TYPES)
    return deletes + replaces


def describe(action):
    kind = "DELETE" if isinstance(action, Delete) else "REPLACE"
    values = " ".join(sorted(rd.to_text() for rd in action.rdatas))
    ttl = f" ttl={action.ttl}" if isinstance(action, Replace) else ""
    return f"{kind} {action.zone} {action.name} {dns.rdatatype.to_text(action.rdtype)}{ttl} [{values}]"
