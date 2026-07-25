import ipaddress

import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.tsigkeyring
import dns.zone

from static_dns_helper.records import FORWARD_TYPES

QUERY_TIMEOUT = 10
TRANSFER_TIMEOUT = 60

MANAGED_TYPES = frozenset(dns.rdatatype.from_text(t) for t in FORWARD_TYPES + ("PTR",))

# Zone meta: never touched, regardless of markers or git contents.
META_TYPES = frozenset(
    dns.rdatatype.from_text(t)
    for t in ("SOA", "NS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DS", "CDS", "CDNSKEY")
)

_resolver = dns.resolver.Resolver()
_resolver.cache = dns.resolver.Cache()


def resolve_nameserver(nameserver):
    try:
        ipaddress.ip_address(nameserver)
        return nameserver
    except ValueError:
        pass

    # prefer IPv6; the resolver cache honors record TTLs
    try:
        return _resolver.resolve(nameserver, "AAAA")[0].address
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return _resolver.resolve(nameserver, "A")[0].address


def fetch_live(zone_name, settings):
    xfr = dns.query.xfr(
        resolve_nameserver(settings.nameserver),
        zone_name,
        port=settings.port,
        keyring=dns.tsigkeyring.from_text(settings.keyring),
        keyalgorithm="hmac-sha256",
        timeout=QUERY_TIMEOUT,
        lifetime=TRANSFER_TIMEOUT,
        relativize=False,
    )
    return dns.zone.from_xfr(xfr, relativize=False)


def excluded_names(zone_obj, marker_prefix):
    """Names bearing a TXT whose value starts with the marker prefix.

    A marked name belongs to a dynamic writer: every type at it is off-limits.
    """
    prefix = marker_prefix.encode("utf-8")
    excluded = set()
    for name in zone_obj.nodes:
        rds = zone_obj.get_rdataset(name, dns.rdatatype.TXT)
        if rds and any(b"".join(rd.strings).startswith(prefix) for rd in rds):
            excluded.add(name)
    return excluded


def managed_rrsets(zone_obj, excluded):
    """Live RRsets this tool owns: managed types at unmarked names, meta hard-skipped."""
    managed = {}
    for name, node in zone_obj.nodes.items():
        if name in excluded:
            continue
        for rds in node.rdatasets:
            if rds.rdclass != dns.rdataclass.IN:
                continue
            if rds.rdtype in META_TYPES or rds.rdtype not in MANAGED_TYPES:
                continue
            managed[(name, rds.rdtype)] = rds
    return managed
