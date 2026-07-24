import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype

from static_dns_helper.plan import Delete, Replace, describe, diff_zone
from static_dns_helper.records import RRset

ZONE = dns.name.from_text("example.internal")


def name(text):
    return dns.name.from_text(f"{text}.example.internal")


def a_rdata(address):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, address)


def desired_a(*addresses, ttl=3600):
    return RRset(ttl=ttl, rdatas=frozenset(a_rdata(a) for a in addresses))


def live_a(*addresses, ttl=3600):
    return dns.rdataset.from_rdata_list(ttl, [a_rdata(a) for a in addresses])


class TestDiff:
    def test_missing_rrset_added(self):
        key = (name("nas"), dns.rdatatype.A)
        plan = diff_zone(ZONE, {key: desired_a("10.42.1.10")}, {})
        assert plan == [
            Replace(zone=ZONE, name=key[0], rdtype=dns.rdatatype.A, ttl=3600, rdatas=frozenset({a_rdata("10.42.1.10")}))
        ]

    def test_identical_rrset_is_noop(self):
        key = (name("nas"), dns.rdatatype.A)
        plan = diff_zone(ZONE, {key: desired_a("10.42.1.10")}, {key: live_a("10.42.1.10")})
        assert plan == []

    def test_value_and_ttl_drift_converged(self):
        key = (name("nas"), dns.rdatatype.A)
        assert diff_zone(ZONE, {key: desired_a("10.42.1.10", "10.42.1.11")}, {key: live_a("10.42.1.10")}) != []
        assert diff_zone(ZONE, {key: desired_a("10.42.1.10", ttl=60)}, {key: live_a("10.42.1.10", ttl=3600)}) != []
        (action,) = diff_zone(ZONE, {key: desired_a("10.42.1.10", ttl=60)}, {key: live_a("10.42.1.10")})
        assert isinstance(action, Replace)
        assert action.ttl == 60

    def test_unmanaged_extra_rrset_purged_with_observed_values(self):
        key = (name("stray"), dns.rdatatype.A)
        (action,) = diff_zone(ZONE, {}, {key: live_a("10.42.1.9", "10.42.1.8")})
        assert action == Delete(
            zone=ZONE, name=key[0], rdtype=dns.rdatatype.A, rdatas=frozenset({a_rdata("10.42.1.9"), a_rdata("10.42.1.8")})
        )

    def test_deletes_ordered_before_replaces(self):
        # www flips from A to CNAME: the A delete must precede the CNAME add
        www = name("www")
        cname = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, "nas.example.internal.")
        plan = diff_zone(
            ZONE,
            {(www, dns.rdatatype.CNAME): RRset(ttl=3600, rdatas=frozenset({cname}))},
            {(www, dns.rdatatype.A): live_a("10.42.1.10")},
        )
        assert [type(action) for action in plan] == [Delete, Replace]

    def test_address_records_added_before_referencing_types(self):
        # BIND check-integrity refuses an MX whose in-zone target has no
        # address records yet, so A/AAAA replaces must land first.
        mx = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, "10 nas.example.internal.")
        plan = diff_zone(
            ZONE,
            {
                (name("mail"), dns.rdatatype.MX): RRset(ttl=3600, rdatas=frozenset({mx})),
                (name("nas"), dns.rdatatype.A): desired_a("10.42.1.10"),
            },
            {},
        )
        assert [action.rdtype for action in plan] == [dns.rdatatype.A, dns.rdatatype.MX]

    def test_case_insensitive_value_comparison(self):
        key = (name("www"), dns.rdatatype.CNAME)
        upper = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, "NAS.Example.Internal.")
        lower = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, "nas.example.internal.")
        plan = diff_zone(
            ZONE,
            {key: RRset(ttl=3600, rdatas=frozenset({lower}))},
            {key: dns.rdataset.from_rdata_list(3600, [upper])},
        )
        assert plan == []


def test_describe_mentions_zone_name_type_and_values():
    key = (name("nas"), dns.rdatatype.A)
    (action,) = diff_zone(ZONE, {key: desired_a("10.42.1.10")}, {})
    text = describe(action)
    assert "REPLACE" in text
    assert "example.internal" in text
    assert "A" in text
    assert "10.42.1.10" in text
