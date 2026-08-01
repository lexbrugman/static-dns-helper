import dns.name
import dns.rdatatype
import dns.zone
import pytest

from static_dns_helper.zones import excluded_names, managed_rrsets

FORWARD_ZONE_TEXT = """
$ORIGIN example.internal.
$TTL 3600
@       IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
@       IN NS   ns1
@       IN DNSKEY 256 3 8 AwEAAcFcGsaxxdCOaGrU6hVLMuyXloqSy7Y4gI3T5NGKJK2vCpMTj88H
ns1     IN A    10.42.1.1
nas     IN A    10.42.1.10
nas     IN AAAA 2001:db8::10
www     IN CNAME nas
_dmarc  IN TXT  "v=DMARC1; p=none"
lease1  IN A    10.42.1.100
lease1  IN TXT  "x-dyn:2b6e1b0a"
spfhost IN A    10.42.1.20
spfhost IN TXT  "v=spf1 -all"
"""

REVERSE_ZONE_TEXT = """
$ORIGIN 1.42.10.in-addr.arpa.
$TTL 3600
@       IN SOA  ns1.example.internal. hostmaster.example.internal. 1 7200 3600 1209600 3600
@       IN NS   ns1.example.internal.
10      IN PTR  nas.example.internal.
100     IN PTR  lease1.example.internal.
100     IN TXT  "x-dyn:2b6e1b0a"
7       IN PTR  stale.example.internal.
"""


def zone_from(text, origin):
    return dns.zone.from_text(text, origin=origin, relativize=False)


def name(text):
    return dns.name.from_text(text)


def managed_of(zone):
    return managed_rrsets(zone, excluded_names(zone, "x-dyn:"))


@pytest.fixture
def forward_zone():
    return zone_from(FORWARD_ZONE_TEXT, "example.internal")


@pytest.fixture
def reverse_zone():
    return zone_from(REVERSE_ZONE_TEXT, "1.42.10.in-addr.arpa")


class TestExcludedNames:
    def test_marked_name_excluded(self, forward_zone):
        assert name("lease1.example.internal") in excluded_names(forward_zone, "x-dyn:")

    def test_legitimate_txt_not_excluded(self, forward_zone):
        excluded = excluded_names(forward_zone, "x-dyn:")
        assert name("_dmarc.example.internal") not in excluded
        assert name("spfhost.example.internal") not in excluded

    def test_marker_matching_is_prefix_based(self):
        zone = zone_from(FORWARD_ZONE_TEXT.replace("x-dyn:2b6e1b0a", "seen x-dyn: mid-value"), "example.internal")
        assert name("lease1.example.internal") not in excluded_names(zone, "x-dyn:")

    def test_marked_reverse_name_excluded(self, reverse_zone):
        assert excluded_names(reverse_zone, "x-dyn:") == {name("100.1.42.10.in-addr.arpa")}


class TestManagedRRsets:
    def test_meta_types_skipped(self, forward_zone):
        managed = managed_of(forward_zone)
        types_at_apex = {rdtype for owner, rdtype in managed if owner == name("example.internal")}
        assert types_at_apex == set()  # SOA, NS, DNSKEY all skipped

    def test_marked_name_fully_skipped(self, forward_zone):
        assert not any(owner == name("lease1.example.internal") for owner, _ in managed_of(forward_zone))

    def test_unmarked_records_managed(self, forward_zone):
        assert {
            (name("nas.example.internal"), dns.rdatatype.A),
            (name("nas.example.internal"), dns.rdatatype.AAAA),
            (name("www.example.internal"), dns.rdatatype.CNAME),
            (name("_dmarc.example.internal"), dns.rdatatype.TXT),
            (name("spfhost.example.internal"), dns.rdatatype.TXT),
        } <= set(managed_of(forward_zone))

    def test_reverse_zone_managed_set(self, reverse_zone):
        assert set(managed_of(reverse_zone)) == {
            (name("10.1.42.10.in-addr.arpa"), dns.rdatatype.PTR),
            (name("7.1.42.10.in-addr.arpa"), dns.rdatatype.PTR),
        }
