import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from static_dns_helper.records import RecordsError, build_desired, quote_txt


def name(text):
    return dns.name.from_text(text)


def rdata(rdtype, text, origin=None):
    return dns.rdata.from_text(dns.rdataclass.IN, rdtype, text, origin=origin, relativize=False)


def desired_of(settings, *entries):
    desired, _ = build_desired({"records": list(entries)}, settings)
    return desired


def errors_of(settings, *entries):
    with pytest.raises(RecordsError) as excinfo:
        build_desired({"records": list(entries)}, settings)
    return str(excinfo.value)


class TestForwardParsing:
    def test_a_record_with_derived_ptr(self, settings):
        desired = desired_of(settings, {"name": "nas", "type": "A", "value": "10.42.1.10"})

        forward = desired[settings.zone][(name("nas.example.internal"), dns.rdatatype.A)]
        assert forward.rdatas == {rdata(dns.rdatatype.A, "10.42.1.10")}
        assert forward.ttl == 3600

        reverse = desired[name("1.42.10.in-addr.arpa")][
            (name("10.1.42.10.in-addr.arpa"), dns.rdatatype.PTR)
        ]
        assert reverse.rdatas == {rdata(dns.rdatatype.PTR, "nas.example.internal.")}

    def test_aaaa_record_with_derived_v6_ptr(self, settings):
        desired = desired_of(settings, {"name": "nas", "type": "AAAA", "value": "2001:db8::10"})

        reverse_zone = name("8.b.d.0.1.0.0.2.ip6.arpa")
        owner = name("0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
        reverse = desired[reverse_zone][(owner, dns.rdatatype.PTR)]
        assert reverse.rdatas == {rdata(dns.rdatatype.PTR, "nas.example.internal.")}

    def test_ptr_false_skips_derivation(self, settings):
        desired = desired_of(settings, {"name": "nas", "type": "A", "value": "10.42.1.11", "ptr": False})

        assert (name("nas.example.internal"), dns.rdatatype.A) in desired[settings.zone]
        assert desired[name("1.42.10.in-addr.arpa")] == {}
        assert desired[name("42.10.in-addr.arpa")] == {}

    def test_multi_value_rrset_merges(self, settings):
        desired = desired_of(
            settings,
            {"name": "nas", "type": "A", "value": "10.42.1.10"},
            {"name": "nas", "type": "A", "value": "10.42.1.11", "ptr": False},
        )

        forward = desired[settings.zone][(name("nas.example.internal"), dns.rdatatype.A)]
        assert forward.rdatas == {rdata(dns.rdatatype.A, "10.42.1.10"), rdata(dns.rdatatype.A, "10.42.1.11")}

    def test_relative_cname_target_expanded_against_zone(self, settings):
        desired = desired_of(settings, {"name": "www", "type": "CNAME", "value": "nas"})

        rrset = desired[settings.zone][(name("www.example.internal"), dns.rdatatype.CNAME)]
        assert rrset.rdatas == {rdata(dns.rdatatype.CNAME, "nas.example.internal.")}

    def test_mx_srv_and_apex(self, settings):
        desired = desired_of(
            settings,
            {"name": "@", "type": "MX", "value": "10 nas"},
            {"name": "_sip._tcp", "type": "SRV", "value": "10 60 5060 nas"},
        )

        mx = desired[settings.zone][(settings.zone, dns.rdatatype.MX)]
        assert mx.rdatas == {rdata(dns.rdatatype.MX, "10 nas.example.internal.")}
        assert (name("_sip._tcp.example.internal"), dns.rdatatype.SRV) in desired[settings.zone]

    def test_txt_value_kept_verbatim(self, settings):
        desired = desired_of(settings, {"name": "_dmarc", "type": "TXT", "value": "v=DMARC1; p=none"})

        rrset = desired[settings.zone][(name("_dmarc.example.internal"), dns.rdatatype.TXT)]
        (rd,) = rrset.rdatas
        assert rd.strings == (b"v=DMARC1; p=none",)

    def test_long_txt_value_chunked(self, settings):
        value = "x" * 300
        desired = desired_of(settings, {"name": "long", "type": "TXT", "value": value})

        (rd,) = desired[settings.zone][(name("long.example.internal"), dns.rdatatype.TXT)].rdatas
        assert rd.strings == (b"x" * 255, b"x" * 45)

    def test_ttl_override_and_default(self, settings):
        desired = desired_of(settings, {"name": "nas", "type": "A", "value": "10.42.1.10", "ttl": 60})

        forward = desired[settings.zone][(name("nas.example.internal"), dns.rdatatype.A)]
        assert forward.ttl == 60
        reverse = desired[name("1.42.10.in-addr.arpa")][
            (name("10.1.42.10.in-addr.arpa"), dns.rdatatype.PTR)
        ]
        assert reverse.ttl == 60

    def test_every_configured_zone_present_even_when_empty(self, settings):
        desired = desired_of(settings, {"name": "www", "type": "CNAME", "value": "nas"})

        assert set(desired) == {settings.zone, *settings.reverse_zones}
        assert all(desired[zone] == {} for zone in settings.reverse_zones)


class TestReverseZoneMatching:
    def test_longest_matching_reverse_zone_wins(self, settings):
        desired = desired_of(
            settings,
            {"name": "a", "type": "A", "value": "10.42.1.10"},  # matches /16 and /24 zones
            {"name": "b", "type": "A", "value": "10.42.2.10"},  # matches only the /16 zone
        )

        assert (name("10.1.42.10.in-addr.arpa"), dns.rdatatype.PTR) in desired[name("1.42.10.in-addr.arpa")]
        assert (name("10.2.42.10.in-addr.arpa"), dns.rdatatype.PTR) in desired[name("42.10.in-addr.arpa")]

    @pytest.mark.parametrize(
        "entry",
        [
            {"name": "x", "type": "A", "value": "192.168.1.1"},
            {"name": "x", "type": "AAAA", "value": "2001:db9::1"},
        ],
        ids=["v4", "v6"],
    )
    def test_address_outside_reverse_zones_rejected(self, settings, entry):
        assert "matches no REVERSE_ZONES entry" in errors_of(settings, entry)

    def test_ptr_false_exempt_from_reverse_zone_check(self, settings):
        desired = desired_of(settings, {"name": "x", "type": "A", "value": "192.168.1.1", "ptr": False})
        assert (name("x.example.internal"), dns.rdatatype.A) in desired[settings.zone]

    def test_second_ptr_for_same_address_rejected(self, settings):
        message = errors_of(
            settings,
            {"name": "a", "type": "A", "value": "10.42.1.10"},
            {"name": "b", "type": "A", "value": "10.42.1.10"},
        )
        assert "ptr: false" in message


class TestValidation:
    @pytest.mark.parametrize(
        "entry, fragment",
        [
            ({"name": "x", "type": "NS", "value": "ns1"}, "'type' must be one of"),
            ({"name": "@", "type": "SOA", "value": "a b 1 2 3 4 5"}, "'type' must be one of"),
            ({"name": "x", "type": "A", "value": "10.42.1.999"}, "not a valid IPv4 address"),
            ({"name": "x", "type": "A", "value": "2001:db8::1"}, "not a valid IPv4 address"),
            ({"name": "x", "type": "AAAA", "value": "10.42.1.10"}, "not a valid IPv6 address"),
            ({"name": "x", "type": "MX", "value": "nas"}, "invalid MX value"),
            ({"name": "x", "type": "SRV", "value": "10 nas"}, "invalid SRV value"),
            ({"name": "x", "type": "A", "value": "10.42.1.10", "reverse": True}, "unknown keys"),
            ({"name": "www", "type": "CNAME", "value": "nas", "ptr": False}, "'ptr' only applies"),
            ({"name": "nas.example.internal.", "type": "A", "value": "10.42.1.10"}, "no trailing dot"),
        ],
        ids=[
            "ns-type",
            "soa-type",
            "malformed-v4",
            "v6-literal-in-a",
            "v4-literal-in-aaaa",
            "mx-without-priority",
            "srv-too-few-fields",
            "unknown-key",
            "ptr-flag-on-cname",
            "absolute-name",
        ],
    )
    def test_single_record_rejected(self, settings, entry, fragment):
        assert fragment in errors_of(settings, entry)

    def test_cname_coexistence_rejected(self, settings):
        message = errors_of(
            settings,
            {"name": "www", "type": "CNAME", "value": "nas"},
            {"name": "www", "type": "A", "value": "10.42.1.10"},
        )
        assert "CNAME must not coexist" in message

    def test_multiple_cname_values_rejected(self, settings):
        message = errors_of(
            settings,
            {"name": "www", "type": "CNAME", "value": "nas"},
            {"name": "www", "type": "CNAME", "value": "backup"},
        )
        assert "CNAME must not coexist" in message

    def test_duplicate_name_type_value_rejected(self, settings):
        message = errors_of(
            settings,
            {"name": "nas", "type": "A", "value": "10.42.1.10"},
            {"name": "nas", "type": "A", "value": "10.42.1.10"},
        )
        assert "duplicate record" in message

    def test_conflicting_ttls_within_rrset_rejected(self, settings):
        message = errors_of(
            settings,
            {"name": "nas", "type": "A", "value": "10.42.1.10", "ttl": 60},
            {"name": "nas", "type": "A", "value": "10.42.1.11", "ttl": 120, "ptr": False},
        )
        assert "conflicting ttl" in message

    @pytest.mark.parametrize(
        "document",
        [None, [], "records", {"record": []}, {"records": "nope"}],
        ids=["none", "bare-list", "bare-string", "misspelled-key", "records-not-a-list"],
    )
    def test_document_shape_enforced(self, settings, document):
        with pytest.raises(RecordsError, match="'records' list"):
            build_desired(document, settings)

    def test_all_errors_reported_at_once(self, settings):
        message = errors_of(
            settings,
            {"name": "x", "type": "A", "value": "bad"},
            {"name": "y", "type": "WEIRD", "value": "z"},
        )
        assert "records[0]" in message
        assert "records[1]" in message


class TestEmptySource:
    def test_zero_records_returns_zero_count(self, settings):
        desired, count = build_desired({"records": []}, settings)
        assert count == 0
        assert all(rrsets == {} for rrsets in desired.values())


@pytest.mark.parametrize(
    "value, expected",
    [
        ('say "hi"', '"say \\"hi\\""'),
        ("back\\slash", '"back\\\\slash"'),
        ("", '""'),
        ("x" * 256, '"' + "x" * 255 + '" "x"'),
    ],
    ids=["embedded-quotes", "backslash", "empty", "chunked-at-255"],
)
def test_quote_txt_escapes_and_chunks(value, expected):
    assert quote_txt(value) == expected
