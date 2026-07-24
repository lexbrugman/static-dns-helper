import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.tsigkeyring

from static_dns_helper.nsupdate import build_update
from static_dns_helper.plan import Delete, Replace

ZONE = dns.name.from_text("example.internal")
NAME = dns.name.from_text("nas.example.internal")
KEYRING = dns.tsigkeyring.from_text({"update-key": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0AA=="})


def a_rdata(address):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, address)


class TestDeleteMessage:
    def test_delete_guarded_by_exact_observed_values(self):
        action = Delete(
            zone=ZONE, name=NAME, rdtype=dns.rdatatype.A,
            rdatas=frozenset({a_rdata("10.42.1.10"), a_rdata("10.42.1.11")}),
        )
        update = build_update(action, KEYRING)

        # RFC2136 value-dependent prereqs: same-name/type RRs union into one
        # "rrset exists exactly" check on the server side.
        assert all(p.name == NAME and p.rdtype == dns.rdatatype.A for p in update.prerequisite)
        assert all(p.rdclass == dns.rdataclass.IN and p.ttl == 0 for p in update.prerequisite)
        assert {rd for p in update.prerequisite for rd in p} == set(action.rdatas)

        assert all(d.deleting == dns.rdataclass.NONE for d in update.update)  # exact RRs, not whole RRset
        assert {rd for d in update.update for rd in d} == set(action.rdatas)

        update.to_wire()  # must serialize

    def test_replace_converges_whole_rrset(self):
        action = Replace(
            zone=ZONE, name=NAME, rdtype=dns.rdatatype.A, ttl=600,
            rdatas=frozenset({a_rdata("10.42.1.10"), a_rdata("10.42.1.11")}),
        )
        update = build_update(action, KEYRING)

        assert update.prerequisite == []  # replace is unconditional convergence
        delete_rrset = [s for s in update.update if s.deleting == dns.rdataclass.ANY]
        adds = [s for s in update.update if s.deleting is None]
        assert len(delete_rrset) == 1  # clear the (name, type) first...
        assert all(a.ttl == 600 for a in adds)
        assert {rd for a in adds for rd in a} == set(action.rdatas)

        update.to_wire()
