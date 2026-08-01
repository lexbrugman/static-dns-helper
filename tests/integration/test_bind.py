"""End-to-end tests against a throwaway BIND managed by testcontainers.

Skipped automatically when no container API socket is reachable (docker, or
rootless podman via `systemctl --user enable --now podman.socket` plus
DOCKER_HOST pointing at the podman socket). The container serves the forward
zone plus a v4 and a v6 reverse zone, seeded with marked "lease" records
(the dynamic-writer convention) and unmarked drift for the purge assertions.
"""

import base64
import time
from pathlib import Path

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.zone
import pytest

from static_dns_helper import reconcile
from static_dns_helper.records import RecordsError
from static_dns_helper.settings import Settings

BIND_IMAGE = "docker.io/internetsystemsconsortium/bind9:9.20"
FORWARD = "example.internal"
REVERSE_V4 = "1.42.10.in-addr.arpa"
REVERSE_V6 = "8.b.d.0.1.0.0.2.ip6.arpa"
MARKER = "x-dyn:"
UPDATE_SECRET = base64.b64encode(b"integration-update-secret-32byte").decode()

NAMED_CONF = f"""
options {{
    directory "/var/cache/bind";
    recursion no;
    allow-query {{ any; }};
    listen-on {{ any; }};
    listen-on-v6 {{ any; }};
}};
key "update-key" {{ algorithm hmac-sha256; secret "{UPDATE_SECRET}"; }};
"""

ZONE_CONF = """
zone "{zone}" {{
    type primary;
    file "/var/lib/bind/{zone}.zone";
    allow-update {{ key "update-key"; }};
    allow-transfer {{ key "update-key"; }};
}};
"""

FORWARD_SEED = f"""
$TTL 3600
@       IN SOA  ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600
@       IN NS   ns1.example.net.
lease1  IN A    10.42.1.100
lease1  IN TXT  "{MARKER}2b6e1b0a"
stale   IN A    10.42.1.7
"""

REVERSE_V4_SEED = f"""
$TTL 3600
@       IN SOA  ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600
@       IN NS   ns1.example.net.
100     IN PTR  lease1.{FORWARD}.
100     IN TXT  "{MARKER}2b6e1b0a"
7       IN PTR  stale.{FORWARD}.
"""

REVERSE_V6_SEED = f"""
$TTL 3600
@       IN SOA  ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600
@       IN NS   ns1.example.net.
7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0 IN PTR stale.{FORWARD}.
"""

RECORDS_FULL = """
records:
  - { name: nas,    type: A,     value: 10.42.1.10 }
  - { name: nas,    type: A,     value: 10.42.1.11, ptr: false }
  - { name: nas,    type: AAAA,  value: 2001:db8::10 }
  - { name: www,    type: CNAME, value: nas }
  - { name: mail,   type: MX,    value: "10 nas" }
  - { name: _dmarc, type: TXT,   value: "v=DMARC1; p=none" }
"""

RECORDS_SHRUNK = """
records:
  - { name: nas, type: A, value: 10.42.1.10 }
"""


def docker_api_available():
    try:
        from testcontainers.core.docker_client import DockerClient

        return DockerClient().client.ping()
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not docker_api_available(), reason="no container API socket reachable")


@pytest.fixture(scope="module")
def bind_server(tmp_path_factory):
    from testcontainers.core.container import DockerContainer

    root = tmp_path_factory.mktemp("bind")
    conf = root / "conf"
    zones = root / "zones"
    conf.mkdir()
    zones.mkdir()

    named_conf = NAMED_CONF + "".join(ZONE_CONF.format(zone=z) for z in (FORWARD, REVERSE_V4, REVERSE_V6))
    (conf / "named.conf").write_text(named_conf)
    (zones / f"{FORWARD}.zone").write_text(FORWARD_SEED)
    (zones / f"{REVERSE_V4}.zone").write_text(REVERSE_V4_SEED)
    (zones / f"{REVERSE_V6}.zone").write_text(REVERSE_V6_SEED)
    zones.chmod(0o777)
    for zone_file in zones.iterdir():
        zone_file.chmod(0o666)

    container = (
        DockerContainer(BIND_IMAGE)
        .with_volume_mapping(str(conf / "named.conf"), "/etc/bind/named.conf", "ro")
        .with_volume_mapping(str(zones), "/var/lib/bind", "rw")
        .with_exposed_ports(53)  # the app only ever speaks TCP (updates and AXFR)
    )
    with container:
        host = container.get_container_host_ip()
        if host == "localhost":  # dnspython's query functions want an IP literal
            host = "127.0.0.1"
        port = int(container.get_exposed_port(53))
        _wait_for_bind(host, port, container)
        yield host, port


def _wait_for_bind(host, port, container):
    query = dns.message.make_query(FORWARD, dns.rdatatype.SOA)
    for _ in range(60):
        try:
            response = dns.query.tcp(query, host, port=port, timeout=2)
            if response.rcode() == dns.rcode.NOERROR:
                return
        except (OSError, dns.exception.DNSException):
            pass
        time.sleep(0.5)
    stdout, stderr = container.get_logs()
    raise RuntimeError(f"BIND did not become ready:\n{stdout.decode()}\n{stderr.decode()}")


@pytest.fixture
def settings(bind_server, tmp_path):
    host, port = bind_server
    return Settings(
        zone=dns.name.from_text(FORWARD),
        nameserver=host,
        port=port,
        reverse_zones=(dns.name.from_text(REVERSE_V4), dns.name.from_text(REVERSE_V6)),
        ttl=300,
        records_file=str(tmp_path / "records.yaml"),
        marker_prefix=MARKER,
        reconcile_interval=900,
        allow_empty=False,
        dry_run=False,
        heartbeat_file=str(tmp_path / "heartbeat"),
        keyring={"update-key": UPDATE_SECRET},
    )


def axfr(zone, settings):
    keyring = dns.tsigkeyring.from_text({"update-key": UPDATE_SECRET})
    xfr = dns.query.xfr(
        settings.nameserver, zone, port=settings.port, keyring=keyring, keyalgorithm="hmac-sha256", relativize=False
    )
    return dns.zone.from_xfr(xfr, relativize=False)


def rrset(zone_obj, name, rdtype):
    return zone_obj.get_rdataset(dns.name.from_text(name), rdtype)


def values(zone_obj, name, rdtype):
    rds = rrset(zone_obj, name, rdtype)
    return {rd.to_text() for rd in rds} if rds else None


def run_cycle(settings, records_text):
    Path(settings.records_file).write_text(records_text)
    reconcile.reconcile_once(settings)


V6_PTR_OWNER = "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + REVERSE_V6


def test_full_reconcile_lifecycle(settings):
    run_cycle(settings, RECORDS_FULL)

    forward = axfr(FORWARD, settings)
    expected = {
        (f"nas.{FORWARD}", dns.rdatatype.A): {"10.42.1.10", "10.42.1.11"},
        (f"nas.{FORWARD}", dns.rdatatype.AAAA): {"2001:db8::10"},
        (f"www.{FORWARD}", dns.rdatatype.CNAME): {f"nas.{FORWARD}."},
        (f"mail.{FORWARD}", dns.rdatatype.MX): {f"10 nas.{FORWARD}."},
        (f"_dmarc.{FORWARD}", dns.rdatatype.TXT): {'"v=DMARC1; p=none"'},
    }
    assert {key: values(forward, *key) for key in expected} == expected

    # marked lease records survive, in both directions
    assert values(forward, f"lease1.{FORWARD}", dns.rdatatype.A) == {"10.42.1.100"}
    reverse4 = axfr(REVERSE_V4, settings)
    assert values(reverse4, f"100.{REVERSE_V4}", dns.rdatatype.PTR) == {f"lease1.{FORWARD}."}

    # unmarked drift is purged, forward and reverse
    assert rrset(forward, f"stale.{FORWARD}", dns.rdatatype.A) is None
    assert rrset(reverse4, f"7.{REVERSE_V4}", dns.rdatatype.PTR) is None

    # derived PTRs: only for the primary A (ptr: false suppressed) and the AAAA
    assert values(reverse4, f"10.{REVERSE_V4}", dns.rdatatype.PTR) == {f"nas.{FORWARD}."}
    assert values(reverse4, f"11.{REVERSE_V4}", dns.rdatatype.PTR) is None
    reverse6 = axfr(REVERSE_V6, settings)
    assert values(reverse6, V6_PTR_OWNER, dns.rdatatype.PTR) == {f"nas.{FORWARD}."}
    # the seeded v6 orphan is purged
    assert len([n for n, node in reverse6.nodes.items() if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.PTR)]) == 1

    # zone meta untouched
    assert rrset(forward, FORWARD, dns.rdatatype.SOA) is not None
    assert values(forward, FORWARD, dns.rdatatype.NS) == {"ns1.example.net."}

    assert Path(settings.heartbeat_file).exists()


def test_removed_records_are_purged(settings):
    run_cycle(settings, RECORDS_FULL)
    run_cycle(settings, RECORDS_SHRUNK)

    forward = axfr(FORWARD, settings)
    assert values(forward, f"nas.{FORWARD}", dns.rdatatype.A) == {"10.42.1.10"}
    assert rrset(forward, f"nas.{FORWARD}", dns.rdatatype.AAAA) is None
    assert rrset(forward, f"www.{FORWARD}", dns.rdatatype.CNAME) is None

    # the v6 reverse zone emptied out: its PTR is purged even with zero desired v6 records
    reverse6 = axfr(REVERSE_V6, settings)
    assert not any(node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.PTR) for node in reverse6.nodes.values())

    # marked records still survive repeated cycles
    assert values(forward, f"lease1.{FORWARD}", dns.rdatatype.A) == {"10.42.1.100"}
    reverse4 = axfr(REVERSE_V4, settings)
    assert values(reverse4, f"100.{REVERSE_V4}", dns.rdatatype.PTR) == {f"lease1.{FORWARD}."}


def test_reconcile_is_idempotent(settings):
    run_cycle(settings, RECORDS_FULL)
    assert reconcile.build_plan(settings) == []


def test_empty_source_refused_and_zone_untouched(settings):
    run_cycle(settings, RECORDS_FULL)
    Path(settings.records_file).write_text("records: []\n")
    with pytest.raises(RecordsError, match="ALLOW_EMPTY"):
        reconcile.reconcile_once(settings)
    assert values(axfr(FORWARD, settings), f"nas.{FORWARD}", dns.rdatatype.A) == {"10.42.1.10", "10.42.1.11"}
