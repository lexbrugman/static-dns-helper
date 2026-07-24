import dataclasses
import os

import dns.zone
import pytest

from static_dns_helper import nsupdate, reconcile, zones
from static_dns_helper.records import RecordsError

EMPTY_FORWARD = """
$ORIGIN example.internal.
$TTL 3600
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 3600
@ IN NS  ns1
"""

EMPTY_REVERSE = """
$TTL 3600
@ IN SOA ns1.example.internal. hostmaster.example.internal. 1 7200 3600 1209600 3600
@ IN NS  ns1.example.internal.
"""


@pytest.fixture
def live_zones(monkeypatch):
    def fake_fetch(zone_name, settings):
        if zone_name == settings.zone:
            return dns.zone.from_text(EMPTY_FORWARD, origin=zone_name, relativize=False)
        return dns.zone.from_text(EMPTY_REVERSE, origin=zone_name, relativize=False)

    monkeypatch.setattr(zones, "fetch_live", fake_fetch)


def write_records(settings, text):
    with open(settings.records_file, "w", encoding="utf-8") as fh:
        fh.write(text)


class TestFailClosed:
    def test_missing_file_raises_and_leaves_no_heartbeat(self, settings, live_zones):
        with pytest.raises(RecordsError, match="cannot read"):
            reconcile.reconcile_once(settings)
        assert not os.path.exists(settings.heartbeat_file)

    def test_invalid_yaml_raises(self, settings, live_zones):
        write_records(settings, "records: [\n")
        with pytest.raises(RecordsError, match="not valid YAML"):
            reconcile.reconcile_once(settings)

    def test_schema_failure_raises(self, settings, live_zones):
        write_records(settings, "records:\n  - {name: x, type: BOGUS, value: y}\n")
        with pytest.raises(RecordsError, match="invalid records file"):
            reconcile.reconcile_once(settings)

    def test_empty_source_refused(self, settings, live_zones):
        write_records(settings, "records: []\n")
        with pytest.raises(RecordsError, match="ALLOW_EMPTY"):
            reconcile.reconcile_once(settings)
        assert not os.path.exists(settings.heartbeat_file)

    def test_empty_source_applied_with_allow_empty(self, settings, live_zones):
        write_records(settings, "records: []\n")
        allow = dataclasses.replace(settings, allow_empty=True)
        reconcile.reconcile_once(allow)
        assert os.path.exists(allow.heartbeat_file)


class TestReconcileOnce:
    def test_in_sync_zone_applies_nothing_and_beats(self, settings, live_zones, monkeypatch):
        write_records(settings, "records: []\n")
        settings = dataclasses.replace(settings, allow_empty=True)
        monkeypatch.setattr(nsupdate, "apply_plan", lambda *a: pytest.fail("no changes expected"))
        reconcile.reconcile_once(settings)
        assert os.path.exists(settings.heartbeat_file)

    def test_changes_applied_via_plan(self, settings, live_zones, monkeypatch):
        write_records(settings, "records:\n  - {name: nas, type: A, value: 10.42.1.10}\n")
        applied = []
        monkeypatch.setattr(nsupdate, "apply_plan", lambda plan, s: applied.extend(plan) or True)
        reconcile.reconcile_once(settings)
        assert len(applied) == 2  # forward A + derived PTR
        assert os.path.exists(settings.heartbeat_file)

    def test_failed_apply_blocks_heartbeat(self, settings, live_zones, monkeypatch):
        write_records(settings, "records:\n  - {name: nas, type: A, value: 10.42.1.10}\n")
        monkeypatch.setattr(nsupdate, "apply_plan", lambda plan, s: False)
        with pytest.raises(reconcile.ReconcileError):
            reconcile.reconcile_once(settings)
        assert not os.path.exists(settings.heartbeat_file)

    def test_dry_run_prints_plan_and_writes_nothing(self, settings, live_zones, monkeypatch, capsys):
        write_records(settings, "records:\n  - {name: nas, type: A, value: 10.42.1.10}\n")
        dry = dataclasses.replace(settings, dry_run=True)
        monkeypatch.setattr(nsupdate, "apply_plan", lambda *a: pytest.fail("dry-run must not apply"))
        reconcile.reconcile_once(dry)
        out = capsys.readouterr().out
        assert "REPLACE" in out
        assert "10.42.1.10" in out
        assert not os.path.exists(dry.heartbeat_file)


class TestHealthcheck:
    def test_missing_heartbeat_unhealthy(self, settings):
        from static_dns_helper.healthcheck import healthcheck

        assert healthcheck(settings) == 1

    def test_fresh_heartbeat_healthy(self, settings):
        from static_dns_helper.healthcheck import healthcheck

        reconcile.write_heartbeat(settings.heartbeat_file)
        assert healthcheck(settings) == 0

    def test_stale_heartbeat_unhealthy(self, settings):
        from static_dns_helper.healthcheck import healthcheck

        reconcile.write_heartbeat(settings.heartbeat_file)
        stale = 2 * settings.reconcile_interval + 1
        os.utime(settings.heartbeat_file, (os.path.getmtime(settings.heartbeat_file) - stale,) * 2)
        assert healthcheck(settings) == 1
