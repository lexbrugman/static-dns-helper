import sys
from pathlib import Path

import dns.name
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from static_dns_helper.settings import Settings  # noqa: E402


@pytest.fixture
def settings(tmp_path):
    return Settings(
        zone=dns.name.from_text("example.internal"),
        nameserver="127.0.0.1",
        port=53,
        reverse_zones=(
            dns.name.from_text("42.10.in-addr.arpa"),
            dns.name.from_text("1.42.10.in-addr.arpa"),
            dns.name.from_text("8.b.d.0.1.0.0.2.ip6.arpa"),
        ),
        ttl=3600,
        records_file=str(tmp_path / "records.yaml"),
        marker_prefix="x-dyn:",
        reconcile_interval=900,
        allow_empty=False,
        dry_run=False,
        heartbeat_file=str(tmp_path / "heartbeat"),
        keyring={"update-key": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0AA=="},
        transfer_keyring={"transfer-key": "dHJhbnNmZXJ0cmFuc2ZlcnRyYW5zZmVyAA=="},
    )
