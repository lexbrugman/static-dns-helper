import logging
import os
import signal
import threading
import time

from static_dns_helper import nsupdate
from static_dns_helper import records
from static_dns_helper import zones
from static_dns_helper.plan import describe, diff_zone

logger = logging.getLogger(__name__)


class ReconcileError(Exception):
    pass


def build_plan(settings):
    desired, record_count = records.load_desired(settings.records_file, settings)
    if record_count == 0 and not settings.allow_empty:
        raise records.RecordsError(
            "records file yielded zero records; refusing to purge the zone (set ALLOW_EMPTY=true to override)"
        )

    plan = []
    for zone_name in (settings.zone, *settings.reverse_zones):
        live = zones.fetch_live(zone_name, settings)
        excluded = zones.excluded_names(live, settings.marker_prefix)
        managed = zones.managed_rrsets(live, excluded)
        plan.extend(diff_zone(zone_name, desired[zone_name], managed))
    return plan


def reconcile_once(settings):
    plan = build_plan(settings)
    for action in plan:
        logger.debug("plan: %s", describe(action))

    if settings.dry_run:
        for action in plan:
            print(describe(action))
        logger.info("dry-run: %d change(s) planned, nothing applied", len(plan))
        return

    if not plan:
        logger.info("in sync: no changes")
    elif not nsupdate.apply_plan(plan, settings):
        raise ReconcileError("one or more updates failed; heartbeat not advanced")

    write_heartbeat(settings.heartbeat_file)


def write_heartbeat(path):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(f"{int(time.time())}\n")
    os.replace(tmp, path)


def run_loop(settings):
    stop = threading.Event()

    def _terminate(signum, frame):
        logger.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)

    logger.info(
        "reconciling %s + %d reverse zone(s) every %ds",
        settings.zone,
        len(settings.reverse_zones),
        settings.reconcile_interval,
    )
    while not stop.is_set():
        try:
            reconcile_once(settings)
        except Exception as e:
            # Fail closed: no changes this cycle, heartbeat not advanced, keep running.
            logger.error("reconcile failed: %s", e, exc_info=not isinstance(e, (records.RecordsError, ReconcileError)))
        stop.wait(settings.reconcile_interval)
    return 0
