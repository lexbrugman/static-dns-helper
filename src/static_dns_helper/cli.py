import argparse
import dataclasses
import logging
import os
import sys

from static_dns_helper import healthcheck
from static_dns_helper import reconcile
from static_dns_helper.settings import Settings


def main(argv=None):
    parser = argparse.ArgumentParser(prog="static-dns-helper", description="Reconcile static DNS records into BIND")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="reconcile now and on every RECONCILE_INTERVAL tick")
    once = subparsers.add_parser("once", help="run a single reconcile cycle and exit")
    for sub in (run, once):
        sub.add_argument("--dry-run", action="store_true", help="print the plan; write nothing")
    subparsers.add_parser("healthcheck", help="exit non-zero if the heartbeat is stale")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    settings = Settings.from_env()
    if getattr(args, "dry_run", False):
        settings = dataclasses.replace(settings, dry_run=True)

    if args.command == "healthcheck":
        return healthcheck.healthcheck(settings)
    if args.command == "once":
        try:
            reconcile.reconcile_once(settings)
        except Exception as e:
            logging.getLogger(__name__).error("reconcile failed: %s", e)
            return 1
        return 0
    return reconcile.run_loop(settings)


if __name__ == "__main__":
    sys.exit(main())
