import os
import sys
import time


def healthcheck(settings):
    """Exit status for the liveness probe: 0 iff the heartbeat is fresh."""
    max_age = 2 * settings.reconcile_interval
    try:
        age = time.time() - os.path.getmtime(settings.heartbeat_file)
    except OSError:
        print(f"unhealthy: heartbeat file {settings.heartbeat_file} missing", file=sys.stderr)
        return 1
    if age > max_age:
        print(f"unhealthy: last successful reconcile {int(age)}s ago (max {max_age}s)", file=sys.stderr)
        return 1
    return 0
