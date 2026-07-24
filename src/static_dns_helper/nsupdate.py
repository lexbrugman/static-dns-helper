import logging

import dns.query
import dns.rcode
import dns.rdataset
import dns.tsigkeyring
import dns.update

from static_dns_helper.plan import Delete, describe
from static_dns_helper.zones import QUERY_TIMEOUT, resolve_nameserver

logger = logging.getLogger(__name__)


def build_update(action, keyring):
    update = dns.update.Update(action.zone, keyring=keyring, keyalgorithm="hmac-sha256")
    if isinstance(action, Delete):
        # Guard every delete on the exact RRset observed via AXFR: if the zone
        # changed since (a dynamic writer raced us), the prerequisite fails and
        # nothing is deleted; the next cycle re-observes and retries.
        for rd in sorted(action.rdatas, key=lambda r: r.to_text()):
            update.present(action.name, rd)
        for rd in sorted(action.rdatas, key=lambda r: r.to_text()):
            update.delete(action.name, rd)
    else:
        update.replace(action.name, dns.rdataset.from_rdata_list(action.ttl, list(action.rdatas)))
    return update


def apply_plan(actions, settings):
    """Apply the plan one RRset per update message. Returns True if all applied."""
    keyring = dns.tsigkeyring.from_text(settings.keyring)
    server = resolve_nameserver(settings.nameserver)
    all_applied = True
    for action in actions:
        response = dns.query.tcp(build_update(action, keyring), server, port=settings.port, timeout=QUERY_TIMEOUT)
        rcode = response.rcode()
        if rcode == dns.rcode.NOERROR:
            logger.info("applied: %s", describe(action))
        elif rcode == dns.rcode.NXRRSET and isinstance(action, Delete):
            logger.warning("skipped (changed since observation): %s", describe(action))
        else:
            logger.error("failed (%s): %s", dns.rcode.to_text(rcode), describe(action))
            all_applied = False
    return all_applied
