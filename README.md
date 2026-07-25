# static-dns-helper

The declarative half of internal DNS: reconciles static DNS records declared in a
git-managed YAML file into an authoritative BIND zone (and its reverse zones) over
TSIG-authenticated RFC2136 dynamic update. It reads current zone state via AXFR,
diffs it against the declared records, and applies adds, updates, and purges until
the zone converges. One running instance manages one forward zone plus a configured
set of reverse zones.

Its counterpart, [dhcp-dns-helper](https://github.com/lexbrugman/dhcp-dns-helper),
writes the dynamic (DHCP lease) records. The two services share no code — only the
marker convention below.

## The marker contract (published interface)

> Any dynamic writer stamps each record it writes with a TXT record whose value
> starts with `MARKER_PREFIX` (default `x-dyn:`). Zone owners must never modify or
> purge a record so marked.

This is the sole coupling between static-dns-helper and dhcp-dns-helper, and the
sole mechanism protecting dynamic records from the purge pass. Both services must
be deployed with the same `MARKER_PREFIX` value. A name bearing a marker TXT is
off-limits in its entirety: every record type at that name is left alone.

## Ownership model

The invariant enforced on each managed zone:

> zone == git-declared records ∪ marked exceptions ∪ zone meta — and nothing else.

The tool owns the whole zone by default. The only exceptions are:

- **Marked records** — any name carrying a TXT value starting with `MARKER_PREFIX`.
- **Zone meta** — SOA, NS, and DNSSEC types (DNSKEY/RRSIG/NSEC*/DS/CDS/CDNSKEY),
  never touched.

Everything else not declared in the records file is drift and gets purged —
there is no "hand-made records are safe" category. Because this polarity fails
toward over-deletion, the input safety rules below are load-bearing.

## Records file

Structured YAML at `RECORDS_FILE`. Names are relative to the zone (`@` for the
apex); PTR records are derived automatically and cannot be hand-authored:

```yaml
records:
  - { name: nas,    type: A,     value: 10.42.1.10 }              # PTR -> in-addr.arpa
  - { name: nas,    type: AAAA,  value: 2001:db8::10 }            # PTR -> ip6.arpa
  - { name: nas,    type: A,     value: 10.42.1.11, ptr: false }  # 2nd RR, no PTR
  - { name: www,    type: CNAME, value: nas }
  - { name: mail,   type: MX,    value: "10 nas" }
  - { name: _dmarc, type: TXT,   value: "v=DMARC1; p=none" }
```

- Supported types: `A`, `AAAA`, `CNAME`, `MX`, `SRV`, `TXT`. Multi-value RRsets are
  supported (repeat the name/type with different values).
- `ttl` is optional per record (defaults to `TTL`); all records of one RRset must
  agree on it.
- Relative names in `CNAME`/`MX`/`SRV` values are expanded against the zone; use a
  trailing dot for external targets.
- Every `A`/`AAAA` derives one PTR in the matching reverse zone. `ptr: false` opts
  a record out — required when several records share an address (one PTR per
  address; the primary record owns it).
- The derived reverse name must fall inside a configured `REVERSE_ZONES` entry
  (longest match wins); an address outside the managed reverse space is a
  validation error.

The file is schema-validated before anything is applied: unknown types, malformed
IP/MX/SRV values, duplicate records, conflicting TTLs, CNAME coexisting with other
records at a name, and unmatched reverse addresses are all rejected — and the whole
cycle refuses to run.

## Reconcile behavior

On start and every `RECONCILE_INTERVAL` seconds, for the forward zone and every
configured reverse zone:

1. Read the live zone via AXFR.
2. Exclude marked names and zone meta; the rest of the managed-type RRsets are owned.
3. Diff against the declared records at RRset granularity and apply adds/updates as
   whole-RRset replaces, and purges as per-record deletes.

Reconciliation is idempotent (no drift means zero writes) and self-healing
(out-of-band changes are corrected on the next tick). Every purge is guarded by an
RFC2136 prerequisite on the exact records observed in the AXFR: if the zone changed
in between, the delete is skipped and retried next cycle.

### Input safety — fail closed, loudly

A bad or empty source file must never cause a wrongful mass-purge:

- File missing, unreadable, or failing schema validation → no changes this cycle,
  an error log, and no heartbeat advance (the pod goes unhealthy).
- A source that parses to **zero records** is refused unless `ALLOW_EMPTY=true` —
  a delivery failure looks exactly like an intentionally emptied file.
- `--dry-run` (or `DRY_RUN=true`) prints the plan and writes nothing.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `ZONE` | *(required)* | Forward zone to manage |
| `NAMESERVER` | *(required)* | BIND primary to send updates/AXFR to (IP or hostname) |
| `REVERSE_ZONES` | *(required)* | Comma-separated reverse zones, e.g. `168.192.in-addr.arpa,8.b.d.0.1.0.0.2.ip6.arpa` |
| `KEYRING_JSON` | *(required)* | TSIG key for updates and AXFR (hmac-sha256), JSON `{"name": "secret"}` — needs both `allow-update` and `allow-transfer` on the managed zones |
| `MARKER_PREFIX` | `x-dyn:` | Shared marker convention (see above); must match the dynamic writer |
| `TTL` | `3600` | Default record TTL |
| `RECORDS_FILE` | `/config/records.yaml` | Path to the records file |
| `RECONCILE_INTERVAL` | `900` | Seconds between reconcile cycles |
| `ALLOW_EMPTY` | `false` | Explicit opt-in to a zero-record desired set |
| `DRY_RUN` | `false` | Print the plan, write nothing |
| `HEARTBEAT_FILE` | `/run/last-reconcile` | Touched after each successful cycle |
| `DNS_PORT` | `53` | Nameserver port (mainly for tests) |
| `LOG_LEVEL` | `INFO` | `DEBUG` logs the full plan per cycle |

When reconciling IPv4 reverse zones shared with dhcp-dns-helper, `REVERSE_ZONES`
must include exactly the in-addr.arpa zone(s) it writes to, so static PTRs land in
the same zones and marked lease PTRs are honored.

## Running

```
python -m static_dns_helper run           # reconcile now + every RECONCILE_INTERVAL
python -m static_dns_helper once          # single cycle, exit non-zero on failure
python -m static_dns_helper once --dry-run
python -m static_dns_helper healthcheck   # non-zero if heartbeat older than 2x interval
```

There is no HTTP server. Liveness is the heartbeat file: `healthcheck` exits
non-zero when the last successful reconcile is more than 2× `RECONCILE_INTERVAL`
ago — wire it as an exec liveness probe. Fail-closed states (bad input, failed
updates) stop the heartbeat and surface there.

## Development

```
uv venv .venv && uv pip install -p .venv/bin/python -r requirements-dev.txt
.venv/bin/python -m pytest tests/
```

Unit tests cover parsing/derivation, exception detection, diffing, and the
fail-closed paths. `tests/integration/` runs the full reconcile lifecycle against
a throwaway BIND, orchestrated by [testcontainers](https://testcontainers-python.readthedocs.io/)
(containers are reaped even if the test run is killed). The tests skip
automatically when no container API socket is reachable. With docker no setup is
needed; with rootless podman, expose the API socket once:

```
systemctl --user enable --now podman.socket
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
```

Kubernetes manifests, records-file delivery, BIND server configuration, and TSIG
key provisioning are handled on the infra side; this repo only ships the container
image, the config surface above, and the healthcheck.
