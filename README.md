# PyP0f

A small, dependency-light passive TCP fingerprinting collector, built on
[Scapy](https://scapy.net/)'s bundled p0f-v3-compatible signature matcher
(`scapy.modules.p0f`) and the classic
[p0f](https://github.com/p0f/p0f) `p0f.fp` signature database.

It sniffs incoming TCP SYN packets on a given interface, classifies the
likely client OS from the TCP/IP signature (TTL, window size, MSS, option
order, etc. - the same passive fingerprinting technique p0f uses), and
writes the result to Redis as a simple `key -> "OS name"` pair with a TTL.
Nothing is kept in the process's own memory beyond the current packet: it is
meant to be a thin, stateless, restart-safe collector, with Redis as the
single source of truth for accumulated results.

## Why

The original `p0f` (v3.09b) is unmaintained since 2016 and, as a plain C
daemon, its host-cache handling can be fragile under sustained high
connection churn. This project trades some raw performance for running the
same style of signature-based classification in a memory-safe language,
persists results externally (Redis, not in-process memory) so a restart
does not discard accumulated data, and is small enough to read and modify
in an afternoon.

## Configuration

All configuration is via environment variables (see `pyp0f/config.py`):

| Variable | Default | Description |
|---|---|---|
| `PYP0F_IFACE` | `eth0` | Network interface to listen on |
| `PYP0F_BPF_FILTER` | SYN packets on ports 80/443 | BPF filter, compiled and applied at the kernel level |
| `PYP0F_DB_PATH` | `/app/p0f.fp` | Path to a p0f v3 signature database |
| `PYP0F_REDIS_HOST` / `PYP0F_REDIS_PORT` / `PYP0F_REDIS_DB` | `127.0.0.1` / `6379` / `0` | Redis connection |
| `PYP0F_REDIS_KEY_PREFIX` | `pyp0f:` | Prefix for written keys (`<prefix><ip>`) |
| `PYP0F_REDIS_TTL_SECONDS` | `7200` | TTL applied to each written entry |

## Running

```bash
docker build -t pyp0f .
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PYP0F_IFACE=eth0 \
  -e PYP0F_REDIS_HOST=redis \
  pyp0f
```

Raw packet capture requires `NET_RAW`/`NET_ADMIN` (or `--privileged`) and,
in practice, host networking to see real interface traffic.

## Status

⚠️ **This is a vibe-coded prototype, written with heavy AI assistance, and
has not been tested in production.** It has not been load-tested, hardened,
or reviewed to any production standard. Expect rough edges. Use it as a
starting point, not as a finished tool.

## License

MIT - see [LICENSE](LICENSE). Provided as-is, with no warranty of any kind;
see the license text for the full disclaimer.
