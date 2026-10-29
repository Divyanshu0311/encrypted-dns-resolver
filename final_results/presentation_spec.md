# Encrypted DNS Resolver: Full Spec and 15-Minute Presentation Plan

*Prepared 2026-10-29 from the repository at commit `3bfa887` (`main`). Every number below has a source in
the [evidence ledger](#11-evidence-ledger).*

**How to use this document.** Sections 1–2 are the story and who did what. Section 3 is the full technical
spec, for reference and Q&A. Sections 4–7 are the presentation itself: decisions to show, what to
highlight, the slide-by-slide plan and the demo. Sections 8–10 are for rehearsal: honest status, likely
questions and weak points. Section 12 lists what still has to be decided before presenting.

---

## 1. The story

**Governing thought.** We built an encrypted DNS server whose front door and traffic control are complete
and heavily tested. It speaks DNS-over-TLS with TLS 1.3, cuts off abusive clients before spending
TLS work on them, and guarantees every query exactly one answer, even under overload. Its backend answers
authoritatively from standard zone files. Live upstream resolution (forwarding and recursion) is the
piece still to build.

**SCQA**

- **Situation.** Ordinary DNS travels in plain text, so anyone on the network path can see every name a
  user looks up. Resolvers are also a common target for abuse.
- **Complication.** Encrypting DNS (DNS-over-TLS, RFC 7858) moves cost onto the server: TLS handshakes,
  long-lived connections, and clients that can hold those resources. A naive encrypted server is easy
  to exhaust.
- **Question.** Can we build a resolver that keeps queries private and stays responsive under abuse and
  overload?
- **Answer.** Yes for the serving path. 411 automated tests cover encryption, rejection, abuse blocking,
  overload shedding and authoritative answers. Upstream resolution is not built yet, so today the server
  answers from a stand-in (stub) resolver or from zone files.

**Key lines** (each one gets a block of slides):

1. **Private:** every query is encrypted with TLS 1.3, and reply sizes are hidden with padding. *(front-end)*
2. **Hard to abuse:** bad clients are rejected or blocked before they cost TLS work, and per-client
   limits stop any one client exhausting the server. *(front-end + middleware)*
3. **Always answers:** every query gets exactly one reply. Overload and failures turn into fast
   SERVFAILs, not hangs, and identical queries are resolved once. *(middleware)*
4. **Correct answers:** the backend reads standard zone files and follows DNS rules for referrals, CNAMEs,
   wildcards and negative answers. *(backend)*
5. **Honest status:** what's tested, what's stubbed, what's next. *(all)*

---

## 2. Team and contributions

Taken from git authorship (who created which files, and each commit's changes). **Each member should
confirm their row before the presentation** (see section 12).

| Member | Area | What they built | Tests in their area |
|---|---|---|---|
| **Dhruv** | Front-end (DoT) | TLS context, DoT framing, DNS query parsing and reply encoding (with EDNS padding and BADVERS), blocked-domain policy (`Admission`), the epoll server loop, the `dns_server` binary. Also the abuse **block list** (`BlockList`) and its hooks into the middleware (`is_blocked`, `report_abuse`), plus the front-end config keys. The front-end design doc. | 110 (admission 8, block list 17, DNS message 45, framer 11, server 23, TLS 6) |
| **divyanshu** | Middleware | The `Middleware` facade, rate limiter, request coalescing, worker threads with circuit breakers, three load-balancing policies, deadline timer, metrics, config parser, logger, `load_gen`, the test framework and printers, CMake presets, README. Ported the first DNS message code into the tree. Later hardened the front-end (per-source connection cap, stall reset, handshake strike rules, graceful `stop(grace)`). | 127 (config 25, types 20, middleware 16, worker 11, queue 9, metrics 9, factory 8, load balancer 7, timer 6, rate limiter 6, in-flight 5, responder 5) |
| **Arnav Bhate** | Backend + shared types | Shared `types` namespace (`DomainName`, `IP`, `Records`), the zone file parser, `ZoneFilesResolver`, `HostsFileResolver`, resolver interface, the switch to CMake, temp-dir test support. Declared `ForwardingResolver`, `RecursiveResolver` and `Cache` (bodies not written yet). | 174 (zone file 59, zone resolver 36, domain name 33, records 17, hosts file 15, IP 14) |

**Total: 411 tests**, all passing (see ledger L1).

> Note: git shows `.clang-format` added in divyanshu's commit, but team notes call it Arnav's style. Confirm.

---

## 3. Full technical spec

### 3.1 Architecture: one query, end to end

```
 client ──TLS 1.3 / TCP 853──► FRONT-END (Dhruv)                    MIDDLEWARE (divyanshu)              BACKEND (Arnav)
                               accept: blocked? ─► reset            submit(name, type, client, cb)
                               TLS handshake                          ├ blocked? ─► REFUSED
                               framing (2-byte length)                ├ rate limit ─► REFUSED + strike
                               parse ─► FORMERR/NOTIMP/BADVERS        ├ coalesce identical queries
                               blocked domain? ─► REFUSED             ├ load balancer ─► worker queue ──► Resolver chain
                               submit() ─────────────────────────────►├ deadline timer ─► SERVFAIL          zone files
                                                                      └ exactly one callback ◄────────── hosts file
                               encode + pad ◄── mailbox/eventfd ◄────── (worker or timer thread)          (stub today)
 client ◄──────────────────── TLS write
```

Three threads of control matter: the front-end's single **I/O thread**, the middleware's **worker
threads** (one resolver chain each) and one **deadline timer** thread. Answers cross from worker to I/O
thread through a locked mailbox plus an `eventfd` wake-up.

### 3.2 Shared types (Arnav): `include/DomainName.hpp`, `IP.hpp`, `Records.hpp`

- **`DomainName`:** a list of labels plus an `absolute` flag. It can be built from text (with `\.` and
  `\DDD` escapes) or from wire bytes (with compression pointers, at most 128 jumps to stop loops).
  Comparison and hashing ignore case; the original spelling is kept. Limits: label 63 bytes, name 255.
  Also `parent()`, `is_ancestor_of` and `is_descendent_of`, and concatenation.
- **`IP`:** IPv4 or IPv6 from text, wire bytes or socket structs; converts to the reverse-lookup name
  (`in-addr.arpa` / `ip6.arpa`).
- **`Records`:** every IANA record type, rcodes 0–11, classes IN/CS/CH/HS, `ResourceRecord`
  {name, type, class, TTL, rdata} and `ResolveResult` {rcode, answer, authority, additional}.
  `find_records` helpers.

### 3.3 Backend (Arnav): `include/backend/`, `src/backend/`

- **`Resolver` interface:** `resolve(name, type, class, recurse)` returns a `ResolveResult`.
  Resolvers chain through a `fallback` pointer.
- **Zone file parser** (`ZoneFile.cpp`, RFC 1035 master format): `$ORIGIN`, `$TTL`, `$INCLUDE` (nested up
  to 10 deep, its origin scoped to the included file), parentheses across lines, comments, quoted strings,
  escapes, TTL units (`1h30m`), TTL/class in either order. Typed RDATA for A, AAAA, NS, CNAME, PTR, DNAME,
  MX, SRV, SOA, TXT, HINFO, CAA, SSHFP, DS, DNSKEY, TLSA and more, plus the RFC 3597 generic `\# len hex`
  form for anything else. TTL precedence: explicit, then `$TTL`, then previous record, then the SOA minimum.
- **`ZoneFilesResolver`:** picks the longest matching zone per class, then:
  - **referrals** at zone cuts (NS below the apex), with glue in the additional section; DS queries are
    answered on the parent side of the cut
  - **CNAME chasing** across zones and into the fallback, up to 8 links (then SERVFAIL)
  - **wildcards** at the closest encloser (RFC 4592)
  - **NODATA vs NXDOMAIN**, each with the zone's SOA in the authority section; empty non-terminals are NODATA
  - **additional section** glue for NS, MX and SRV targets
  - each zone file must have exactly one SOA and a single class
- **`HostsFileResolver`:** `/etc/hosts` format, giving A/AAAA plus the matching PTR, TTL 0, with a fallback.
- **Declared but not implemented:** `ForwardingResolver`, `RecursiveResolver`, `Cache`.

### 3.4 Middleware (divyanshu): `include/mw/`, `src/`

**Facade:** `Middleware(config, resolver_factory)`, `start()`, `submit(name, type, client, callback)`,
`is_blocked(ip)`, `report_abuse(ip)`, `stop(drain)`, `metrics_snapshot()`, `worker_stats()`.
`submit` never blocks or throws, and **its callback runs exactly once**.

What `submit` does, in order:

1. Not started or stopping: **SERVFAIL**.
2. Source blocked: **REFUSED**.
3. Rate limiter says no: **REFUSED**, plus a rate-limit strike.
4. Name invalid: **FORMERR**.
5. Create a `Responder` (an atomic flag guards the exactly-once callback) and register its deadline.
6. **Coalesce:** if the same (name, type) is already in flight, join it and stop here.
7. **Load balancer** hands the job to a worker. If every worker refuses: **SERVFAIL** for all waiters
   (overload).
8. The worker resolves it, then every waiter gets a copy of the answer. If the deadline passes first, the
   timer answers **SERVFAIL**. Whichever comes first wins; the other is ignored.

Components:

| Component | Spec |
|---|---|
| `RateLimiter` | Token bucket per client address (`rate_limit_qps`, `rate_limit_burst`). A new client starts full. Buckets idle for 60 s are dropped. `qps = 0` turns it off |
| `InFlightTable` | Map from (name, type) to waiters. Names compare without case, so `example.com` and `Example.COM.` share one lookup |
| `Worker` | One thread, a bounded queue (`queue_capacity`, push never blocks), its own resolver chain. Tracks latency (EWMA) and failures |
| Circuit breaker | Closed → **Open** after `failure_threshold` consecutive failures (only SERVFAIL or an exception counts; NXDOMAIN is a success) → after `cooldown_ms`, **HalfOpen**: one probe decides whether it closes again |
| `LoadBalancer` | `round_robin`, `least_outstanding` (fewest queued, then lowest EWMA), `power_of_two` (two random workers, the less loaded wins). Tries a second choice before declaring overload |
| `DeadlineTimer` | One thread, a min-heap of deadlines holding weak references, so finished requests aren't kept alive. Fails late requests with SERVFAIL |
| `Metrics` | Lock-free counters: received, rate-limited, overload, timeouts, coalesced, resolver exceptions, replies per rcode, latency histogram (12 buckets) with p50/p95/p99 |
| `Config` | `key = value` file. Unknown or duplicate keys are errors with line numbers, every number is range-checked, cross-field rules (forwarding needs upstreams; protocol strikes > rate-limit strikes; cert and key set together); files named in the config must exist |
| `load_gen` | Drives `submit()` in-process with a stub resolver and reports throughput, metrics and per-worker breaker state; exits 1 if any query lost or doubled its answer |

### 3.5 Abuse blocking (Dhruv, inside the middleware): `BlockList`

- **Two kinds of strike:** *rate-limit* (from the middleware) and *protocol* (from the front-end).
  Each has its own threshold within `block_window_ms`; reaching it blocks the source for
  `block_duration_ms`.
- IPv4 is tracked per address, IPv6 per /64; `::ffff:a.b.c.d` counts as `a.b.c.d`.
- At most `block_max_entries` sources are tracked. When full, new sources are ignored and nobody is
  evicted, so existing blocks always stand.
- `is_blocked` and `report_abuse` **fail open**: an internal error never locks everyone out.

### 3.6 Front-end (Dhruv): `include/mw/{dot_server,tls_context,dot_framer,dns_message,admission}.hpp`

Full detail is in `docs/frontend.md` (architecture, connection life cycle, every decision). Summary:

| Area | Spec |
|---|---|
| Transport | DNS-over-TLS (RFC 7858) on TCP; default `0.0.0.0:853`, and `[::]` takes IPv4 too |
| TLS | OpenSSL 3, **TLS 1.3 only**, certificate chain plus key checked to match, ALPN `dot` accepted but not required, warning if the key file is readable by others |
| Framing | 2-byte length prefix; zero length is a protocol error |
| Parsing | Exactly 1 question, no answer/authority records, at most 1 additional (must be OPT). Names: letters, digits, `-`, `_`. Types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, ANY (others NOTIMP). Class IN only. EDNS version above 0 gets BADVERS |
| Replies | Echo ID, RD and the question in the client's spelling; answer, authority and additional sections; EDNS padding to 468-byte blocks when asked; falls back to SERVFAIL if a reply can't be encoded |
| Rejections | Blocked source: TCP reset before TLS. Unreadable message or not a query: close. Malformed: FORMERR. Unsupported: NOTIMP. Bad EDNS version: BADVERS. Blocked domain (and its subdomains): REFUSED |
| Protocol strikes | Zero-length frame, no readable ID / not a query, FORMERR, handshake that isn't TLS or uses a refused version. Not for NOTIMP, BADVERS, idle timeout, a hang-up mid-handshake or a certificate alert |
| Limits | 1000 connections; 32 per source; idle 10 s (covers the handshake; only whole messages count); 100 queries waiting per connection, then reading pauses; 256 KiB of unsent answers, or answers unread for 10 s, closes the connection |
| Threads | One epoll I/O thread; answers come back through a mailbox plus `eventfd` |
| Shutdown | SIGINT/SIGTERM: stop accepting, up to 2 s for outstanding answers to go out, then stop the middleware |

### 3.7 Configuration keys (`src/config.cpp`, `include/mw/config.hpp`)

| Key | Default | Range / values |
|---|---|---|
| `mode` | `forwarding` | `forwarding`, `recursive` |
| `upstreams` | none | IPs with optional port; required in forwarding mode |
| `records_file` | none | must exist if set |
| `workers` | 4 | 1–64 |
| `queue_capacity` | 256 | 1–100000 (per worker) |
| `request_timeout_ms` | 2500 | 50–30000 |
| `lb_policy` | `least_outstanding` | `round_robin`, `least_outstanding`, `power_of_two` |
| `failure_threshold` | 5 | ≥ 1 |
| `cooldown_ms` | 5000 | ≥ 100 |
| `rate_limit_qps` / `rate_limit_burst` | 0 (off) / 0 | burst ≥ 1 when qps > 0 |
| `block_rate_limit_strikes` / `block_protocol_strikes` | 0 (off) | protocol must be greater when both are set |
| `block_window_ms` | 10000 | 100–3600000 |
| `block_duration_ms` | 300000 | 1000–604800000 |
| `block_max_entries` | 100000 | 1–10000000 |
| `log_level` | `info` | `debug`, `info`, `warn`, `error` |
| `listen` | `0.0.0.0:853` | IP with optional port |
| `tls_cert`, `tls_key` | none | both or neither; the server needs both |
| `max_connections` | 1000 | 1–100000 |
| `max_connections_per_source` | 32 | 0–100000 (0 = no limit) |
| `idle_timeout_ms` | 10000 | 1000–300000 |
| `blocked_domains_file` | none | must exist if set |

### 3.8 Build and test

- C++23, CMake (presets: `local`, `release`, `asan`, `tsan`), GoogleTest fetched at configure time,
  OpenSSL 3. The team has moved to **GCC 15** (README and presets updated 2026-10-29).
- The DoT server is Linux-only (epoll/eventfd); everything else is guarded so it builds elsewhere.
- Binaries: `dns_server <config>`, `load_gen`, `dns_tests`.

---

## 4. Decisions to present

A professor rewards visible judgment. Pick **two per speaker** for the slides (marked ★); keep the
rest as backup for questions. The complete front-end list is in `docs/frontend.md`.

| # | Decision | Alternative rejected | Why | Owner |
|---|---|---|---|---|
| ★1 | DNS-over-TLS only, TLS 1.3 only | Plain DNS on port 53; TLS 1.2 | Privacy is the point; every TLS 1.3 suite is forward secret and authenticated | Dhruv |
| ★2 | Check blocked sources at accept(), **before** the TLS handshake (and again per query) | Check only after decrypting | A blocked attacker costs a TCP reset, not a TLS handshake. TCP means the source IP can't be spoofed | Dhruv |
| 3 | Pad replies to 468-byte blocks | No padding | TLS hides content, not size; size alone can reveal which site was looked up (RFC 8467 block size) | Dhruv |
| 4 | Two strike types; protocol threshold must exceed the rate-limit one | One shared counter | Honest clients sometimes fail a handshake; the config enforces the order | Dhruv |
| 5 | Name and type whitelists (others FORMERR/NOTIMP) | Accept anything | Small attack surface; also refuses zone transfers without a separate rule | Dhruv |
| 6 | Per-source connection cap, only whole messages count as activity, reset clients that stop reading | Global limits only | Stops one host exhausting the server (slowloris-style attacks) | divyanshu |
| ★7 | **Exactly one callback per query**, guaranteed by an atomic flag | Best-effort replies | Clients never hang; timeouts and overload become fast SERVFAILs | divyanshu |
| ★8 | Bounded per-worker queues that never block; full means SERVFAIL | Unbounded queues | Under overload, latency stays bounded instead of growing without limit | divyanshu |
| 9 | Coalesce identical in-flight queries | Resolve each separately | Popular names hit the resolver once | divyanshu |
| 10 | Circuit breaker per worker; NXDOMAIN counts as success | Retry everything | A failing resolver chain is taken out of rotation quickly | divyanshu |
| 11 | One resolver chain per worker | Shared resolver behind a lock | No lock contention, no shared state in resolvers | divyanshu |
| ★12 | Shared `types` namespace used by all three layers | Each layer with its own types | One definition of names, records and rcodes; no conversions between layers | Arnav |
| ★13 | Standard RFC 1035 zone files, including `$INCLUDE` and RFC 3597 generic records | A custom record format | Works with existing zone files and tools; any record type can be served | Arnav |
| 14 | Negative answers carry the SOA; empty non-terminals are NODATA, not NXDOMAIN | Bare NXDOMAIN | Correct negative caching (RFC 2308) and correct behaviour for names with children | Arnav |
| 15 | Resolvers chain through a fallback (hosts → zones → upstream) | One monolithic resolver | Each source is simple and testable on its own | Arnav |

---

## 5. What to highlight (and what to leave out)

**Highlight**

- **The rejection ladder** (front-end): a picture of the cheapest-first order. Reset before TLS →
  close → FORMERR/NOTIMP/BADVERS → REFUSED → middleware. It shows security thinking in one slide.
- **Exactly-once under overload** (middleware): the `load_gen` result. 100,000 queries in, 100,000
  answers out, with 77,836 shed as fast SERVFAILs because the stub was deliberately too slow (ledger L3).
- **Coalescing in numbers:** 20,968–28,438 queries per 100,000 shared another's lookup (L3, L4).
- **Circuit breakers working:** with 20% injected failures, all four workers tripped and every query was
  still answered (L5).
- **DNS correctness in the backend:** referrals, CNAME chains, wildcards, NODATA vs NXDOMAIN, each backed
  by tests (zone resolver: 36 tests; zone parser: 59).
- **Testing discipline:** 411 tests (L1), split 110/127/174 across the three areas. The front-end tests
  include real in-process TLS connections with a generated certificate.
- **The live demo** (section 7): encrypted query, blocked domain, padding, and an attacker getting blocked.

**Leave out of the main talk** (keep for questions): config parsing details, the metrics histogram,
TTL precedence rules, OpenSSL error handling, the mailbox/eventfd mechanics, the load-balancer tie-break
order.

**Don't claim:** that the server resolves real internet names (it uses a stub or zone files today), or any
throughput figure as network performance (section 8).

---

## 6. Run of show (15 minutes)

The order follows a query's path: front-end → middleware → backend. That gives a natural hand-over
between speakers. **Read the titles alone: they should tell the whole story.**

| # | Time | Speaker | Action title | Exhibit | Key points |
|---|---|---|---|---|---|
| 1 | 0:00–1:00 | Dhruv | Plain DNS shows the network every site you visit | A `dig` query in plain text vs over TLS | Privacy problem; DoT (RFC 7858) as the answer; encryption makes the server the target |
| 2 | 1:00–2:30 | Dhruv | One query crosses three layers, each built by one of us | Architecture diagram (3.1) | Front-end, middleware, backend; shared `types`; who owns what |
| 3 | 2:30–4:00 | Dhruv | TLS 1.3 encrypts every query, and padding hides reply sizes | TLS + padding diagram; 468-byte reply from the demo | TLS 1.3 only (★1); forward secrecy; padding to 468 bytes |
| 4 | 4:00–5:30 | Dhruv | Bad clients are rejected before they cost the server TLS work | The rejection ladder | Cheapest check first (★2); strikes → block; blocked domains get REFUSED |
| 5 | 5:30–6:30 | divyanshu | Connection limits stop one client exhausting the server | Limits table | Per-source cap, whole-message activity, stall reset (decision 6) |
| 6 | 6:30–8:00 | divyanshu | Every query gets exactly one answer, even under overload | `load_gen` result: 100,000 in, 100,000 out | Exactly-once (★7); bounded queues (★8); deadline timer |
| 7 | 8:00–9:00 | divyanshu | Identical queries are resolved once, and failing workers step aside | Coalescing count + breaker table | Coalescing; three LB policies; circuit breaker states |
| 8 | 9:00–10:30 | Arnav | The backend answers authoritatively from standard zone files | A small zone file and its answers | RFC 1035 parser (★13); generic records; shared types (★12) |
| 9 | 10:30–11:30 | Arnav | Referrals, CNAME chains and wildcards follow the DNS rules | Resolution decision flow | Zone cuts + glue; CNAME depth 8; wildcards; SOA in negative answers |
| 10 | 11:30–13:00 | Dhruv (drives), all | Live: an encrypted query, a blocked domain, and an attacker cut off | Terminal | Section 7 script |
| 11 | 13:00–14:00 | Arnav | 411 tests back the design; live upstream resolution is next | Test counts per area; status table | Honest status (section 8); next steps |
| 12 | 14:00–15:00 | all | Summary: private, hard to abuse, always answers | Three-line recap | Governing thought; thank you |

**If running long:** merge slides 5 and 4, or drop slide 9 to backup. **If the demo fails:** switch to the
recorded fallback at once (section 7) and don't debug live.

**Appendix (backup slides):** config keys (3.7); the full decisions table (4); circuit breaker state
diagram; zone file features list; the strike table; the known-issues list (8).

---

## 7. Demo plan

**Setup (before the talk)** — needs a built `dns_server` (GCC 15, or g++-14 with the stand-in patch from
the code review), `dig` 9.18+ and `nc`. Dry-run on 2026-10-29 against a scratch build: every step below
worked as described.

```sh
mkdir demo && cd demo
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout server.key -out server.pem -days 30 -subj /CN=localhost
chmod 600 server.key
printf 'ads.example\n' > blocked.txt
cat > demo.conf <<'EOF'
mode = recursive
listen = 127.0.0.1:8853
tls_cert = server.pem
tls_key = server.key
blocked_domains_file = blocked.txt
block_protocol_strikes = 2
block_duration_ms = 15000
log_level = info
EOF
../build/local/dns_server demo.conf        # leave running in a visible terminal
```

**Script (about 90 seconds)**

| Step | Command | What the audience sees | Say |
|---|---|---|---|
| 1 | `dig @127.0.0.1 -p 8853 +tls +short example.com` | `127.0.0.1` | "An encrypted query and its answer. The answer comes from our stand-in resolver; live upstream resolution is next." |
| 2 | `dig @127.0.0.1 -p 8853 +tls x.ads.example` | `status: REFUSED` | "A subdomain of a blocked name: refused, and the connection stays open." |
| 3 | `dig @127.0.0.1 -p 8853 +tls +padding=468 example.com` | `MSG SIZE rcvd: 468` | "Padded to a fixed size, so the size gives nothing away." |
| 4 | Run twice: `printf 'GET / HTTP/1.1\r\n\r\n' \| nc -q1 127.0.0.1 8853` | Server log: `blocking 127.0.0.1 for 15000 ms` | "Something that isn't TLS: two strikes, and the source is blocked." |
| 5 | `dig @127.0.0.1 -p 8853 +tls +tries=1 example.com` | `connection reset` | "Now it's cut off before any TLS work." |
| 6 | Ctrl-C the server | Log: `SIGINT received, shutting down` | "Graceful shutdown." |

**Fallback:** record the demo once (screen recording) on the presenting laptop the day before and have
it open. Wait 15 s after step 5 before re-running, or the block is still active.

**Optional extra (backup only):** `./build/release/load_gen --stub-delay-ms 0` shows the metrics report.

---

## 8. Status, evidence and honest limitations

**Works and is tested**

- DoT front-end end to end with `dig` (demo dry-run, L6), 110 tests.
- Middleware pipeline: exactly-once delivery, overload shedding, coalescing, breakers (L3–L5), 127 tests.
- Backend: zone-file parsing and authoritative resolution, hosts file, 174 tests.

**Not finished: say so plainly, next to the claim it limits**

| Limitation | Effect | Where to mention it |
|---|---|---|
| `ForwardingResolver`, `RecursiveResolver` and `Cache` are declared but empty; the server is wired to the **stub resolver** (`make_factory` ignores `mode` and `upstreams`) | The server can't resolve real internet names yet; demo answers are `127.0.0.1` | Slides 1, 10, 11 |
| `main` at `3bfa887` doesn't compile: a `noexcept` mismatch on `DomainName::parent()` breaks every compiler, and `append_range` / `ranges::ends_with` need GCC 15 | Must be fixed before the demo build; all numbers here come from a scratch copy with those spots patched for g++-14 | Fix before presenting (section 12) |
| The `load_gen` throughput is in-process, with a stub resolver and no network or TLS | It measures middleware overhead, not server performance | Slide 6 (say it) |
| Example config sets `records_file = config/records.txt`, which doesn't exist | `dns_server config/middleware.example.conf` won't start | Fix, or don't show it |
| Smaller issues from the code review: a wire name one byte over the limit is accepted; hosts-file trailing comments become names; `nan`/`inf` accepted in config; the IPv6 rate limit is per address while blocking is per /64; blocked-domain and FORMERR replies skip the rate limiter | None affect the demo | Backup / Q&A only |

---

## 9. Q&A prep

| Question | Short answer | Who | Backup |
|---|---|---|---|
| Why DoT and not DoH? | DoT is DNS's own protocol on its own port (RFC 7858), simpler to implement and reason about. DoH hides inside HTTPS but needs an HTTP stack. A good extension | Dhruv | — |
| Why TLS 1.3 only? Won't old clients break? | Every 1.3 suite is forward secret and authenticated; DoT clients are modern. We chose security over compatibility | Dhruv | Decisions |
| Can an attacker spoof an IP to get someone else blocked? | Not over TCP: the handshake proves the address. That's why IP-based blocking is safe here and wouldn't be over UDP | Dhruv | Strike table |
| Doesn't blocking punish many users behind one NAT? | Yes, a real trade-off. Blocking is off by default; thresholds and the per-source cap are configurable | Dhruv / divyanshu | Config keys |
| Why is padding 468 bytes? | The response block size recommended by RFC 8467 | Dhruv | — |
| What does "exactly once" mean, and how do you know? | An atomic flag lets only the first of (answer, timeout, overload) run the callback. Tests check it, and `load_gen` exits non-zero if any reply is lost or doubled | divyanshu | Slide 6 |
| Why not just make the queues bigger? | Bigger queues only delay failure: latency grows without limit. A fast SERVFAIL lets the client retry elsewhere | divyanshu | — |
| How is 280–320k queries/s possible? Is it real? | It's in-process with a stub resolver: middleware overhead only, no network, no TLS. We don't claim it as server throughput | divyanshu | Ledger L4 |
| Why does NXDOMAIN count as success for the breaker? | The resolver worked; the name just doesn't exist. Only SERVFAIL or an exception means the chain is unhealthy | divyanshu | — |
| How do you choose a load-balancing policy? | Least-outstanding by default; power-of-two is cheaper at scale; round-robin for uniform workloads. Configurable | divyanshu | — |
| How do you handle CNAME loops? | A depth limit of 8, then SERVFAIL | Arnav | Slide 9 |
| What's the difference between NODATA and NXDOMAIN? | NXDOMAIN: the name doesn't exist. NODATA: it exists, but not with that type (or it has only children). Both carry the SOA so resolvers can cache the negative answer | Arnav | — |
| Why can't the server resolve google.com? | Upstream forwarding and recursion aren't built yet; that's the next milestone. The interfaces are in place | Arnav | Status |
| How did you split the work and integrate it? | By layer, with agreed interfaces (`submit`, `is_blocked`, `report_abuse`, `Resolver`) and shared types, so each layer could be tested with fakes before the others existed | all | Slide 2 |
| What would you do with more time? | Forwarding and recursive resolvers with a cache; DoH; fix the known issues; benchmark over the network with TLS | all | Status |

---

## 10. Weakest points and per-member coverage

**Weakest points** (everyone rehearses these answers):

1. **"It doesn't resolve real names."** Answer: correct. Serving, security and traffic control are done and
   tested, the backend answers authoritatively from zone files, and upstream resolution is the planned next
   step behind an interface that already exists.
2. **"The build is broken / the throughput number is synthetic."** Answer: fix the build before the talk
   (section 12). Present the throughput with its conditions, or leave it out.
3. **"Did each of you really do your part?"** Answer with the contribution table (section 2) and the test
   counts per area. Each speaker presents their own layer.

**Know beyond your own part**

- **Dhruv:** exactly-once and why bounded queues; what coalescing is; NODATA vs NXDOMAIN.
- **divyanshu:** why blocks happen before TLS; what padding hides; zone cuts and referrals in one sentence.
- **Arnav:** the rejection ladder; the strike types; what the circuit breaker does.

---

## 11. Evidence ledger

| ID | Number / claim | Source |
|---|---|---|
| L1 | 411 tests, all passing, 8 runs in a row | `dns_tests` from a scratch copy of `3bfa887` with the build break patched for g++-14, run 2026-10-29. Count = `TEST(` macros in `tests/test_*.cpp` |
| L2 | Per-area test counts 110 / 127 / 174 | `TEST(` counts per file in `tests/`, grouped by the author who created each file (git) |
| L3 | Default `load_gen`: 100,000 submitted, 100,000 answered, 77,836 overload, 20,968 coalesced, 1.528 s | `load_gen` (defaults: 8 threads, 4 workers, queue 256, stub delay 5 ms), release build of the same scratch copy, Intel Core Ultra 5 125H, 2026-10-29 |
| L4 | No-delay `load_gen`: 322,959 and 277,291 submits/s in two runs; p50 5 ms, p95 10 ms, p99 20 ms; 28,438 coalesced; 8,821 overload | `load_gen --stub-delay-ms 0`, same build and machine |
| L5 | With 20% injected failures: 20,000/20,000 answered, every worker's breaker tripped once, exit code 0 | `load_gen --stub-fail-rate 0.2 --queries 20000`, same build and machine |
| L6 | Demo: answer `127.0.0.1`; REFUSED for `x.ads.example`; 468-byte padded reply; block after 2 non-TLS connections; reset afterwards; graceful SIGINT | Dry run of section 7 against the scratch `dns_server`, `dig` 9.18.39, 2026-10-29 |
| L7 | Config defaults and ranges | `include/mw/config.hpp`, `src/config.cpp` |
| L8 | Front-end limits (1000, 32, 10 s, 100, 256 KiB) | `include/mw/dot_server.hpp`, `include/mw/config.hpp` |
| L9 | CNAME depth 8, `$INCLUDE` depth 10, compression jumps 128 | `src/backend/ZoneFilesResolver.cpp`, `src/backend/ZoneFile.cpp`, `src/DomainName.cpp` |

---

## 12. Open items before presenting

1. **Approve the storyline:** the governing thought (section 1) and the slide titles (section 6). Change
   them now, before slides are built.
2. **Confirm contributions:** each member checks their row in section 2, including the `.clang-format`
   question.
3. **Fix the build:** the `noexcept` mismatch in `src/DomainName.cpp` (Arnav's file), then build with
   GCC 15 and re-run the tests and demo on the presenting laptop.
4. **Decide on the throughput number:** show it with its conditions, or keep it as backup only.
5. **Check the course rules:** whether AI-assisted material must be declared, and how marks are split per
   member. No rubric was found in the repository.
6. **Confirm the format:** whether the 15 minutes include Q&A. This plan assumes 15 minutes of talk.
