# encrypted-dns-resolver

A DNS-over-TLS (DoT, RFC 7858) resolver written in C++23 for Linux.

Clients such as `dig +tls`, `kdig` or Android's "Private DNS" send encrypted queries on port 853. The server
answers them from a local records file, a shared cache, public upstream resolvers (**forwarding**), or by
walking down from the root servers itself (**recursive**). Forwarding can be encrypted too: a `tls://`
upstream is asked over DNS-over-TLS, with its certificate checked on every connection, so a query can stay
encrypted from the client all the way to Cloudflare or Google (see [5.5](#55-encrypted-upstreams-dns-over-tls-tlsclient)). A web dashboard shows what's happening live and
has built-in tests for lookups, load, abuse and failures.

The project has three layers, each with one job:

| Layer | Job | Code |
|---|---|---|
| **Front end** | Speak encrypted DNS to clients: TLS, framing, parsing, validating, encoding, padding | `src/dot_server.cpp`, `tls_context`, `dot_framer`, `dns_message`, `admission` |
| **Middleware** | Decide *whether*, *when* and *where* a query is resolved: rate limiting, blocking, coalescing, deadlines, queues, load balancing, circuit breakers | `include/mw/`, `src/middleware.cpp`, `worker`, `load_balancer`, ... |
| **Backend** | Find the actual answer: records file, cache, forwarding (plain or over TLS, certificates checked), recursion | `include/backend/`, `src/backend/` |

The layers talk through two narrow interfaces. The front end calls `Middleware::submit(name, type, client,
callback)`, and the middleware calls `backend::Resolver::resolve(name, type, class)`. Each layer can be
built, tested and replaced on its own. The middleware was developed against a stub resolver before the real
resolvers existed, and the front end against a fake middleware.

---

## Contents

1. [Architecture](#1-architecture)
2. [What happens to one query](#2-what-happens-to-one-query)
3. [Front end](#3-front-end)
4. [Middleware](#4-middleware)
5. [Backend (resolvers)](#5-backend-resolvers)
6. [Cross-cutting choices](#6-cross-cutting-choices): threads, errors, C++23, observability, testing
7. [Admin dashboard](#7-admin-dashboard)
8. [Capacity, and why SERVFAIL appears under heavy load](#8-capacity-and-why-servfail-appears-under-heavy-load)
9. [Known limitations and future work](#9-known-limitations-and-future-work)
10. [Configuration and tuning](#10-configuration-and-tuning)
11. [Building, testing, running the demo](#11-building-and-testing)

---

## 1. Architecture

```
                       DoT clients (dig +tls, kdig, Android "Private DNS", ...)
                                         │  TCP 853, TLS 1.3
                                         ▼
 ┌──────────────────────────── FRONT END  (1 epoll thread) ─────────────────────────────────┐
 │  accept ─► source blocked? ─► TCP reset (no TLS work)                                      │
 │  TLS 1.3 handshake (OpenSSL) ─► DotFramer: 2-byte length prefix ─► parse_query()           │
 │        │ malformed → FORMERR / NOTIMP / BADVERS          (+ protocol strike)               │
 │        │ blocked domain (Admission) → NXDOMAIN                                             │
 │        ▼                                                                                   │
 │  Middleware::submit(name, type, client, callback)                                          │
 │        ▲                                                                                   │
 │        └── Mailbox + eventfd ◄── callback (any thread): encode_response(), pad to 468 B    │
 │            I/O thread wakes, frames, SSL_write()s the answer on the right connection       │
 └────────┬─────────────────────────────────────────────────────────────────────────────────┘
          ▼
 ┌───────────────────────────────────── MIDDLEWARE ─────────────────────────────────────────┐
 │  BlockList.is_blocked?  ──────────────────────────────────────────► REFUSED               │
 │  RateLimiter (token bucket per client) ─ over the rate ──────────► REFUSED + strike       │
 │  Responder (owns the callback, atomic "done": answers exactly once)                       │
 │  DeadlineTimer (min-heap, 1 thread) ─ now + request_timeout ─────► SERVFAIL "timed out"   │
 │  InFlightTable.attach(name, type)                                                         │
 │     ├─ already in flight → follower: waits for the leader's answer      (coalescing)      │
 │     └─ first → leader ─► LoadBalancer ─ all full / all breakers open ─► SERVFAIL          │
 └────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                          ▼
     ┌──────── Worker 0 ────────┐  ┌──────── Worker 1 ────────┐        ┌──── Worker N-1 ──────┐
     │ BoundedQueue (FIFO)      │  │ BoundedQueue             │  ...   │ BoundedQueue         │
     │ circuit breaker          │  │ circuit breaker          │        │ circuit breaker      │
     │ 1 jthread, blocking      │  │ 1 jthread                │        │ 1 jthread            │
     │ own ResolverChain ───────┼──┼──────────────────────────┼────────┼──────────────────────┤
     └──────────────────────────┘  └──────────────────────────┘        └──────────────────────┘
                                          │
 ┌──────────────────────────────────── BACKEND (one chain per worker) ───────────────────────┐
 │  fault injection (demo) ─► records file (hosts / .zone) ─► SwitchedResolver               │
 │                                                              │                            │
 │                     ┌──────── shared Cache (RRsets + TTL, shared_mutex) ────────┐         │
 │                     │ hit → answer straight away                                │         │
 │                     └──────────────────────────┬────────────────────────────────┘         │
 │                                         miss   │                                          │
 │              ┌─────────────────────────────────┴───────────────────────────┐              │
 │              ▼                                                             ▼              │
 │   ForwardingResolver                                          RecursiveResolver           │
 │   tls:// → DoT, certificate checked; else UDP/TCP             root → TLD → authoritative  │
 │   last good upstream asked first (shared)                     referrals, CNAMEs, bailiwick│
 └───────────────────────────────────────────────────────────────────────────────────────────┘

 Side door: AdminServer (HTTP, loopback only), its own threads. Reads metrics, the query log and breaker
 states; runs the Lookup / Compare / Traffic / Load / Abuse / Failures tests through Middleware::submit.
```

### Threads

| Thread | How many | Does what | Blocks on |
|---|---|---|---|
| Front-end I/O | 1 | every client socket, TLS, parsing, encoding replies | `epoll_wait` |
| Worker | `workers` (1–64) | one resolve at a time from its own queue | its queue, then upstream sockets |
| Deadline timer | 1 | fails queries whose deadline passed | a condition variable until the next deadline |
| Admin | 1 accept + 1 per request/test | dashboard API and tests | `poll`, HTTP sockets |
| Main | 1 | starts everything, then waits for SIGINT/SIGTERM | `sigwait` |

The split is deliberate. Network I/O to clients is many slow, mostly idle connections, which suits one
event loop. Resolving is a few CPU-light but latency-heavy calls, which suits a pool of threads. A queue
separates the two, so a slow upstream can never stall the socket loop.

---

## 2. What happens to one query

1. **Connect.** `accept()` runs on the I/O thread. A source on the block list gets a TCP reset straight
   away, before any TLS work. Overall and per-source connection limits apply here too.
2. **Handshake.** TLS 1.3 is negotiated non-blockingly. A client that sends something that isn't TLS, or
   offers an old version, gets a *protocol strike*.
3. **Frame.** Decrypted bytes go into a `DotFramer`, which cuts them into messages by their 2-byte length
   prefix (RFC 1035 §4.2.2). Many queries can arrive back to back on one connection (pipelining).
4. **Parse and validate.** `parse_query()` checks the header, section counts, name syntax, type, class and
   EDNS. A broken query gets FORMERR (plus a strike), an unsupported one NOTIMP, and EDNS version > 0 gets
   BADVERS.
5. **Policy.** `Admission` answers NXDOMAIN for names on the blocked-domains list, and for anything under them.
6. **Submit.** The front end calls `Middleware::submit()` with a callback that encodes the answer.
7. **Admit.** The middleware checks the block list and the client's token bucket. Over the rate means
   REFUSED plus a *rate-limit strike*, and enough strikes in a window blocks the source.
8. **Deadline.** A `Responder` is created to own the callback, and the deadline timer is armed.
9. **Coalesce.** If the same (name, type) is already being resolved, the query just joins that lookup.
10. **Queue.** Otherwise the load balancer puts a job on a worker's bounded queue. If every queue is full or
    every breaker is open, the query gets SERVFAIL ("overloaded") immediately.
11. **Resolve.** The worker skips the job if its deadline has already passed. Otherwise it runs its resolver
    chain: fault injection, then the records file, then the cache, then forwarding or recursion.
12. **Fan out.** Every waiter for that key gets a copy of the answer. If the timer fires first they get
    SERVFAIL, and whichever comes second is ignored.
13. **Reply.** The callback encodes and pads the reply on whatever thread it runs on and posts it to the
    front end's mailbox. The I/O thread wakes, frames it, encrypts it and sends it.

---

## 3. Front end

### 3.1 Transport: DNS over TLS on one epoll thread

**What's used:** Linux `epoll` in level-triggered mode, non-blocking sockets, one thread (`DotServer::Impl`).
Each connection is a small struct holding its `SSL*`, a framer, a buffer of unsent bytes, a pending-query
count and timestamps.

**Why:**
- **DoT rather than plain DNS or DoH.** DoT is DNS's own wire format inside TLS on a dedicated port. It needs
  no HTTP stack, and `dig`, `kdig`, systemd-resolved and Android support it natively. Plain DNS (UDP 53)
  is readable and forgeable by anyone on the path, which is exactly what this project is meant to fix. DoH
  would add HTTP/2 framing for the same privacy.
- **One event loop instead of a thread per connection.** DoT clients keep connections open and are idle most
  of the time. A thread per connection would mean thousands of sleeping threads with their own stacks. One
  loop handles them all with a few KB each, and the expensive work (resolving) happens elsewhere anyway.
- **Not Boost.Asio or libuv.** Raw epoll plus OpenSSL keeps the dependencies at OpenSSL alone and makes every
  state transition visible and testable, including `WANT_READ`/`WANT_WRITE`, pausing and resets.
- **Level-triggered.** It's simpler to get right with TLS, because OpenSSL may hold buffered bytes that edge
  triggering would never report again.

**Getting answers back to the I/O thread.** A middleware callback can run on any thread: a worker, the
deadline timer, or even inside `submit()` itself. It must not touch the connection. Instead it encodes the
reply and posts `(connection id, bytes)` to a **mailbox** (a mutex-guarded vector), then writes to an
**eventfd** that the epoll loop watches. The I/O thread wakes, takes the whole batch and sends each reply on
its connection. If the client left in the meantime, the reply is dropped. The mailbox is held by
`shared_ptr`, so a callback that fires after shutdown still has a valid eventfd to write to.

**TCP details:**
- `TCP_NODELAY` is set, because answers are small and latency matters.
- Resets are done with `SO_LINGER` 0, so a dropped client leaves no `TIME_WAIT` state behind.
- `[::]` is opened dual-stack, and IPv4-mapped peers are reported as plain IPv4 so that blocking and limits
  see one identity.

### 3.2 TLS (`TlsContext`)

| Choice | Why |
|---|---|
| **OpenSSL 3** | It's the standard, audited library, available everywhere as `libssl-dev`. Writing TLS yourself is never the right call. |
| **TLS 1.3 only** (min = max = 1.3) | Every 1.3 cipher suite uses ephemeral ECDHE (forward secrecy) and AEAD encryption. There are no weak suites or downgrade paths to configure. DoT clients that are new enough to speak DoT all support 1.3. |
| **`SSL_MODE_ENABLE_PARTIAL_WRITE \| ACCEPT_MOVING_WRITE_BUFFER`** | The loop retries writes from a buffer that may have grown or moved since. Without these flags OpenSSL rejects the retry. |
| **ALPN "dot" accepted, not required** | Clients that offer it get it confirmed (RFC 7858 recommends it), and clients that don't still work. |
| **Key-file permission check at startup** | It warns if the private key is readable by group or others. Mistakes with key files are common, and this one is cheap to catch. |
| **Cert/key mismatch reported clearly** | "tls_key does not match tls_cert" is much more useful than an OpenSSL error string. |

### 3.3 Framing (`DotFramer`)

DNS over a stream prefixes each message with its 2-byte length. The framer buffers whatever TLS hands it
and yields complete messages one at a time, or "need more data". A zero-length frame is **invalid**, which
earns a protocol strike and closes the connection. It's a separate class with no sockets in it, so the
awkward cases (a message split across reads, several messages in one read, a frame cut off mid-length) can be
unit tested on their own.

### 3.4 Parsing, validating and encoding (`dns_message`)

**What's used:** a hand-written parser and encoder over `std::span<const std::byte>`, returning
`std::expected<DnsQuery, ParseError>`.

| Choice | Why |
|---|---|
| **Hand-written, bounds-checked parser** | The message comes from an untrusted network. Every read is checked against the span, so a hostile packet can't read past the message. Compression pointers are followed with loop and length limits. |
| **`std::expected` instead of exceptions** | A malformed query is a normal outcome, not an exceptional one. The error carries the rcode to answer with and the query ID if one could be read, so the front end knows whether it *can* reply. |
| **Precise error replies** | FORMERR for a broken query, NOTIMP for an unsupported opcode/class/type, BADVERS for EDNS version > 0. A clear code tells the client what to fix, where silence makes it retry. |
| **Strict name syntax** (letters, digits, `-`, `_`) | It rejects junk early. `_` is allowed because SRV and DKIM names use it. |
| **Case kept in the reply** | Names are compared case-insensitively, but the reply echoes the client's spelling. Some resolvers randomise case ("0x20") as an anti-spoofing check. |
| **Encoder always produces a valid message** | If an answer can't be encoded (too big, for example), it falls back to a SERVFAIL reply instead of sending nothing. |
| **Padding to 468-byte blocks** (RFC 7830 / RFC 8467) | TLS hides content but not length, and the size of an answer can reveal which site was looked up. When the client asks for padding with the EDNS Padding option, replies are padded to a multiple of 468 bytes, the size RFC 8467 recommends for responses. |

### 3.5 Policy and abuse at the front door

| Choice | Why |
|---|---|
| **Blocked sources reset at `accept()`, before TLS** | The handshake is the most expensive thing a client can make us do: asymmetric crypto plus several round trips. A blocked client should cost a `close()`. They are checked again before each query, in case the block started mid-connection. |
| **Blocked domains answered NXDOMAIN, no strike** (`Admission`) | Asking for an ad domain isn't abuse. The name looks nonexistent, so the client doesn't retry at another resolver (REFUSED would make it), and it keeps its connection. A listed name also covers every name under it, checked by walking parents up to the root, so `doubleclick.net` blocks `ad.doubleclick.net`. |
| **Protocol strikes for real protocol abuse only** | Not TLS, an old TLS version, a zero-length or ID-less message, a response instead of a query, FORMERR. A client that just disconnects, rejects our certificate, or asks for an unsupported type gets **no** strike, because port scanners, health checks and old clients do these innocently. |
| **Per-connection limits** | Up to 100 queries pending per connection (above that, reading pauses until answers go out, which is back-pressure rather than dropping), 256 KiB of unsent answers (a client that never reads is closed), and an idle timeout that also covers a half-finished handshake or message. Only *whole* messages count as activity, so trickling one byte at a time ("slowloris") can't hold a connection open. |
| **Connection limits** (1000 total, 32 per source) | One host can't take every slot. IPv6 is counted per /64, because one device usually owns a whole /64 and per-address counting would let it rotate addresses for free. |
| **Graceful stop** | New connections are refused at the kernel. Answers already being looked up get a grace period to go out, then everything is closed. |

The front end's full rejection table is in [`docs/frontend.md`](docs/frontend.md).

---

## 4. Middleware

The middleware's contract is one function:

```cpp
void submit(std::string_view name, RecordType type, ClientInfo client, ResultCallback cb) noexcept;
```

**The callback runs exactly once**, whatever happens: an answer, a timeout, overload, an exception, a
shutdown. It's `noexcept` so the front end never has to guard the call. Everything below exists to keep
that promise while protecting the server from overload and abuse.

### 4.1 Responder: exactly-once delivery

**What's used:** a `Responder` object (always in a `shared_ptr`) that owns the callback and an
`std::atomic<bool> done`. `complete()` and `fail()` both do `done.exchange(true)`, and only the caller
that flipped it runs the callback and records the reply in the metrics.

**Why:** a real answer and the deadline can race on two different threads. Without a single atomic
gatekeeper you get either two replies, which corrupts the client's view, or none, which leaves the client
hanging. Locking the whole path would serialise everything for the sake of one rare race. An atomic
exchange settles it in one instruction.

### 4.2 Deadlines (`DeadlineTimer`)

**What's used:** one background `std::jthread` with a min-heap (`std::priority_queue`) of
`(deadline, weak_ptr<Responder>)`. It sleeps on a condition variable until the earliest deadline, or until
an earlier one is scheduled, then fails every expired responder with SERVFAIL "timed out".

| Choice | Why |
|---|---|
| **A deadline on every query** (`request_timeout_ms`) | A dead upstream must not leave clients hanging forever. A fast SERVFAIL lets a stub resolver retry or fail over to another server. |
| **One timer thread and a heap, not a timer per query** | Thousands of queries in flight would mean thousands of timers. A heap gives O(log n) insertion and wakes only for the next deadline. |
| **`weak_ptr` in the heap** | A query that was answered on time is freed straight away instead of lingering until its deadline. |
| **Callbacks run outside the heap's lock** | A callback runs front-end code that may call `submit()` again and schedule a new deadline. Doing that under the lock would deadlock. |
| **Real steady clock in the timer, injectable clock elsewhere** | `wait_until` needs real time, while the rest of the middleware takes a `Clock` function so tests can move time by hand. |

### 4.3 Request coalescing (`InFlightTable`)

**What's used:** `unordered_map<QueryKey, vector<shared_ptr<Responder>>>` under a mutex. `attach()`
returns true for the first query of a key (the **leader**, which must schedule a job) and false for
everyone else (**followers**, who just wait). When the lookup finishes, `take()` removes the entry and
returns every waiter, and each gets a copy of the result.

**Why:**
- Popular names arrive in bursts. When `google.com` expires from the cache and 500 clients ask in the same
  second, coalescing turns that into **one** upstream query instead of 500 (no "cache stampede").
- It saves worker time too, which is the scarce resource (see [section 8](#8-capacity-and-why-servfail-appears-under-heavy-load)).
- The key is the **normalised** name plus type (absolute, case-insensitive), so `Example.COM` and
  `example.com.` coalesce together.
- Waiters are completed **after** the lock is released, for the same deadlock reason as the timer.

### 4.4 Rate limiting (`RateLimiter`)

**What's used:** a **token bucket per client address**. Each bucket refills at `rate_limit_qps` tokens per
second up to `rate_limit_burst`, and each query takes one token. A new client starts with a full bucket.
Idle buckets (60 s) are swept every 1024 calls.

**Why a token bucket:** it allows the short bursts real clients make, like a page load firing 30 lookups at
once, while capping the *sustained* rate. A fixed-window counter is burstier at window edges, and a
sliding log costs memory per query. A bucket is two numbers per client. Sweeping keeps memory bounded when
an attacker cycles through addresses.

**Why REFUSED rather than SERVFAIL:** REFUSED means "you're not allowed", so a client won't hammer us by
retrying. SERVFAIL means "try again".

### 4.5 Blocking (`BlockList`)

**What's used:** a map from source to `{rate-limit strikes, protocol strikes, window start, blocked until}`,
under a `std::shared_mutex` (many readers, few writers). Keys are the 4 address bytes for IPv4, or the
8-byte /64 prefix for IPv6.

| Choice | Why |
|---|---|
| **Strikes within a window, then a timed block** | Being refused once means a client is busy. Being refused 50 times in 10 s means it's abusive. Blocks expire on their own, so a mistake heals without an operator. |
| **Two strike kinds with separate limits** | Rate-limit strikes come from the middleware and protocol strikes from the front end. Protocol limits are set *higher*, because honest clients do occasionally fail a handshake. |
| **`shared_mutex`** | `is_blocked()` runs on every connection and every query, while strikes are rare. Readers shouldn't queue behind each other. |
| **Bounded size, newcomers dropped when full** | Evicting someone to make room would let an attacker flush existing blocks by spraying new addresses. Dropping the newcomer keeps every block in place. |
| **IPv6 per /64, `::ffff:a.b.c.d` = `a.b.c.d`** | One identity per real client, whatever the socket reports. |
| **Fails open** | If a strike can't be recorded (allocation failure), it's skipped. The DNS service matters more than one strike. |
| **`unblock()`** | The dashboard and operators can lift a block early. |

### 4.6 Workers, queues and the threading choice

**What's used:** `workers` instances of `Worker`, each with its own `std::jthread`, its own
`BoundedQueue<Job>` (mutex + `condition_variable_any` + `deque`, fixed capacity) and **its own resolver
chain**. The thread pops a job, resolves it with a *blocking* `resolve()` call, hands the result back and
repeats.

| Choice | Why |
|---|---|
| **Blocking resolvers on a thread pool** | The resolvers are plain synchronous code: `resolve()` returns the answer. That keeps forwarding, recursion with nested lookups, zone files and the cache simple to write, read and unit test without callbacks or coroutines. Parallelism comes from the number of workers. The trade-off is throughput (see [section 8](#8-capacity-and-why-servfail-appears-under-heavy-load)). |
| **A queue per worker, not one shared queue** | The load balancer can see each worker's load and route away from a slow or broken one, and each worker can have its own circuit breaker. One shared queue would hide which worker is struggling. |
| **Bounded queues; `try_push` never blocks** | An unbounded queue turns overload into unbounded latency and memory: queries wait minutes for answers nobody wants any more. A bounded queue turns overload into an immediate, cheap SERVFAIL. |
| **Expired jobs skipped** ("expired in queue") | If the deadline has passed, the client has already had SERVFAIL. Resolving anyway is wasted work that only makes the backlog worse. |
| **Every worker owns its resolver chain** | Resolvers aren't thread safe and don't need to be: no locks inside forwarding or recursion. Only the cache is shared. |
| **`std::jthread` + `stop_token`** | Clean, automatic shutdown: the destructor requests a stop and joins, and `pop()` wakes on the stop token. |
| **Resolver exceptions caught per job** | A throwing resolver becomes SERVFAIL "resolver threw" for that query, counted in the metrics. The worker thread lives on. |
| **EWMA of latency** | Each worker keeps an exponentially weighted moving average of how long it takes, which the load balancer uses as a tie-breaker. |

### 4.7 Load balancing (`LoadBalancer`)

Three policies, chosen with `lb_policy`. Every policy returns a **first choice and a fallback**, so one
full queue doesn't fail a query while another worker has room. Workers whose breaker is open are skipped.

| Policy | How it picks | Why you'd use it |
|---|---|---|
| `least_outstanding` (default) | fewest jobs outstanding, then lowest EWMA latency, then lowest id | Routes around a worker stuck on a slow upstream. The best choice when job times vary a lot, which is always true for DNS. |
| `power_of_two` | two random workers, the less loaded wins | Almost as good as least-outstanding, with less work per pick: the classic "power of two choices" result. Scales better with many workers. |
| `round_robin` | next in turn | The simple baseline, so the other two can be compared against it. |

### 4.8 Circuit breakers

Each worker has a three-state breaker:

```
            failure_threshold SERVFAILs in a row
  CLOSED ──────────────────────────────────────► OPEN ── cooldown_ms ──► HALF-OPEN
    ▲                                              ▲                        │ one probe job
    │              probe succeeds                  │      probe fails       │
    └──────────────────────────────────────────────┼────────────────────────┘
                                                   └────────────────────────┘
```

| Choice | Why |
|---|---|
| **Per worker** | Workers can be switched between resolvers, and failures cluster (a dead upstream, a broken path). A failing worker stops taking jobs, so queries go to healthy ones instead of waiting out timeouts. |
| **Only SERVFAIL and exceptions count** | NXDOMAIN and NODATA are correct answers, not failures. |
| **One probe in half-open** | The breaker tests recovery with one query instead of letting a whole flood back onto a resolver that may still be broken. |
| **"Expired in queue" doesn't count** | That's overload, not the resolver's fault. If the expired job was the probe, the breaker reopens with no cooldown so the probe slot isn't lost. |
| **A failed `try_push` gives the probe back** | Otherwise a full queue would leave the breaker stuck in half-open forever. |

### 4.9 Shutdown and failure handling

- `stop()` waits up to a drain timeout for in-flight queries, stops the workers, fails anything left with
  SERVFAIL "shutting down" and stops the timer. Every outstanding callback still runs once.
- `submit()` catches everything. Before the `Responder` exists, the callback is answered directly. After
  that, the responder owns it. A leader that fails also fails all its followers.
- Shutdown order in `main`: admin page, then front end (2 s grace for answers to go out), then middleware.
  The admin page goes first because its requests use the middleware.

---

## 5. Backend (resolvers)

### 5.1 One interface, composed into a chain

```cpp
class Resolver {
  virtual ResolveResult resolve(const DomainName&, RecordType, RecordClass, bool recurse = true) = 0;
};
```

Every resolver implements this one method, and resolvers wrap each other. `make_factory()` builds **one
chain per worker**:

```
ResolverChain
  └─ fault injection (dashboard's Failures test; off by default)
      └─ records file: HostsFileResolver, or ZoneFilesResolver for a .zone file    (if records_file is set)
          └─ SwitchedResolver: picks one option at run time
              ├─ ForwardingResolver(configured upstreams)   ─┐
              ├─ ForwardingResolver(8.8.8.8 only)  ...       │
              ├─ ForwardingResolver(1.1.1.1 over TLS) ...    ├─ all share one Cache
              └─ RecursiveResolver(root servers)            ─┘
```

**Why a chain of one interface:** each piece does one thing and is tested alone. Swapping forwarding for
recursion, or adding a records file, means changing the chain, not the code. `ResolveResult.served_by`
records which piece answered ("cache", "records file", "upstream 1.1.1.1:53",
"upstream 1.1.1.1:853 (cloudflare-dns.com) over TLS", "recursive", or why it failed). That label is what the dashboard shows.

### 5.2 Local records (`HostsFileResolver`, `ZoneFilesResolver`, `ZoneFile`)

| Choice | Why |
|---|---|
| **Asked first, before cache and upstreams** | Local names (`nas.lan`, `printer.lan`) are answered instantly and **never leak** to a public resolver, which would otherwise learn your internal names. |
| **Hosts file or master zone file** | A hosts file is the quick option. A `.zone` file (RFC 1035 master format: `$ORIGIN`, `$TTL`, `$INCLUDE`, parentheses, quoted strings, RFC 3597 `\#` generic rdata) gives full authoritative behaviour. |
| **Zone semantics done properly** | CNAME chains with loop limits, delegations and referrals at zone cuts (DS on the parent side), empty non-terminals, wildcards at the closest encloser, and NXDOMAIN/NODATA with the zone's SOA so clients can cache the negative answer. |
| **Falls through when the name isn't local** | It calls the next resolver in the chain instead of answering NXDOMAIN. |

### 5.3 Cache (`Cache`)

**What's used:** one `unordered_map<(name, type, class), RRset>` shared by every worker, guarded by a
`std::shared_mutex`, with atomic hit/miss counters. It holds up to 100,000 records.

| Choice | Why |
|---|---|
| **One cache shared by all workers** | A record one worker fetched serves every worker. Per-worker caches would mean N cold caches and N times the upstream traffic. |
| **`shared_mutex`** | Reads (lookups) vastly outnumber writes (new answers), so lookups shouldn't serialise. |
| **Stored by RRset; an update replaces the whole set** | RFC 2181 §5: the records of an RRset belong together. Replacing the whole set means stale and fresh addresses never mix. The set expires with its lowest TTL. |
| **TTLs count down** | An answer from the cache carries the time *remaining*, so a client never caches past the original expiry. TTL 0 records aren't stored. |
| **CNAME chains followed in the cache** (up to 8 hops) | `www.example.com CNAME example.com` plus `example.com A` answers from the cache without any upstream query. |
| **Only records that belong to the question are cached** | The forwarder caches the answer's own records and its CNAME chain, nothing else. A malicious upstream can't slip in records for unrelated names (cache poisoning). |
| **Eviction: expired first, then everything except root hints** | It's simple and predictable. Root hints are pinned so recursion can always start. |
| **Cache flushed on resolver switch** | Otherwise "now using recursion" would keep showing answers the old resolver cached. |

### 5.4 Forwarding (`ForwardingResolver`, `Upstream`)

**What's used:** for a cache miss, `query_server()` sends the question to an upstream over **UDP**, and again
over **TCP** if the reply comes back truncated, or, for a `tls://` upstream, over **DNS-over-TLS** only
(next section). NOERROR answers are cached.

| Choice | Why |
|---|---|
| **Forwarding as the default mode** | Public resolvers (Google, Cloudflare) already have warm caches and anycast nearby, so it's the fastest option for most networks. |
| **Several upstreams, tried in turn** | A SERVFAIL, REFUSED, timeout or garbage reply from one moves on to the next. |
| **The last upstream that answered is asked first, shared across workers** | When one upstream dies, the first query pays one timeout and everyone else then skips it. Without sharing, every worker would pay that timeout separately. |
| **Per-upstream timeout = request timeout ÷ upstreams, clamped to 100–1000 ms** | Trying *every* upstream still fits inside the client's deadline, so there's always time for the second choice to answer. |
| **UDP first, TCP on truncation** | That's the standard DNS behaviour. UDP is one round trip, and TCP is only needed for large answers. The query advertises a 1232-byte EDNS buffer, the DNS Flag Day 2020 value that avoids IP fragmentation. |
| **A fresh connected UDP socket per query, random 16-bit ID** | Connecting makes the kernel drop datagrams from any other address and report "port unreachable" quickly. A new socket gets a new random source port. Port plus ID is the classic defence against off-path spoofing. |
| **Replies with the wrong ID or question are ignored, and the wait continues** | A mismatched reply may be a spoofing attempt. Dropping it and waiting for the real one beats accepting it, and beats giving up. |
| **TTLs with the top bit set are read as 0** | RFC 2181 §8. |

### 5.5 Encrypted upstreams: DNS over TLS (`TlsClient`)

**What's used:** an upstream written `tls://1.1.1.1#cloudflare-dns.com` is asked over DNS-over-TLS
(RFC 7858, port 853 unless given). Every DoT upstream connects through **one shared `TlsClient`**: an
OpenSSL client context that holds the trusted CAs, keeps answered connections open for reuse, and counts
what happened, which is what the dashboard shows as evidence.

```ini
upstreams = tls://1.1.1.1#cloudflare-dns.com, tls://8.8.8.8#dns.google   # name checked
upstreams = tls://9.9.9.9                                                  # no name: the IP is checked
upstreams = tls://[2606:4700::1111]:853#cloudflare-dns.com, 8.8.8.8      # mix plain and TLS
upstream_ca_file = /path/to/ca.pem                                         # optional, default: system CAs
```

**How a certificate is checked**, on every new connection, before the question is sent:

| Check | How | Fails with |
|---|---|---|
| Chain leads to a trusted CA | `SSL_VERIFY_PEER` against the system store (`SSL_CTX_set_default_verify_paths`) or `upstream_ca_file` | `unable to get local issuer certificate`, `self-signed certificate` |
| Certificate is issued to the name after `#` | `SSL_set1_host`, partial wildcards (`dns*.test`) off; the name is also sent as SNI | `hostname mismatch` |
| ...or, without a name, lists the IP address | `X509_VERIFY_PARAM_set1_ip_asc` (Cloudflare, Google and Quad9 put their IPs in their certificates) | `IP address mismatch` |
| Within its validity dates | OpenSSL's chain verification | `certificate has expired`, `certificate is not yet valid` |
| TLS 1.2 or newer | `SSL_CTX_set_min_proto_version` | handshake failure |

| Choice | Why |
|---|---|
| **A rejected certificate is a failure, never a fallback to plain DNS** | RFC 8310's *strict* privacy profile. Falling back would let anyone who can block port 853 downgrade every query to plaintext. The forwarder moves on to the next upstream; if none passes, the client gets SERVFAIL. |
| **Queries padded to 128-byte blocks** (RFC 8467) | TLS hides content but not length, so a short and a long name would look different on the upstream hop. Every `tls://` query carries the EDNS Padding option, which also asks the upstream to pad its answer. Plain upstreams aren't padded: there it would hide nothing. |
| **The question is only sent after the handshake succeeded** | A server that fails the check never learns what was asked. The tests assert the fake server received zero queries. |
| **Answered connections are kept (up to 64, at most 10 s idle) and reused** | A fresh DoT query costs TCP + TLS handshakes before the question (three round trips). Reuse brings it down to one, the same as UDP. The certificate was checked when the connection was made, and a connection is only reused for the same address **and** name. |
| **A kept connection the server closed is replaced transparently** | Servers drop idle clients. If a reused connection turns out to be closed before any reply byte arrived, a new one is opened within the same deadline. |
| **A connection that carried a bad reply is closed** | A garbage, truncated or mismatched reply means the stream can't be trusted; it is dropped, not returned to the pool. |
| **The same deadline as plain upstreams** | Connect, handshake, write and read all share the per-upstream timeout, so a slow TLS server can't hold a worker longer than a plain one. |
| **One client for the whole process, counters behind a mutex** | Workers share kept connections, and the admin page reads one set of totals: queries, handshakes, reuses, rejections, failures, and the subject/issuer of the last accepted certificate and the reason for the last rejection. |
| **The admin page can probe any server** | `POST /api/tls/probe?ip=&port=&name=` does one handshake and returns the certificate presented, the protocol and cipher, and the verdict, so the check can be demonstrated live (the dashboard's **Certificates** test). |

The public resolvers Google, Cloudflare and Quad9 are always available over TLS in the resolver switch and
the Compare test, next to their plain versions, even when `upstreams` lists only plain ones.

### 5.6 Recursion (`RecursiveResolver`)

**What's used:** an iterative resolver. It starts from the closest name servers it knows (from the cache,
or the 13 root servers), asks them, follows referrals down to the authoritative servers, follows CNAMEs, and
looks up name-server addresses when no glue is given.

| Choice | Why |
|---|---|
| **Available as an option, not the default** | It doesn't depend on any third party and gives the most privacy. It's slower from cold, though, and some networks block it. The dashboard's Compare test shows the difference live. |
| **Bailiwick checks** | A server's records are only trusted for names inside the zone it was asked about, and glue outside its zone is ignored. A malicious or broken server can't plant answers for someone else's domain. That's the core defence against cache poisoning in a recursive resolver. |
| **A budget per client question** (total timeout and at most 64 server queries, nesting depth 8) | Referral loops, CNAME loops and deliberately deep delegations can't make one question run forever or turn us into a traffic amplifier. |
| **Server lists shuffled** | It spreads load over a zone's name servers, and one dead server isn't always asked first. |
| **Lame servers skipped** | Neither an answer nor a referral means move on to the next server. |
| **Shares the cache** | Referrals and NS addresses are cached, so the second lookup under `.com` skips the root and TLD round trips. |
| **IPv4 name-server addresses only** | Many networks, including demo networks, have no working IPv6. That's a deliberate simplification. |

### 5.7 Switching resolvers at run time (`ResolverSwitch`)

Every worker's chain holds *all* the configured options, built once by `make_factory`. An atomic index
picks the active one. The dashboard's resolver dropdown sets the index and flushes the cache. **Why:** the
demo can compare forwarding against recursion, or one upstream against another, **live** and without a
restart, and an atomic index means no locks on the query path.

---

## 6. Cross-cutting choices

### 6.1 Concurrency rules used everywhere

- **Never call a callback while holding a lock.** Callbacks may run front-end code that re-enters the
  middleware. The timer, the in-flight table and the worker all release their lock before completing anything.
- **Atomics for counters and flags** (metrics, `done`, outstanding counts, the active resolver), mutexes for
  maps, `shared_mutex` where reads dominate (cache, block list).
- **Each thread owns its data.** Connections belong to the I/O thread and resolver chains to their worker.
  Shared state is kept to the cache, the block list, the rate limiter and the in-flight table.
- **Injectable clocks.** The middleware takes a `Clock` function, so tests move time forward instead of
  sleeping. Rate limiting, blocking, breakers and expiry are all tested deterministically.
- **Every component is tested under ThreadSanitizer** (`tsan` preset) and AddressSanitizer/UBSan (`asan` preset).

### 6.2 Errors

| Situation | Mechanism | Why |
|---|---|---|
| Expected failures (bad config, malformed query, TLS setup) | `std::expected<T, std::string>` / `ParseError` | They're normal outcomes. The caller must handle them, and the message is specific ("line 7: unknown key 'worker'"). |
| Programming errors / impossible states | exceptions (`std::invalid_argument`, ...) | They fail loudly at construction, for example a factory returning null or zero workers. |
| The query path | `noexcept` boundaries that turn anything thrown into SERVFAIL | One bad query must never take the server down or lose a reply. |

The configuration is validated in full at startup: ranges, file existence, both-or-neither cert and key, and
protocol strikes above rate-limit strikes. A server that starts is a server that's configured correctly.

### 6.3 Why C++23

| Feature | Used for |
|---|---|
| `std::expected` | error handling without exceptions on hot or expected paths |
| `std::format` / `std::format_string` | type-checked log lines, formatted only if the level is enabled |
| `std::jthread`, `std::stop_token`, `condition_variable_any` | worker and timer threads that shut down cleanly on their own |
| `std::move_only_function`, ranges, `append_range`, `ranges::ends_with` | callbacks that own move-only state; shorter, clearer algorithms |

C++ itself: predictable latency without GC pauses, direct access to epoll and OpenSSL, and control over memory
on untrusted input.

### 6.4 Observability

- **`Metrics`:** lock-free atomic counters (received, rate limited, overload, timeouts, coalesced, resolver
  exceptions, blocked, rcodes) plus a 12-bucket latency histogram (1 ms … 2 s, then "over 2 s"). Percentiles
  are read from the histogram. **Why atomics and a histogram:** they cost almost nothing on the query path,
  and a histogram gives p50/p95/p99 without storing every sample.
- **`QueryLog`:** a ring buffer of the last 500 replies (client, name, rcode, latency, who answered, the
  first 4 records) behind the dashboard's live feed. Simulated test traffic is marked `quiet` and kept out.
- **Logger:** thread-safe single lines `[HH:MM:SS.mmm][LEVEL][thread] message` on stderr. A line below the
  log level is never formatted.

### 6.5 Testing

About 525 GoogleTest cases over 30 test files, one per component. Fakes in `tests/support/` include a fake
DNS server for forwarding and recursion tests, a fake DNS-over-TLS upstream (`fake_dot_server.hpp`), a
throwaway certificate authority that issues certificates with any names, addresses and dates
(`tls_cert.hpp`), a fake middleware and temporary directories. No key material lives in the repo. The front
end is tested end to end over real TLS sockets, and so are encrypted upstreams.

What the upstream tests cover (`test_dot_upstream.cpp`, `test_forwarding_resolver.cpp`,
`test_resolver_factory.cpp`, `test_admin_server.cpp`):

| Area | Tests |
|---|---|
| A query completing over DNS-over-TLS | answer received with the name sent as SNI; certificate subject and issuer recorded; through the full resolver chain from a `tls://` config line; through the admin Lookup |
| Certificate validation | wrong name, IP not in the certificate, untrusted issuer, self-signed, expired, not yet valid, wildcard not covering the parent; the system store not trusting a test CA; nothing is sent to a rejected server; the next upstream is tried; a kept connection is not reused for another name |
| Invalid responses | garbage, a reply to another question (wrong ID), truncated, a reply cut short mid-frame (TLS); junk datagrams before the real answer, only malformed datagrams, a malformed TCP reply (plain); a bad reply doesn't poison the next query |
| Upstream failure | closed port, a plain DNS server where TLS was expected (fails, no fallback, no plain query sent), server closing a kept connection, missing or unreadable CA file, unconfigured client |
| Timeouts | a TLS server that never answers gives SERVFAIL within the deadline; silent plain upstreams; slow resolvers in the middleware | `load_gen` stress-tests the middleware
alone and **exits non-zero if any query got anything other than exactly one reply**.

---

## 7. Admin dashboard

`AdminServer` is a small HTTP/1.1 server (`admin_listen`) that serves `gui/index.html` and a JSON API.

| Choice | Why |
|---|---|
| **Plain HTTP, loopback only, Host header checked** | It has no login, so it must not be reachable from outside. Checking Host also stops DNS-rebinding attacks from a web page in your browser. |
| **One static HTML file, no build step** | Nothing to install. It polls `/api/metrics` and `/api/queries` once a second. |
| **Tests run through `Middleware::submit`** | Traffic, Load and Abuse exercise the *real* rate limiter, coalescing, queues and breakers. Only TLS is skipped. Simulated clients use the 198.18.0.0/15 benchmarking range (RFC 2544). |
| **Paced tests cap unanswered queries at 20,000** | A slow upstream can't make the test itself pile up unbounded work. |
| **Unique-name tests capped at 200/s** | Every unique name is a real query to Google or Cloudflare, so the tests stay polite. |
| **Compare test uses separate resolvers with their own caches** | Cold and cached mean the same thing for every resolver being compared. |
| **An "Upstream encryption" row and a Certificates test** | Evidence that upstream certificates are checked: queries over TLS, certificates accepted and rejected, the last certificate's subject and issuer, the last rejection's reason, and a live handshake against any server. |

API: `GET /api/status`, `/api/metrics`, `/api/queries?after=N`, `/api/lookup?name=&type=&via=`;
`POST /api/resolver?id=`, `/api/load`, `/api/traffic`, `/api/traffic/stop`, `/api/abuse`, `/api/abuse/stop`,
`/api/unblock?client=`, `/api/faults?fail_rate=`, `/api/cache/flush`, `/api/tls/probe?ip=&port=&name=`.
`/api/metrics` includes an `upstream_tls` object with the `TlsClient` counters.

---

## 8. Capacity, and why SERVFAIL appears under heavy load

Each worker is **one thread doing one blocking lookup at a time**, so the most cache misses the server can
resolve per second is about

```
workers × (1000 ms ÷ average upstream round trip)
```

With `workers = 4` and upstream round trips of 10–50 ms, plus the occasional lost packet that stalls a
worker for a full per-upstream timeout, that comes out at roughly **100–150 lookups a second**.

The Traffic test's "mixed" mode makes one name in ten brand new, so at 2,000 queries a second about **200 a
second must go to an upstream**. That is more than the workers can finish, so the queues grow. Once a
query has waited longer than `request_timeout_ms` (2 s in the demo), it's answered SERVFAIL by the deadline
timer ("timed out") or skipped when its worker reaches it ("expired in queue").

**This is the design working, not a bug.** The server sheds load with a fast, honest SERVFAIL instead of
letting latency and memory grow without limit. Measured on the demo config:

| Run | SERVFAIL |
|---|---|
| 4 workers, 2,000/s, popular names only (the cache answers everything) | 0 of 30,000 |
| 4 workers, 2,000/s, mixed names | thousands, all "expired in queue" or "timed out" |
| 32 workers, 2,000/s, mixed names | 26 of 30,000 (upstream packet loss) |

To handle more cache misses, raise `workers` (up to 64).

---

## 9. Known limitations and future work

| Limitation | Effect | Fix |
|---|---|---|
| Blocking resolvers | Throughput on cache misses = workers ÷ upstream latency | Asynchronous resolvers: one thread keeps many upstream queries open (epoll or io_uring) |
| Cache checked inside the worker | When overloaded, a query the cache could answer still waits behind slow lookups | Check the cache in `submit()` before queueing |
| Only NOERROR answers cached | Repeated queries for names that don't exist always go upstream | Negative caching with the SOA minimum (RFC 2308) |
| Query IDs from `mt19937` | Not cryptographically random (the source port still adds entropy) | Use `RAND_bytes` / `getrandom` |
| No DNSSEC validation | Answers are trusted as the upstream or the authority sent them | Validate signatures in the recursive resolver |
| Recursion uses IPv4 name servers only | IPv6-only zones can't be reached | Also use AAAA glue |
| No DoH / DoQ | DoT only, to clients and to upstreams | Add an HTTP/2 or QUIC front end that calls the same `submit()`, and an HTTPS transport next to `TlsClient` |
| One query at a time per upstream TLS connection | Concurrent misses to one upstream open more connections instead of pipelining | Pipeline queries on one connection, matched by ID (RFC 7766 §6.2.1) |
| No certificate pinning | Any certificate from a trusted CA for the right name passes | Optional SPKI pins per upstream (RFC 7858 §4.2) |
| Settings read only at startup | Changing `workers` needs a restart | Reload on SIGHUP |

---

## 10. Configuration and tuning

All settings live in one `key = value` file passed on the command line. Lines starting with `#` are
comments. Every key, with its allowed range, is documented in
[`config/middleware.example.conf`](config/middleware.example.conf). Settings are read once at startup, **so
restart the server after changing them** (Ctrl+C, then run it again). Only two things change while it runs:
the resolver switch and the failure rate in the dashboard's Failures test.

For example, to use 16 workers in the demo, edit `config/demo.conf`:

```ini
workers = 16
```

then restart:

```sh
./build/release/dns_server config/demo.conf
```

The dashboard's worker panels and breaker timeline pick up the new count automatically.

| Key | Demo value | Default | What it controls | Raise it when… |
|---|---|---|---|---|
| `workers` | 4 | 4 | Worker threads, 1–64. How many cache misses resolve in parallel | you see "expired in queue" / "timed out" at high rates |
| `queue_capacity` | 1024 | 256 | Jobs each worker can hold before new ones get SERVFAIL "overloaded" | short bursts are rejected (a longer queue only helps if the work fits in the timeout) |
| `request_timeout_ms` | 2000 | 2500 | Deadline for every query, 50–30000 | upstreams or recursion are slow |
| `lb_policy` | least_outstanding | least_outstanding | `round_robin`, `least_outstanding` or `power_of_two` | — |
| `failure_threshold` | 3 | 5 | SERVFAILs in a row before a worker's breaker opens | breakers trip on an unreliable network |
| `cooldown_ms` | 3000 | 5000 | How long an open breaker waits before a probe | — |
| `rate_limit_qps` | 200 | 0 (off) | Sustained queries/s allowed per client | real clients get REFUSED |
| `rate_limit_burst` | 100 | — | Token-bucket size, the burst allowed above the rate | — |
| `block_rate_limit_strikes` | 50 | 0 (off) | Rate-limited queries within the window before a block | — |
| `block_protocol_strikes` | 100 | 0 (off) | Protocol errors within the window before a block | — |
| `block_window_ms` / `block_duration_ms` | 10000 / 60000 | 10000 / 300000 | How long strikes are remembered / how long a block lasts | — |
| `block_max_entries` | — | 100000 | Most sources tracked for strikes | — |
| `mode` | forwarding | forwarding | `forwarding` (ask `upstreams`) or `recursive` (start from the root servers) | — |
| `upstreams` | tls://1.1.1.1#cloudflare-dns.com, tls://8.8.8.8#dns.google | — | Upstream resolvers for forwarding mode. `IP[:port]` is plain DNS; `tls://IP[:port][#name]` is DNS-over-TLS (port 853), the certificate checked against the name (or the IP) | — |
| `upstream_ca_file` | — | system CAs | PEM file of CAs that `tls://` upstreams' certificates must chain to | your upstream uses a private CA |
| `records_file` | config/demo.hosts | none | Local names answered first (hosts file, or a `.zone` file) | — |
| `blocked_domains_file` | config/blocked_domains.txt | none | Domains (and everything under them) answered NXDOMAIN | — |
| `listen` | 127.0.0.1:8853 | 0.0.0.0:853 | DoT address. Port 853 needs root | — |
| `tls_cert` / `tls_key` | config/server.pem / .key | — | Certificate chain and private key (both required) | — |
| `max_connections` / `max_connections_per_source` | — | 1000 / 32 | Connection limits | many clients share one NAT address |
| `idle_timeout_ms` | — | 10000 | Closes connections with no complete query | — |
| `admin_listen` / `admin_ui_dir` | 127.0.0.1:8080 / gui | off / gui | Admin page address and where `index.html` lives | — |
| `log_level` | info | info | `debug`, `info`, `warn` or `error` | debugging |

For quick experiments without the network, `load_gen` takes the same knobs as flags
(`--workers 16 --queue 64 --timeout-ms 500 ...`, see [Load generator](#load-generator)).

---

## 11. Building and testing

### Prerequisites

- CMake 3.21+ (for `CMakePresets.json`)
- `g++-15` (C++23: `std::expected`, `std::format`, `std::move_only_function`, and the GCC 15 library's
  `vector::append_range` and `ranges::ends_with`)
- OpenSSL 3 development headers (`libssl-dev`)
- Internet access on the first configure (GoogleTest is fetched by CMake)

On Ubuntu 22.04, `g++-15` comes from the toolchain PPA:

```sh
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install g++-15 cmake libssl-dev
```

### Build and test

The presets in `CMakePresets.json` build out of tree under `build/<preset>/`.

```sh
cmake --preset local            # configure (Debug)
cmake --build --preset local    # build dns_server, load_gen and dns_tests
ctest --preset local            # run the tests (or: ./build/local/dns_tests)
```

| Preset    | Build dir        | What it is                                  |
|-----------|------------------|---------------------------------------------|
| `local`   | `build/local`    | Debug build                                 |
| `release` | `build/release`  | Optimised build, use it for the demo and load_gen numbers |
| `asan`    | `build/asan`     | AddressSanitizer + UBSan                    |
| `tsan`    | `build/tsan`     | ThreadSanitizer                             |

Every preset accepts the same steps, e.g. `cmake --preset tsan && cmake --build --preset tsan && ctest --preset tsan`.
The code builds with `-Wall -Wextra -Wpedantic`. To use another compiler, override it at configure time:
`cmake --preset local -DCMAKE_CXX_COMPILER=clang++`.

### Load generator

`load_gen` drives `Middleware::submit()` directly (no network) with a stub resolver and prints
throughput, the metrics report and a per-worker table. It exits 0 when every query got exactly
one callback, 1 if a reply went missing, 2 for bad arguments.

```sh
./build/release/load_gen                                  # defaults: 8 threads, 100000 queries
./build/release/load_gen --stub-fail-rate 0.2             # watch the circuit breakers trip
./build/release/load_gen --queue 1 --workers 1 --stub-delay-ms 50   # force overload
```

Options: `--threads`, `--queries`, `--dup-ratio`, `--workers`,
`--policy round_robin|least_outstanding|power_of_two`, `--timeout-ms`, `--queue`,
`--stub-delay-ms`, `--stub-fail-rate`, `--stub-throw-rate`, `--qps` (per thread),
`--failure-threshold` (default 3), `--cooldown-ms` (default 200).

### Running the demo

```sh
cmake --preset release && cmake --build --preset release
./tools/make_demo_cert.sh                      # self-signed config/server.pem + .key (git-ignored)
./build/release/dns_server config/demo.conf    # DoT on 127.0.0.1:8853, admin page on :8080
```

Open <http://127.0.0.1:8080/>. It's a Grafana-style dashboard showing queries per second by result,
latency percentiles, cache hit ratio, protection events, a breaker state timeline per worker and a live query
log. A **resolver** switch at the top changes which resolver every worker uses while the server runs.
The tests on the left (each one can be opened directly, e.g. <http://127.0.0.1:8080/#abuse>):

| Test | What it shows |
|---|---|
| Lookup | a name's addresses, the latency, and where the answer came from (cache, records file, upstream, recursive) |
| Compare | the same name through forwarding to 8.8.8.8 / 1.1.1.1 / 9.9.9.9 and recursion from the root servers, cold then cached |
| Traffic | a steady stream of queries from 1000 simulated clients until you press Stop |
| Load | a fixed number of queries as fast as possible: throughput, latency, coalescing, cache |
| Abuse | one client at a fixed rate: under the limit it is served, over it it is rate limited and then blocked |
| Failures | inject lookup failures and watch the circuit breakers open, half-open and close |
| Certificates | one TLS handshake with an upstream: the certificate it presented, protocol, cipher, and whether it passed. Try the **Impostor** preset (1.1.1.1 claiming to be dns.google): rejected with `hostname mismatch` |

**Showing encryption end to end.** The demo config forwards over DNS-over-TLS, so with it a query is
encrypted from `dig +tls` to the server and from the server to Cloudflare or Google:

1. `dig +tls @127.0.0.1 -p 8853 example.com`. The live feed shows it served by
   `upstream 1.1.1.1:853 (cloudflare-dns.com) over TLS`.
2. The **Upstream encryption** row counts it, and shows the accepted certificate's subject and issuer.
3. The **Certificates** test: Cloudflare is accepted, the Impostor is rejected, and the rejection shows up
   in the row with its reason.
4. The **resolver** switch at the top offers each public resolver plain and over TLS. The **Compare** test
   shows what encryption costs (the first, cold query pays for the handshake; later ones reuse the connection).

Real encrypted queries show up in the feed too:

```sh
dig +tls @127.0.0.1 -p 8853 www.wikipedia.org     # BIND 9.18+
dig +tls @127.0.0.1 -p 8853 nas.lan               # from config/demo.hosts
dig +tls @127.0.0.1 -p 8853 ad.doubleclick.net    # NXDOMAIN, from config/blocked_domains.txt
```

Some networks (campus, corporate) only let DNS through to a few resolvers and drop queries without the
RD bit, and some block port 853. There, recursion, some upstreams or DNS-over-TLS time out (switch the
resolver at the top to a plain one). Check the Compare test on the demo network first,
and keep a phone hotspot as a fallback.

### Layout

```
include/           shared types (DomainName, IP, Records), the DNS wire format (dns_message) and utils
include/backend/   resolvers (zone files, hosts file, forwarding, recursive), the cache, upstream queries
include/mw/        middleware and front-end headers (namespace mw)
src/               library sources
tools/             load_gen, make_demo_cert.sh
gui/               the admin page (served by dns_server when admin_listen is set)
tests/             GoogleTest suite; tests/support/ holds printers and fakes
config/            example and demo configuration
docs/              front-end design notes
```
