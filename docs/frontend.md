# DoT Front-end

*As of 2026-10-20 · Owner: Dhruv*

The front-end is the resolver's front door. It accepts encrypted DNS queries from clients over
DNS-over-TLS (TCP port 853), checks each one, passes valid queries to the middleware, and sends
back the encrypted answers. It also decides which clients and queries get rejected, and how.

We are implementing all of the features below. Some are complete; the rest are in progress.

---

## How a query flows through the front-end

```
client connects
   │
   ├─ client is blocked? ───────────────────────► connection closed
   ▼
TLS handshake (encryption set up)
   │
client sends an encrypted query
   │
   ▼
decrypt ─► separate the stream into individual messages
   │
   ├─ client blocked since connecting? ────────► connection closed
   ├─ malformed query? ────────────────────────► FORMERR / NOTIMP reply
   ├─ query breaks a policy rule? ─────────────► REFUSED reply
   ▼
hand the query to the middleware ──► middleware resolves it
                                            │
   ┌────────────────────────────────────────┘
   ▼
build the reply (+ padding) ─► add its length ─► encrypt ─► send to client
   │
connection stays open for the client's next query
```

---

## Features

| Feature | What it does | Status |
|---|---|---|
| Query parsing and validation | Turns raw bytes into a checked query; rejects anything malformed or hostile without ever reading outside the message | ✅ Done |
| Name normalization | Treats `WWW.Example.COM` and `www.example.com.` as the same name, and rejects invalid names | ✅ Done |
| Reply building | Turns the middleware's answer into a correct DNS reply, always producing a valid message (falls back to SERVFAIL if needed) | ✅ Done |
| Length padding | Pads replies to a fixed block size so encrypted traffic doesn't reveal which site was looked up by its size | ✅ Done |
| Message framing | Splits the decrypted byte stream into individual queries, and prefixes each reply with its length | ✅ Done |
| TLS encryption | Encrypts every connection with OpenSSL; sets up keys securely and proves the server's identity | ⏳ Remaining |
| Abuse blocking | Drops clients the middleware has flagged as abusive, before spending any work on them | ⏳ Remaining |
| Policy rejections | Answers REFUSED for queries that break a rule, such as a blocked domain | ⏳ Remaining |
| Connection handling | Serves many clients at once, several queries per connection, with timeouts and connection limits | ⏳ Remaining |
| Configuration | Listen address, certificate and key paths, limits, blocked-domain list | ⏳ Remaining |
| Runnable server | A server binary that can be tested end to end with `dig +tls` | ⏳ Remaining |

---

## How the front-end rejects queries

| Situation | Response | Why |
|---|---|---|
| Client flagged as abusive by the middleware | Connection closed, no reply | No work or bandwidth spent on attackers |
| Message too broken to even read its ID, or not a query at all | Connection closed, no reply | There is nothing valid to reply to |
| Malformed query | FORMERR | Tells a buggy client what's wrong |
| Query kind we don't support | NOTIMP | Clear answer instead of silence |
| Query breaks a policy rule | REFUSED | Clear answer for legitimate clients |
| Middleware is overloaded | SERVFAIL | The client can retry later |

### What the response codes mean

Every DNS reply carries a response code. FORMERR, NOTIMP and REFUSED say the problem is with the
query; SERVFAIL says the problem is on the resolver's side.

| Code | Meaning | When this resolver sends it | Does retrying help? |
|---|---|---|---|
| **FORMERR** (1) | Format error: the query is broken | The query was readable enough to reply to, but breaks DNS rules: wrong section counts, a damaged or invalid name, a bad EDNS record, or extra bytes at the end | No, the client must fix its query |
| **NOTIMP** (4) | Not implemented: valid, but unsupported | The query is well-formed but asks for something we don't support: an operation other than a standard query, a class other than Internet (e.g. CHAOS), or a record type we don't handle yet (e.g. HTTPS) | No |
| **REFUSED** (5) | Refused: understood, but not allowed | The query is valid and supported, but a policy rule forbids answering it, such as a blocked domain | No |
| **SERVFAIL** (2) | Server failure: no answer could be produced | The query was fine, but the resolver couldn't answer: the middleware was overloaded, the upstream servers failed, or the answer couldn't be turned into a valid reply | Yes, later or through another resolver |

---

## How the encryption works

- **The session key is never sent.** Client and server each compute it from a key exchange
  (ECDHE), so someone watching the network can't get it.
- **The server proves its identity** by signing the handshake with its private key. The key
  never leaves the server, and the signature stops anyone impersonating it.
- **Forward secrecy.** A stolen private key would let an attacker impersonate the server in
  future, but not decrypt traffic recorded earlier.
- **Length padding** covers the one thing TLS doesn't hide: message sizes.
- **Key file protection.** The private key file is readable only by the server, and key files
  are kept out of git.

---

## What the front-end needs from the middleware

The middleware is built separately by a teammate. The front-end relies on two things from it:

- **A way to submit a query.** The middleware either accepts it and answers later, rejects the
  client, or reports that it's overloaded.
- **A blocklist the front-end can check.** It answers "is this client blocked right now?"

---

## Running the tests

```sh
make CXX=g++ test    # build and run all tests
make CXX=g++ asan    # same tests with memory-error detection
```
