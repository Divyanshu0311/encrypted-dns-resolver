# dns-middleware

A C++23 encrypted DNS server. The middleware (`include/mw/`, namespace `mw`) sits between the
DNS-over-TLS front end and the resolver backend (`include/backend/`): it rate-limits clients,
coalesces identical in-flight queries, spreads work over worker threads with circuit breakers,
and guarantees every query gets exactly one answer (SERVFAIL on timeout or overload).

## Prerequisites

- CMake 3.21+ (for `CMakePresets.json`)
- `g++-14` (C++23: `std::expected`, `std::format`, `std::move_only_function`)
- Internet access on the first configure (GoogleTest is fetched by CMake)

On Ubuntu 22.04, `g++-14` comes from the toolchain PPA:

```sh
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install g++-14 cmake
```

## Building and testing

The presets in `CMakePresets.json` build out of tree under `build/<preset>/`.

```sh
cmake --preset local            # configure (Debug)
cmake --build --preset local    # build dns_server, load_gen and dns_tests
ctest --preset local            # run the tests (or: ./build/local/dns_tests)
```

| Preset    | Build dir        | What it is                                  |
|-----------|------------------|---------------------------------------------|
| `local`   | `build/local`    | Debug build                                 |
| `release` | `build/release`  | Optimised build, use it for load_gen numbers |
| `asan`    | `build/asan`     | AddressSanitizer + UBSan                    |
| `tsan`    | `build/tsan`     | ThreadSanitizer                             |

Every preset accepts the same steps, e.g. `cmake --preset tsan && cmake --build --preset tsan && ctest --preset tsan`.

To use another compiler, override it at configure time:
`cmake --preset local -DCMAKE_CXX_COMPILER=clang++`.

## Load generator

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

## Configuration

The middleware reads `key = value` files; see `config/middleware.example.conf` for every key.

## Layout

```
include/           shared types (DomainName, IP, Records) and utils
include/backend/   resolvers (zone files, hosts file, forwarding, recursive) and the cache
include/mw/        middleware and front-end headers (namespace mw)
src/               library sources
tools/             load_gen
tests/             GoogleTest suite; tests/support/ holds printers and fakes
config/            example configuration
docs/              front-end design notes
```
