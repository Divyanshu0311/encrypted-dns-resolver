# dns-middleware

A C++23 DNS middleware. This repository currently contains the project skeleton only.

## Prerequisites

- GNU Make
- `g++-14` (C++23)
- `libgtest-dev` (GoogleTest headers and static libraries)
- `clang-format` (only for `make format`)

On Ubuntu 24.04:

```sh
sudo apt install g++-14 libgtest-dev clang-format make
```

On Ubuntu 22.04, `g++-14` comes from the toolchain PPA:

```sh
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install g++-14 libgtest-dev clang-format make
```

To use a different compiler, override `CXX`, e.g. `make CXX=clang++`.

## Make targets

| Target         | Description                                                                       |
|----------------|-----------------------------------------------------------------------------------|
| `make` / `all` | Builds `build/libmw.a` from `src/` and links `build/load_gen`.                    |
| `make test`    | Builds `build/run_tests` from `tests/*.cpp` against `libmw.a` and runs it.         |
| `make asan`    | Full build and tests with AddressSanitizer + UBSan, in `build/asan/`.              |
| `make tsan`    | Full build and tests with ThreadSanitizer, in `build/tsan/` (tests run via `setarch -R`). |
| `make release` | Optimised build (`-O2 -DNDEBUG`), in `build/release/`.                             |
| `make format`  | Runs `clang-format -i` over `include/`, `src/`, `tests/` and `tools/`.             |
| `make clean`   | Removes `build/`.                                                                  |

Header dependencies are tracked automatically (`-MMD -MP`), so editing a header rebuilds
everything that includes it.

## Layout

```
include/mw/   public headers (namespace mw)
src/          library sources, archived into build/libmw.a
tools/        load_gen, a load generator
tests/        GoogleTest suite; tests/fakes/ holds test doubles
config/       example configuration
```
