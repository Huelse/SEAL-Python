# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A pybind11 binding that exposes the Microsoft SEAL homomorphic-encryption C++ library as a single Python extension module named `seal`. Published to PyPI as `seal-python`.

Everything is bound from one translation unit: `src/wrapper.cpp` (~1200 lines, single `PYBIND11_MODULE(seal, m)`). There is no Python-level package — no `seal/` source directory exists; the importable `seal` is the compiled `.so`/`.pyd` sitting in the working directory or site-packages.

## Build

The SEAL submodule must be built into static libs **before** `setup.py` will run — `setup.py` globs `SEAL/build/lib/*.a` (`*.lib` on Windows) into `extra_objects` and calls `sys.exit(1)` if none are found.

```bash
git submodule update --init --recursive          # SEAL only; pybind11 comes from pip
pip install numpy pybind11
cmake -S SEAL -B SEAL/build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
cmake --build SEAL/build
python3 setup.py build_ext -i                    # produces seal.*.so in repo root
```

The three `-DSEAL_USE_*=OFF` flags are load-bearing: they are used identically in the Dockerfile, in `RELEASE.md`, and in CI, and the `compr_mode_type.zlib`/`.zstd` enum values in `wrapper.cpp` are `#ifdef`-gated on them, so the default build ships compression-mode `none` only.

Windows requires the **x64 Native Tools Command Prompt for VS** (x64 only) and `-G Ninja`. On macOS, export `MACOSX_DEPLOYMENT_TARGET` before both the CMake and the `setup.py` step so the static lib and the extension agree (see README).

Docker: `docker build -t huelse/seal -f Dockerfile .` does the whole sequence on Ubuntu 22.04.

## Test

There is no test suite. `examples/` doubles as the regression suite; the scripts import `seal` from the current directory, so copy the built module in first:

```bash
cp seal.*.so examples && cd examples
python3 4_bgv_basics.py        # run a single "test"
```

After any binding change, run at least one arithmetic flow (`4_bgv_basics.py`) and one serialization flow (`7_serialization.py`). `examples/seal_helper.py` provides the shared `print_parameters` / `print_vector` helpers the numbered examples use. CI's only smoke test is `python -c "import seal; print(seal.__version__)"`.

## Working on the bindings

- **`seal.pyi` is hand-maintained and must be edited alongside `src/wrapper.cpp`.** The project ships PEP 561 typing (`seal.pyi` + `py.typed`); `setup.py`'s `build_ext_with_typing` subclass copies both next to the compiled extension on every build. A new or changed binding that isn't mirrored in the stub silently degrades to `Any` for users.
- **The version string lives in two places that must stay in sync**: `__version__` in `setup.py` and `m.attr("__version__")` in `src/wrapper.cpp:21`.
- Bindings are grouped by upstream SEAL header with a `// encryptionparams.h`-style comment marking each block; keep new bindings in the matching block and mirror upstream SEAL names so the API stays familiar.
- Every binding carries a `SEAL_DOC("...")` docstring (the macro is a passthrough) and named `py::arg(...)`. Follow that convention.
- **pybind11 overload order matters.** Encoders register the same Python name several times — `std::vector<T>` form, then `py::array_t<T>` (NumPy) form, then `py::iterable` form — and pybind11 tries them in registration order. Insert new overloads with that resolution order in mind; the NumPy paths raise `"E101: Number of dimensions must be one"` for non-1-D input.
- C++ overloads that Python cannot disambiguate get distinct names: complex CKKS encoding is exposed as `encode_complex`, not an `encode` overload.
- Serialization is bound as lambdas taking a **file path string** (`save(path)` / `load(context, path)`), plus a `load_bytes(context, py::bytes)` variant — not raw C++ streams. Supported on `EncryptionParameters, Ciphertext, Plaintext, SecretKey, PublicKey, RelinKeys, GaloisKeys`.
- `std::vector<double|complex<double>|uint64_t|int64_t>` are `PYBIND11_MAKE_OPAQUE`'d and bound as `VectorDouble` / `VectorComplex` / `VectorUInt` / `VectorInt` with the buffer protocol, so they do not implicitly convert to/from Python lists.

## Release

`RELEASE.md` has the full checklist. `.github/workflows/wheels.yml` builds cibuildwheel wheels (cp38–cp314, x86_64 Linux / AMD64 Windows / auto64 macOS, no musllinux or PyPy) plus an sdist on every push and PR, and publishes to PyPI via trusted publishing only on a **published GitHub release**.
