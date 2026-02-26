# Repository Guidelines

## Project Structure & Module Organization
- `src/wrapper.cpp`: pybind11 bindings that expose Microsoft SEAL C++ APIs as the Python module `seal`.
- `SEAL/`: Microsoft SEAL submodule source and CMake build output (`SEAL/build/...`).
- `pybind11/`: pybind11 submodule headers used by the extension build.
- `examples/`: runnable Python usage samples (for example `4_bgv_basics.py`, `7_serialization.py`).
- Root build files: `setup.py`, `pyproject.toml`, `Dockerfile`, and `README.md`.

## Build, Test, and Development Commands
- `git submodule update --init --recursive`: fetch SEAL and pybind11 submodules.
- `cmake -S SEAL -B SEAL/build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF && cmake --build SEAL/build`: build static SEAL libraries used by the Python extension.
- `python3 setup.py build_ext -i`: build `seal` extension in-place for local development.
- `python3 setup.py install`: install the module into the active environment.
- `cp seal.*.so examples && python3 examples/4_bgv_basics.py`: smoke-test a Linux/macOS build with an example.
- `docker build -t seal-python -f Dockerfile .`: build reproducible container environment.

## Coding Style & Naming Conventions
- Python: follow PEP 8, 4-space indentation, `snake_case` for functions/variables.
- C++ bindings: keep existing style in `wrapper.cpp` (4-space indentation, grouped bindings by SEAL header/domain).
- Exposed Python symbols should match upstream SEAL naming where practical (for API familiarity).
- Prefer adding small, focused binding blocks rather than large mixed edits.

## Testing Guidelines
- No formal `tests/` suite is currently checked in; use example scripts as regression checks.
- For binding changes, run at least one arithmetic flow (`examples/4_bgv_basics.py`) and one serialization flow (`examples/7_serialization.py`).
- If adding new behavior, include a minimal runnable example in `examples/` named after the feature.

## Commit & Pull Request Guidelines
- Recent history favors short imperative subjects (for example: `Update deps`, `Update README.md`, `Update SEAL`).
- Keep commit titles under ~72 characters and focused on one change.
- PRs should include: purpose, build/test commands run, platform used, and any API surface changes.
- Link related issues and include sample output when behavior changes are user-visible.
