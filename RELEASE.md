# Release to PyPI

## 1. Build prerequisites

```bash
python3 -m pip install --upgrade pip build twine
git submodule update --init --recursive
cmake -S SEAL -B SEAL/build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
cmake --build SEAL/build
```

## 2. Build wheel and sdist

```bash
python3 setup.py sdist bdist_wheel
```

## 3. Validate artifacts

```bash
python3 -m twine check dist/*
```

## 4. Upload to TestPyPI (recommended first)

```bash
python3 -m twine upload --repository testpypi dist/*
```

## 5. Upload to PyPI

```bash
python3 -m twine upload dist/*
```

## 6. Post-upload smoke test

```bash
python3 -m venv /tmp/seal-publish-test
source /tmp/seal-publish-test/bin/activate
python -m pip install seal-python
python - <<'PY'
import seal
print("seal version:", seal.__version__)
PY
```
