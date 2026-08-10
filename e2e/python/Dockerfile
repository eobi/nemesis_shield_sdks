# Python SDK: tokenizer parity (36 vectors, via pytest) + live sketch round-trip, on python:3.12.
FROM python:3.12
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY python/ /work/python/
COPY e2e/python/roundtrip.py /work/python/roundtrip.py
WORKDIR /work/python
RUN pip install --no-cache-dir pytest >/dev/null && pip install --no-cache-dir -e . >/dev/null
CMD sh -c '\
  echo "== PARITY (python) ==" && \
  python -m pytest tests/test_parity.py::test_normalize_path_canonical_vectors -q && \
  echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (python) ==" && \
  python roundtrip.py'
