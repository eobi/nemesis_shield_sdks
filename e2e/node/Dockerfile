# Node SDK: tokenizer parity (36 vectors) + live sketch round-trip, in a clean node:20 runtime.
FROM node:20
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY node/ /work/node/
COPY e2e/node/roundtrip.mjs /work/node/roundtrip.mjs
WORKDIR /work/node
CMD sh -c '\
  echo "== PARITY (node) ==" && \
  node test_parity.mjs && echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (node) ==" && \
  node roundtrip.mjs'
