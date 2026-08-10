# PHP SDK: tokenizer parity (36 vectors) + live sketch round-trip, on php:8.3-cli.
FROM php:8.3-cli
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY php/ /work/php/
COPY e2e/php/roundtrip.php /work/php/roundtrip.php
WORKDIR /work/php
CMD sh -c '\
  echo "== PARITY (php) ==" && \
  php tokenize_parity_test.php && echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (php) ==" && \
  php roundtrip.php'
