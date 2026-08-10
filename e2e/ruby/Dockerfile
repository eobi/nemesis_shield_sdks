# Ruby SDK: tokenizer parity (36 vectors) + live sketch round-trip, on ruby:3.3.
FROM ruby:3.3
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY ruby/ /work/ruby/
COPY e2e/ruby/roundtrip.rb /work/ruby/roundtrip.rb
WORKDIR /work/ruby
CMD sh -c '\
  echo "== PARITY (ruby) ==" && \
  ruby test_tokenize_parity.rb && echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (ruby) ==" && \
  ruby roundtrip.rb'
