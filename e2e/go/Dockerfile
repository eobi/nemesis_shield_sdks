# Go SDK: tokenizer parity (36 vectors, via go test) + live sketch round-trip, on golang:1.23.
FROM golang:1.23
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY go/ /work/go/
# The round-trip driver is a main package inside the module so it can import the SDK.
COPY e2e/go/main.go /work/go/cmd/roundtrip/main.go
WORKDIR /work/go
CMD sh -c '\
  echo "== PARITY (go) ==" && \
  go test -run TestNormalizePathParity -v . && echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (go) ==" && \
  go run ./cmd/roundtrip'
