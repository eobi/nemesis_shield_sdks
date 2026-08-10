# Java SDK: tokenizer parity (36 vectors, via mvn test) + live sketch round-trip, on temurin 21 + maven.
FROM eclipse-temurin:21
RUN apt-get update && apt-get install -y --no-install-recommends maven && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY java/ /work/java/
COPY e2e/java/RoundTrip.java /work/java/RoundTrip.java
WORKDIR /work/java
# Pre-resolve Maven deps (junit) so the run phase is fast.
RUN mvn -q -B dependency:resolve test-compile
CMD sh -c '\
  echo "== PARITY (java) ==" && \
  mvn -q -B test && echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (java) ==" && \
  javac -cp target/classes RoundTrip.java -d rt-out && \
  java -cp target/classes:rt-out RoundTrip'
