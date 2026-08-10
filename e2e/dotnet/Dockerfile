# .NET SDK: tokenizer parity (36 vectors) + live sketch round-trip, on dotnet/sdk:8.0.
FROM mcr.microsoft.com/dotnet/sdk:8.0
ENV NEMESIS_TOKENIZE_VECTORS=/work/tokenize.vectors.json
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
WORKDIR /work
COPY tokenize.vectors.json /work/tokenize.vectors.json
COPY dotnet/ /work/dotnet/
# Round-trip console project lives beside the SDK source so ../NemesisShield.cs resolves (like tokenizetest).
COPY e2e/dotnet/Program.cs /work/dotnet/roundtrip/Program.cs
COPY e2e/dotnet/roundtrip.csproj /work/dotnet/roundtrip/roundtrip.csproj
WORKDIR /work/dotnet
# Pre-build both projects so the run phase is fast.
RUN dotnet build tokenizetest/tokenizetest.csproj -v q && dotnet build roundtrip/roundtrip.csproj -v q
CMD sh -c '\
  echo "== PARITY (dotnet) ==" && \
  dotnet run --project tokenizetest --no-build && echo "PARITY_OK 36/36" && \
  echo "== ROUNDTRIP (dotnet) ==" && \
  dotnet run --project roundtrip --no-build'
