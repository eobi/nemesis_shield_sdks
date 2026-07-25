# LLM Guard — integration examples

Every Nemesis Shield SDK ships the same **OWASP-LLM-Top-10** guard: signature rules **plus** a
**HashLR ML classifier** that catches obfuscated / paraphrased prompt injection the rules miss
(e.g. `1gn0re pr3vi0us 1nstruct10ns`). Because feature buckets are `fnv1a(feature) % dim`, every
language scores **identically** (`mlInjectionScore("1gn0re…") == 0.999944`).

Contract (all languages): `guardLLM(prompt, enforce)` → `{ blocked, severity, kind, score, owasp }`.
- `enforce = true` blocks high-severity (score ≥ 0.85); `flag` at ≥ 0.45 (review, not blocked).
- `kind`: `prompt_injection` (regex) | `ml_prompt_injection` (ML). `owasp`: `LLM01`.

| File | Language | Shows |
|------|----------|-------|
| `python_openai.py` | Python | `guard_openai` — wrap the OpenAI client, auto-guard every call |
| `python_guard.py`  | Python | `guard_llm` — manual, with system/response/tools/RAG context |
| `node_guard.mjs`   | Node   | `guardLLM` + `reportLLM` (stream behavior to the portal) |
| `go_guard.go`      | Go     | `nemesis.GuardLLM` |
| `ruby_guard.rb`    | Ruby   | `NemesisShield::LLM.guard_llm` |
| `php_guard.php`    | PHP    | `NemesisShieldLLM::guardLLM` |
| `rust_guard.rs`    | Rust   | `nemesis_shield::guard_llm` |
| `java_Guard.java`  | Java   | `NemesisShieldLLM.guardLLM` |
| `dotnet_guard.cs`  | .NET   | `NemesisShield.LlmGuard.GuardLLM` |
| `gateway.md`       | any    | drop-in reverse proxy — zero code changes |
