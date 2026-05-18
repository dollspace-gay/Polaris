# LLM moderation prompt reference

Demonstrates the LLM half of `.design/llm-moderation-assist.md` end-to-end:
loads Qwen 2.5 32B Instruct (Q3_K_M GGUF, ~14 GB on disk, ~16 GB in VRAM)
via `llama-cpp-python`, sends a moderation case + workbook policy clauses,
and validates that the model produces a structurally valid
`RecommendResponse` JSON per design REQ-A3.

This is **reference material** — the actual production path is the gRPC
`Recommend` RPC added to `proto/polaris-classifier-v1.proto` (#231). The
operator wires any LLM behind a thin adapter that implements the same
prompt template + JSON-shape contract demonstrated here.

## Two test variants in this directory

| File | Model | Engine | Purpose |
|---|---|---|---|
| `smoke_test_direct.py` | Qwen 2.5 7B Instruct (fp16, ~15 GB) | `transformers` | Quick proof of plumbing — JSON shape validation only. **Not** representative of production moderation quality (7B is too small for nuanced cases). |
| `smoke_test_gguf.py` | Qwen 2.5 32B Instruct Q3_K_M (~14 GB) | `llama-cpp-python` (CUDA) | The realistic test — 32B-class reasoning that handles the ambiguous "criticism vs harassment" case correctly. **This is the model class operators should run.** |

## Run

```sh
# 32B (recommended — real reasoning quality)
python3 examples/llm-prompt-reference/smoke_test_gguf.py

# 7B (quick plumbing check, not representative)
python3 examples/llm-prompt-reference/smoke_test_direct.py
```

Requires (for the 32B path):
- `llama-cpp-python` built with CUDA: `CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python`
- A Q3_K_M GGUF of Qwen 2.5 32B Instruct at `/home/doll/llm-setup/qwen-32b-q3km/`
  (override `MODEL_PATH` in the script if elsewhere)
- ~16 GB free VRAM
- A CUDA toolkit (we tested against 13.1 + `cuda-toolkit-13-1` for nvcc)

## What `smoke_test_gguf.py` validates

The test case is intentionally **ambiguous** — a 3-year-old organizer account
criticising a public mayor on policy issues (housing/transit/schools), 11
similar posts in 2 weeks but **no** slurs, doxxing, or threats. Two
harassment reports filed. A poorly-tuned model (7B-class, over-zealous
heuristic) would call this `takedown` from the dogpile signal alone. A
correctly-tuned 32B reads the post, recognises public-figure-criticism as
protected speech, sets a **low** confidence (~0.6, below the 0.95
autonomous floor), and recommends `warn` at most — leaving the safety
floors to downgrade autonomy to `manual` human review.

The test asserts:

- Output is single JSON, matches `RecommendResponse` schema (REQ-A3).
- `cited_policy_identifiers` only contains identifiers from the input
  policies list — no hallucinated policy references.
- Required fields per recommended action present.
- **Quality gate**: no `takedown` with `confidence >= 0.95` on this case.
  If a model emits one, the test reports it as a warning — that's the
  miscalibration the LLM-6 (#235) safety_floors module exists to catch.

## What it doesn't test

- The Rust gRPC adapter that translates Polaris's `Recommend` RPC into
  this prompt + invocation. The in-tree
  [`examples/llm-fixture-adapter/`](../llm-fixture-adapter/) is the
  shipped Rust starter — it returns canned responses, so operators
  fork it as a skeleton and replace the `Recommend` body with the
  call into their model runtime (vLLM, llama.cpp HTTP API, Bedrock,
  Anthropic, OpenAI, …).
- The Polaris-side dispatcher
  (`polaris-backend/src/llm/recommend_dispatcher.rs`) that hydrates
  the case from the DB and routes the response through the eight
  safety floors. The dispatcher is exercised by
  `polaris-backend/tests/llm_safety_floors.rs` (15 cases) and
  `polaris-backend/tests/llm_kill_switch.rs`.
- Multi-action recommendations. The shape is supported on the wire
  (`recommended_actions` is a list); the smoke test only validates
  the head element.
- Production-scale throughput. This is single-request, in-process;
  vLLM / TensorRT-LLM would push tokens/sec 2–3× higher.
