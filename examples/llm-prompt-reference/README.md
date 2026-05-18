# LLM moderation prompt reference

Demonstrates the LLM half of `.design/llm-moderation-assist.md` end-to-end:
loads Qwen 2.5 7B Instruct via `transformers`, sends a sample moderation case
(a spam post with 31 identical-text sibling accounts + two reports + three
observations + workbook policy clauses), and validates that the model
produces a structurally valid `RecommendResponse` JSON per design REQ-A3.

This is **reference material** — the actual production path is the gRPC
`Recommend` RPC added to `proto/polaris-classifier-v1.proto` (#231). The
operator wires any LLM behind a thin adapter that implements the same
prompt template + JSON-shape contract demonstrated here.

## Run

```sh
python3 examples/llm-prompt-reference/smoke_test_direct.py
```

Requires:
- `transformers` + `torch` on `PATH`
- A Qwen 2.5 7B Instruct checkout at `/home/doll/llm-setup/qwen-7b`
  (override `MODEL_PATH` to point elsewhere)
- ~16 GB free VRAM (fp16 load)

## What it validates

- The 7B-class open-weight model can reliably ground its decisions in the
  policy `decision_criteria` text.
- Output is single JSON object, no code fences (the model occasionally adds
  them; the test strips them defensively).
- Required fields per RecommendResponse: `event_id`, `model`,
  `recommended_actions[]` with `action_kind`, `subject_scope`, `confidence`,
  `cited_policy_identifiers`, `reasoning`.
- `cited_policy_identifiers` only contains identifiers that appeared in the
  input `policies` array — no hallucinated policy references.

## What it doesn't yet test

- The Rust gRPC adapter that translates Polaris's Recommend RPC into this
  prompt + invocation (LLM-12 / `examples/llm-fixture-adapter`).
- The Polaris-side dispatcher (LLM-5 / #242) that hydrates the case from
  the DB and routes the response through the safety floors.
- Multi-action recommendations (the current spam-only case has one
  obvious action).
