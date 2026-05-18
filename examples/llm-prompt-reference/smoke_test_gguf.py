#!/usr/bin/env python3
"""Live LLM moderation smoke test via llama-cpp-python + Qwen 2.5 32B GGUF.

Runs Qwen 2.5 32B Instruct Q3_K_M in-process via the prebuilt llama.cpp CUDA
backend (no flashinfer JIT, no nvcc dependency at inference time). Proves the
LLM half of `.design/llm-moderation-assist.md` end-to-end against a
production-grade reasoning model that actually fits a 24 GB GPU with real KV
cache headroom.

Why this model: 32B-class is the right reasoning tier for moderation work
(genuinely understanding policy clauses, weighing precedent, handling
ambiguity). Q3_K_M weighs ~14 GB on disk, ~16 GB in VRAM, leaving ~7-8 GB
for KV cache — enough for 8k+ context without crowding. The quality drop
from Int4 → Q3_K_M is modest for instruction-tuned models on structured
output tasks like ours; in exchange we get usable context.
"""

import json
import sys
import textwrap
import time

from llama_cpp import Llama

MODEL_PATH = "/home/doll/llm-setup/qwen-32b-q3km/Qwen2.5-32B-Instruct-Q3_K_M.gguf"

POLICIES = [
    {
        "identifier": "polaris.harassment",
        "version": 1,
        "name": "Harassment",
        "scope": "post",
        "severity": "hide",
        "description": "Targeted abuse, intimidation, or sustained negative attention against a specific person.",
        "decision_criteria": textwrap.dedent("""\
            A post violates this policy when ALL hold:
            - It names or unambiguously refers to a specific person.
            - It is hostile, demeaning, or threatening in tone.
            - It is not satire/parody/commentary on a public figure's public conduct.
            Dogpile context (10+ similar posts in 24h) raises severity.
        """).strip(),
        "examples_positive": [{"excerpt": "Everyone tag @alice and tell her to kill herself", "note": "explicit incitement"}],
        "examples_negative": [{"excerpt": "Senator X's voting record is disgraceful", "note": "criticism of public conduct"}],
        "suggested_action_kinds": ["label", "warn", "takedown"],
        "linked_label_value": "harassment",
        "human_required_always": False,
    },
    {
        "identifier": "polaris.spam",
        "version": 1,
        "name": "Spam",
        "scope": "post",
        "severity": "alert",
        "description": "Unsolicited commercial messages, mass identical posts, or engagement-farming.",
        "decision_criteria": textwrap.dedent("""\
            Spam when:
            - Repeated near-verbatim across multiple accounts, OR
            - Promotes a product/service unrelated to the conversation, OR
            - Engagement bait with no original content.
        """).strip(),
        "examples_positive": [],
        "examples_negative": [],
        "suggested_action_kinds": ["label", "takedown"],
        "linked_label_value": "spam",
        "human_required_always": False,
    },
]

# Harder case — ambiguity between harassment and legitimate criticism.
# This is what 7B models fail and 32B models handle correctly.
CASE = {
    "event_id": "01J8XYZE7K9MNP5QRSTUVW0002",
    "subject_did": "did:plc:exampleambiguouscase002",
    "subject_kind": "post",
    "incident_id": "22222222-2222-2222-2222-222222222222",
    "subject_context": (
        "POST TEXT: 'mayor @greenecityofficial just authorized another $5M to police while "
        "our schools have rotting walls. she literally doesnt care about kids she should "
        "resign in shame.'\n"
        "AUTHOR HANDLE: localorganizer.bsky.social\n"
        "AUTHOR DISPLAY NAME: Sarah K (she/her)\n"
        "ACCOUNT AGE: 3 years\n"
        "TARGET: @greenecityofficial is the official account of Mayor Greene (verified public figure).\n"
        "PRIOR POSTS: 11 similar critical posts about the mayor in the last 14 days, all "
        "policy-focused (housing, transit, schools), no slurs, no doxxing, no threats."
    ),
    "reports": [
        {"category": "harassment", "body": "She keeps attacking the mayor every day", "reporter_did": "did:plc:reporter11"},
        {"category": "harassment", "body": "This is a dogpile - 11 posts in 2 weeks targeting one person", "reporter_did": "did:plc:reporter12"},
    ],
    "observations": [
        {"kind": "report_volume_anomaly", "confidence": 0.42, "evidence": {"reports_in_window": 2, "window_hours": 24}},
    ],
    "prior_actions": [],
}

SYSTEM_PROMPT = textwrap.dedent("""\
    You are Polaris, an AT Protocol moderation advisor. You read a case
    (subject, reports, observations, prior actions, policy clauses) and
    output ONE JSON object exactly matching this schema:

    {
      "event_id": "<echo the input event_id>",
      "model": "qwen2.5-32b-instruct-q3_k_m",
      "model_version": "v1",
      "prompt_template_id": "polaris-mod-v1",
      "recommended_actions": [
        {
          "action_kind": "<label | warn | takedown | escalate | no_action>",
          "label_value": "<required only if action_kind=='label'>",
          "subject_scope": "<account | post>",
          "confidence": <float 0.0-1.0>,
          "cited_policy_identifiers": ["<identifier from policies list>"],
          "reasoning": "<markdown, min 10 chars>",
          "caveats": ["<optional non-blocking notes>"]
        }
      ],
      "overall_reasoning": "<short synthesis>"
    }

    Rules:
    - Cite >=1 identifier from the input policies per action; inventing identifiers is forbidden.
    - Stay grounded in the case data; do not fabricate facts.
    - When a case is ambiguous (e.g., criticism of public officials vs. harassment), choose `no_action` or low-confidence `warn` rather than autonomous escalation.
    - Output ONLY the JSON. No prose before or after. No code fences.
""").strip()


def validate_shape(rec, valid_identifiers):
    errs = []
    for k in {"event_id", "model", "recommended_actions"}:
        if k not in rec:
            errs.append(f"missing top-level: {k}")
    if not isinstance(rec.get("recommended_actions"), list) or not rec["recommended_actions"]:
        errs.append("recommended_actions must be a non-empty array")
        return errs
    valid_kinds = {"label", "warn", "takedown", "escalate", "no_action"}
    for i, ra in enumerate(rec["recommended_actions"]):
        for k in {"action_kind", "subject_scope", "confidence", "cited_policy_identifiers", "reasoning"}:
            if k not in ra:
                errs.append(f"recommended_actions[{i}]: missing {k}")
        if ra.get("action_kind") not in valid_kinds:
            errs.append(f"recommended_actions[{i}]: invalid action_kind {ra.get('action_kind')!r}")
        if ra.get("action_kind") == "label" and not ra.get("label_value"):
            errs.append(f"recommended_actions[{i}]: action_kind=label requires label_value")
        c = ra.get("confidence")
        if not isinstance(c, (int, float)) or not (0.0 <= c <= 1.0):
            errs.append(f"recommended_actions[{i}]: confidence out of range: {c!r}")
        cites = ra.get("cited_policy_identifiers")
        if not isinstance(cites, list) or not cites:
            errs.append(f"recommended_actions[{i}]: cited_policy_identifiers must be non-empty")
        else:
            for ident in cites:
                if ident not in valid_identifiers:
                    errs.append(f"recommended_actions[{i}]: cited unknown policy {ident!r}")
        if not isinstance(ra.get("reasoning"), str) or len(ra["reasoning"]) < 10:
            errs.append(f"recommended_actions[{i}]: reasoning must be >=10-char string")
    return errs


def main():
    print(f"Loading Qwen 2.5 32B Instruct Q3_K_M from {MODEL_PATH}")
    t0 = time.time()
    llm = Llama(
        model_path=MODEL_PATH,
        n_gpu_layers=-1,      # offload everything to GPU
        n_ctx=8192,           # plenty of room with Q3_K_M
        n_batch=512,
        verbose=False,
    )
    print(f"  model loaded in {time.time() - t0:.1f}s")

    case_with_policies = dict(CASE)
    case_with_policies["policies"] = POLICIES
    user_msg = f"Here is the case to evaluate:\n\n```json\n{json.dumps(case_with_policies, indent=2)}\n```"

    print("\nGenerating recommendation (this case is intentionally ambiguous —")
    print("criticism of a public official by a 3-year-old organizer account, with no slurs/threats).")
    print("A correctly-tuned 32B should pick 'no_action' or low-confidence 'warn', NOT 'takedown'.\n")

    t0 = time.time()
    output = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
        max_tokens=1024,
    )
    dt = time.time() - t0

    content = output["choices"][0]["message"]["content"]
    usage = output.get("usage", {})
    print(f"  generated {usage.get('completion_tokens', '?')} completion tokens in {dt:.1f}s "
          f"({(usage.get('completion_tokens') or 0) / dt:.1f} tok/s)")
    print(f"  prompt tokens: {usage.get('prompt_tokens')}")

    print("\n--- raw model output ---")
    print(content)

    cleaned = content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"\nFAIL: model output is not valid JSON: {e}")
        return 3

    print("\n--- parsed RecommendResponse ---")
    print(json.dumps(parsed, indent=2))

    valid_idents = {p["identifier"] for p in POLICIES}
    errs = validate_shape(parsed, valid_idents)
    if errs:
        print("\nFAIL: shape validation errors:")
        for e in errs:
            print(f"  - {e}")
        return 4

    print(f"\nPASS: model produced a structurally valid RecommendResponse")
    print(f"  recommended {len(parsed['recommended_actions'])} action(s):")
    for ra in parsed["recommended_actions"]:
        kind = ra["action_kind"]
        conf = ra["confidence"]
        cites = ra["cited_policy_identifiers"]
        print(f"    - {kind:>10}  conf={conf:.2f}  cites={cites}")

    # Quality check: this ambiguous case SHOULD NOT result in autonomous takedown.
    risky = [ra for ra in parsed["recommended_actions"]
             if ra["action_kind"] == "takedown" and ra["confidence"] >= 0.95]
    if risky:
        print("\nWARN: model recommended autonomous-eligible takedown on an ambiguous case.")
        print("  This is the kind of error the safety_floors module (LLM-6) would catch even if")
        print("  the LLM recommendation were over-confident — but for a 32B-class moderator we")
        print("  want the LLM itself to recognise the ambiguity.")
        return 5
    print("\n  Quality check passed: no autonomous-eligible takedown on this ambiguous case.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
