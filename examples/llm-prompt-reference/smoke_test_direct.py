#!/usr/bin/env python3
"""Live LLM moderation smoke test — runs Qwen 2.5 7B Instruct in-process via
transformers and proves the model produces a valid RecommendResponse-shaped
JSON for a sample moderation case.

This validates the LLM half of `.design/llm-moderation-assist.md` end-to-end
WITHOUT needing vLLM, flashinfer, AWQ, CUDA toolkit, or a separate HTTP
server. Once the model produces a clean RecommendResponse here, the rest of
the integration is the Rust gRPC adapter (LLM-12 / examples/llm-fixture-adapter)
that wraps this same prompt template + invocation behind the Recommend RPC
that LLM-1 added to `proto/polaris-classifier-v1.proto`.
"""

import json
import sys
import textwrap
import time

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_PATH = "/home/doll/llm-setup/qwen-7b"

# Policy clauses mirror mod_policies rows the workbook would seed; the
# autonomous_*, human_required_always fields demonstrate the autonomy controls.
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

# Sample case (mirrors future RecommendRequest from case_context::hydrate)
CASE = {
    "event_id": "01J8XYZE7K9MNP5QRSTUVW0001",
    "subject_did": "did:plc:examplespammeraccount001",
    "subject_kind": "post",
    "incident_id": "11111111-1111-1111-1111-111111111111",
    "subject_context": (
        "POST TEXT: 'COMMENT YES AND I WILL DM YOU THE LINK!!! Free OnlyFans starter pack, "
        "drop your handle below + repost this so others can see!!! Limited time only!!!'\n"
        "AUTHOR HANDLE: spammyfreebies.bsky.social\n"
        "AUTHOR DISPLAY NAME: Free Stuff Drops\n"
        "ACCOUNT AGE: 4 days\n"
        "PRIOR POSTS: identical text seen 47 times across 31 different accounts in last 24h"
    ),
    "reports": [
        {"category": "spam", "body": "Same exact post copy-pasted from 30+ other accounts", "reporter_did": "did:plc:reporter01"},
        {"category": "spam", "body": "Engagement farming with a fake giveaway", "reporter_did": "did:plc:reporter02"},
    ],
    "observations": [
        {"kind": "report_volume_anomaly", "confidence": 0.88, "evidence": {"reports_in_window": 5, "window_hours": 1}},
        {"kind": "account_cohort", "confidence": 0.94, "evidence": {"cohort_size": 31, "shared_signal": "identical_post_text"}},
        {"kind": "external_label", "confidence": 1.0, "evidence": {"labeler": "did:plc:bsky.social-moderation", "label": "spam"}},
    ],
    "prior_actions": [],
}

SYSTEM_PROMPT = textwrap.dedent("""\
    You are Polaris, an AT Protocol moderation advisor. You read a case
    (subject, reports, observations, prior actions, policy clauses) and
    output ONE JSON object exactly matching this schema:

    {
      "event_id": "<echo the input event_id>",
      "model": "qwen-2.5-7b-instruct",
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
    - Stay grounded in the case data; don't fabricate facts.
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
    print(f"torch {torch.__version__}, cuda {torch.cuda.is_available()}, device {torch.cuda.get_device_name(0)}")
    print(f"free VRAM: {torch.cuda.mem_get_info()[0] / 1e9:.1f} GB")

    t0 = time.time()
    print(f"Loading tokenizer from {MODEL_PATH} ...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    print(f"  tokenizer ready in {time.time() - t0:.1f}s")

    t0 = time.time()
    print("Loading model (fp16, device_map=auto) ...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH, torch_dtype=torch.float16, device_map="auto"
    )
    model.eval()
    print(f"  model ready in {time.time() - t0:.1f}s")
    print(f"  free VRAM after load: {torch.cuda.mem_get_info()[0] / 1e9:.1f} GB")

    case_with_policies = dict(CASE)
    case_with_policies["policies"] = POLICIES
    user_msg = f"Here is the case to evaluate:\n\n```json\n{json.dumps(case_with_policies, indent=2)}\n```"

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]
    inputs = tokenizer.apply_chat_template(
        messages, add_generation_prompt=True, return_tensors="pt"
    ).to(model.device)
    print(f"\nPrompt: {inputs.shape[1]} tokens. Generating ...")

    t0 = time.time()
    with torch.inference_mode():
        out = model.generate(
            inputs,
            max_new_tokens=1024,
            do_sample=False,
            temperature=1.0,
            top_p=1.0,
            pad_token_id=tokenizer.eos_token_id,
        )
    dt = time.time() - t0
    text = tokenizer.decode(out[0][inputs.shape[1]:], skip_special_tokens=True)
    print(f"  generated {out.shape[1] - inputs.shape[1]} tokens in {dt:.1f}s ({(out.shape[1] - inputs.shape[1]) / dt:.1f} tok/s)")

    print("\n--- raw model output ---")
    print(text)

    cleaned = text.strip()
    if cleaned.startswith("```"):
        # strip code fences if the model added them despite instructions
        lines = cleaned.split("\n")
        if lines[0].startswith("```"):
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
