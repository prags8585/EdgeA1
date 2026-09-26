---
base_model: Qwen/Qwen2.5-7B-Instruct
library_name: peft
license: apache-2.0
tags:
  - lora
  - security
  - waf
  - input-validation
  - distillation
---

# NanoPot patch writer (Qwen2.5-7B LoRA)

A LoRA adapter that teaches Qwen2.5-7B-Instruct to write **input-validation rules** (a regex plus
how to apply it) that block a captured web or prompt attack without blocking normal traffic. It's
the small, fast patch writer for [NanoPot: The Shadow Alchemist](https://github.com/prags8585/EdgeA1), an AI
security layer built for the HP Edge AI SJSUHack (Secure AI track) and trained and served
entirely on an HP ZGX Nano (NVIDIA GB10).

**Not a standalone security product.** Every rule it writes is meant to go through NanoPot's deterministic tests (replay, URL-encoding, normal-traffic, ReDoS) and an independent
verifier model before it's ever applied. Don't deploy its output unchecked.

## How it was trained

- **Teacher:** `nvidia/Qwen3-Next-80B-A3B-Instruct-NVFP4`, served on the same Nano.
- **Data: 230 examples, each verified by tests, not by a model.** The teacher wrote rules for
  SQL injection, XSS, prompt injection, and jailbreak samples (public datasets: HttpParamsDataset,
  deepset/prompt-injections, jackhhao/jailbreak-classification). A rule was kept only if it
  blocked every attack it was shown *and* their URL-encoded forms, blocked none of the benign
  inputs it was shown, blocked ≤1% of 300 benign inputs it never saw, and stayed inside a 50 ms
  budget on 2 KB adversarial inputs (ReDoS check). 230 of 500 teacher attempts passed; 58% needed
  retries with feedback, and each was paired with its original first-try prompt.
- **LoRA:** r=16, alpha=32, all attention and MLP projections, bf16, 2 epochs, loss on the rule
  JSON only. 207 train / 23 validation examples, 17.7 min on the GB10, 20.4 GiB peak memory.
  Validation loss 0.678 → 0.642.

## Evaluation: attack types it never trained on

Command injection and path traversal were excluded from training entirely. 80 tasks
(40 per family), the exact production prompt, JSON-schema constrained decoding, greedy
(temperature 0), every rule scored by the same deterministic checks:

| | Base Qwen2.5-7B | **This adapter** | 80B teacher |
|---|---|---|---|
| Rule fully passes (blocks every shown attack, 0 false positives) | 3.75% | **10.0%** | 13.75% |
| Recall on unseen payloads of the same attack type | 35% | **46%** | 50% |
| False-positive rate on 300 unseen benign requests | 3.4% | **0.0%** | 0.01% |
| Output is a valid rule | 90% | **65%** | 85% |

Per family: on command injection the adapter out-passes the teacher (12.5% vs 7.5% full pass);
on path traversal it goes from 0% to 7.5% full pass and 37% to 58% recall (teacher: 20%, 65%).

## Limitations

- **Repetition loops.** About a third of greedy outputs get stuck repeating a regex fragment until
  the token cap and aren't valid JSON (a known failure mode for small fine-tuned models; a
  repetition penalty didn't help in our tests). NanoPot's pipeline retries on invalid
  output, so in practice this costs attempts, not safety.
- **Regex rules generalize poorly to natural-language attacks.** In the training data, teacher
  rules reached a median 80% recall on unseen SQL injection but only 6% on unseen prompt
  injection. NanoPot relies on a trained classifier and a honeypot for those, not regex.
- Small, public/synthetic data from one hackathon day. None of these numbers describe
  enterprise-scale performance.

## Usage

Served with vLLM alongside its base model:

```bash
vllm serve Qwen/Qwen2.5-7B-Instruct --enable-lora --max-lora-rank 16 \
  --lora-modules patchwriter=<path-to-this-adapter> --max-model-len 8192
```

Prompt format and the rule JSON schema: `chameleon/patch/writer.py` (`build_messages`,
`RULE_SCHEMA`) in the GitHub repo. Raw training and evaluation metrics are in `results/`.
