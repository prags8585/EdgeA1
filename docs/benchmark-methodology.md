# Benchmark methodology

Every number below is measured on the assigned HP ZGX Nano (GB10, 128 GB
unified memory), never on a laptop or the cloud, unless a row explicitly
says "cloud" for comparison. All training/evaluation data is public
benchmark data (see `README.md`'s dataset table) or synthetic data we
generated ourselves; none of it is real user data. We report held-out
results, not just training-family results, and we don't tune anything to
hide a bad number -- the 0% held-out recall in the check-model metrics
(section "Check layer" below) is the reason this whole project exists, not
a bug we hid.

## Why these metrics

| Area | Metric | Why we chose it |
| --- | --- | --- |
| Check layer | Detection rate (attacks correctly rerouted) | The honeypot only sees an attacker if the check layer actually reroutes them -- this is the gate the whole product depends on. |
| Check layer | False-positive rate (real users wrongly rerouted) | A layer that traps real users is worse than useless; we'd rather under-block than annoy or lock out legitimate traffic. |
| Check layer | Added delay per normal request (median, p95) | The whole pitch is that normal users shouldn't feel the security layer. If p95 delay is high, that pitch is false. |
| Check layer | Nano check model vs Jev: accuracy, latency, cost | This is the organizer-required comparison (a model we trained, hosted on the Nano, vs. a cloud API) -- see HANDOFF.md section 3, organizer answer 2. |
| Check layer | Recall on the **held-out attack type**, before vs. after the patch loop learns it | This is the core proof the system *learns*, not just that it has a good classifier on day one. |
| Honeypot | Attacker engagement time, messages per session | A convincing decoy wastes more attacker time and captures more technique detail than a one-line rejection. |
| Honeypot | Canary tokens triggered | Tells us exactly what an attacker tried to exfiltrate, and when -- the same signal that catches a check-layer miss in the real demo app. |
| Patching | Time from attack to approved patch | This is the "speed of learning" number for the pitch. |
| Patching | % of patches that block the attack on replay; % that break normal traffic | Quality and safety of the automatically-generated fix, independent of any AI's self-report. |
| Verification | Patches the verifier rejected that the writer thought were good | Direct evidence that a second, differently-trained model catches mistakes the first one makes. |
| Re-attack | Attack success before vs. after patching (including new variations of the same technique) | Proves the app actually got stronger, not just that one exact payload got blocked. |
| Orchestrator | Jobs run on Nano vs. cloud, with the reason, latency, tokens, $ | Organizer answer 1 asked for exactly this: share what ran where, and what it cost. |
| Edge vs. cloud | Cost per 1,000 attacker sessions, Nano vs. the same workload priced on a cloud model | The core "why edge" cost argument -- honeypot conversations can run for hours with zero marginal cost on the Nano. |
| Edge vs. cloud | Bytes of attack data sent off the Nano (target: 0 with cloud disabled) | The data-residency argument: attack payloads, logs, and patches never have to leave the box. |
| Fine-tuning | Base vs. fine-tuned model on the relevant task metric | Shows the on-device training step actually helped, rather than just checking an organizer requirement box. |
| System | Throughput and memory use with both LLMs running together | Proves the two-model plan (writer + verifier) actually fits the Nano's 128 GB, not just in theory. |

## Hardware and network conditions

Recorded next to every latency number in the results files:
- GPU: NVIDIA GB10 (Grace Blackwell), 128 GB coherent unified memory, reported by `nvidia-smi`.
- Concurrent load on the box at benchmark time (from `zrt status` / `nvidia-smi`).
- Network: SSH over Tailscale from the developer's laptop to the Nano; all inference traffic is localhost-only on the Nano itself, so laptop network conditions don't affect these numbers (only the SSH tunnel used to view the dashboard does, and that's not benchmarked).

## Where each number comes from

| Result file | Produced by |
| --- | --- |
| `results/check_metrics.json` | `make train-check` (`chameleon/check/train.py`) |
| `results/llm_baseline.csv` | `scripts/bench_llm.py --model <writer\|verifier> --n 50 --concurrency 1 4 8` |
| Detection-rate before/after, patch pipeline timings | `chameleon/redteam/scenario.py` (also runnable from the dashboard's "Run red-team scenario" button) |
| Nano vs. cloud cost/latency table | `llm_calls` table (SQLite), aggregated at `/api/summary` and shown on the dashboard |

## Cloud pricing

Cloud $ figures use `CLOUD_PRICE_IN_PER_1K` / `CLOUD_PRICE_OUT_PER_1K` in `.env`, entered by hand from the provider's current public price page at the time of the benchmark run -- never hardcoded in source, and never presented as a promise about future pricing.

## Honesty rules (kept from HANDOFF.md section 10)

- All training/eval data is public or synthetic; this is stated everywhere a number appears.
- Held-out results are reported alongside training-family results, not instead of them.
- No number here is presented as representative of enterprise-scale performance -- this is a single Nano, single-team, one-week prototype.
- Every number in `results/` was actually measured by the scripts above on this hardware; nothing here is estimated or invented.
