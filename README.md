# Chameleon Edge

An AI security layer that reroutes malicious requests to a honeypot AI on the HP ZGX Nano, then turns each attack into a tested, independently verified security patch — instead of just blocking it and teaching the attacker nothing.

**30-second demo:** _TODO — record before submission (see NEXT STEPS in HANDOFF.md)._

## The problem, and who has it

**Target user:** a security engineer / SOC analyst protecting a company application from attacks, including insiders — "a cyber security professional" is one of HP's own example personas for this challenge.

- Blocking an attack teaches the defender nothing; the attacker just tries a variation.
- Studying attackers safely needs isolation, and a long attacker conversation through cloud AI costs real money per token.
- Writing and reviewing a fix for every new attack technique is slow, manual work.
- Attack data — payloads, techniques, logs — is sensitive and shouldn't leave the building to a third-party cloud.

**What it does:**
1. A fast check layer decides whether each incoming request is malicious.
2. Safe requests go straight to the protected application.
3. Malicious requests are quietly rerouted to a honeypot AI on the Nano, which keeps the attacker engaged and logs everything they try.
4. An AI on the Nano writes a security patch from the attack.
5. A second AI, from a **different model family**, plus deterministic tests, independently verifies the patch.
6. The approved patch feeds back into the check layer, so the same attack technique is caught immediately next time.

The demo covers both a regular web API (SQLi, XSS, command injection, path traversal) and an AI chatbot endpoint (prompt injection, jailbreaks). **The protected application is only a demo target — the product is the security layer in front of it.**

## Why edge, not cloud alone

- **Containment:** attacker traffic never reaches the real app; it stays trapped on one physical box.
- **Cost:** an attacker can chat with the honeypot for hours — zero marginal cost on the Nano, versus real per-token cost in the cloud.
- **Privacy / data residency:** attack logs, payloads, and patches never have to leave the Nano.
- **Works offline:** the Nano-side loop (honeypot, patching, verification) keeps running even if the cloud link drops; see "offline mode" below.

HP's own research shows attackers increasingly use AI to generate new attack variations faster than defenses can adapt (see References). Chameleon Edge answers with AI on the defense side: trap the attacker, learn from the attempt, ship a verified patch automatically. (We build on this research; HP hasn't published on this exact problem.)

## Architecture

```mermaid
flowchart TD
    R[Incoming request] --> J{Jev check<br/>cloud}
    R --> N{Nano check model<br/>trained on Nano}
    J --> D{Decision fusion<br/>+ approved patch rules}
    N --> D
    D -->|Safe| A[Demo app]
    D -->|Malicious| G[Honeypot session]
    G --> H[Honeypot AI<br/>Qwen3-Next-80B-A3B NVFP4]
    H --> L[(Attack log)]
    L --> W[Patch writer<br/>same model, role=writer]
    W --> T[Replay + normal-traffic tests]
    T --> V{Verifier AI<br/>Gemma 4 12B, different family}
    V -->|Rejected, with reason| W
    V -->|Approved| S[(Patch store)]
    S --> D
    S --> A
```

**How the check layer / router works** (`chameleon/fusion.py`, `chameleon/router.py`): every request's untrusted fields go to (a) our own classifier trained and served on the Nano, (b) Jev — TypeSafe AI's cloud decision model, when available — and (c) every currently-approved patch rule. A request is malicious if *any* signal fires. If Jev is unreachable, the system falls back to the Nano model and rules alone — this is also how "offline mode" works: set `CLOUD_ENABLED=false` and nothing changes except Jev drops out of the vote. Both scores are logged for every request (`requests` table), because the disagreement cases are the interesting evidence.

**Orchestrator** (`chameleon/orchestrator/`): decides where each AI job (honeypot turn, write patch, verify patch) actually runs. Default is always the Nano; if a job's Nano model isn't `Ready` (checked live via `zrt services --json`), it falls back to a configured cloud model (Anthropic, chosen specifically to avoid AWS — see "Attacks and defenses" below) and logs the placement, latency, tokens, and real cost. Policy lives in `config/routing.yaml`, not code.

## Attacks and defenses

| Layer | Defense |
| --- | --- |
| Isolation | Every model server is bound to `127.0.0.1`; only a keyed gateway is meant to be reachable beyond localhost (see Limitations — gateway not yet built) |
| Honeypot | Only fake data, fake credentials, fake files — never anything real |
| Canary tokens | Unique fake secrets planted in the honeypot and the demo app (`chameleon/demoapp/main.py`); if one shows up anywhere else, that's a detected leak. A canary tripping in the *real* demo app is also how an attack the check layer missed gets caught and routed into the patch loop |
| Prompt injection | Attacker text is always marked "untrusted data, not instructions" in every prompt sent to any model (honeypot, writer, verifier) |
| Patch safety | Nothing is ever auto-applied. A patch only reaches `approved` after a deterministic replay test, a deterministic normal-traffic test, *and* an independent verifier — from a different model family than the writer — all pass. Every attempt is versioned and can be rolled back |
| Verifier isolation | The verifier sees only the proposed rule and a sample of the attack, both marked untrusted — never the writer's reasoning or the raw attacker conversation, so an attacker can't hide an "approve this" instruction where the verifier would read it |
| Cloud minimization | Jev gets only what it needs to classify a request. Attack logs, patches, and analysis never leave the Nano |
| AWS sensitivity | The cloud fallback provider is Anthropic, not AWS Bedrock, since AWS people are judges for this event |

## Training pipeline on the Nano

The **check model** (`chameleon/check/`) is a TF-IDF + logistic-regression classifier trained from scratch on the Nano (`make train-check`, ~3 seconds, see `results/check_metrics.json`) — this satisfies the organizer requirement that a model we trained is hosted on the Nano, and doubles as the fallback/second-opinion check when Jev is down.

A held-out attack type (path traversal) is deliberately excluded from training (`chameleon/check/dataset.py`, `HELDOUT_ATTACK_TYPES`). Measured recall on it: **0%** — the classifier genuinely cannot catch an attack family it's never seen. That's not a bug we hid; it's the evidence for why the honeypot/patch loop exists at all. The red-team scenario (`chameleon/redteam/scenario.py`) demonstrates the system catching that exact gap: 0% detection on the first wave → the patch pipeline writes, tests, and verifies a rule → the second wave is caught, because the approved rule feeds back into the check layer.

## Benchmarks

See `docs/benchmark-methodology.md` for the full list of metrics and why each was chosen. Numbers live in `results/` (`check_metrics.json`, `llm_baseline.csv` from `scripts/bench_llm.py`) and in the dashboard's live Nano-vs-cloud table, aggregated from the `llm_calls` log.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
cp .env.example .env          # fill in HF_TOKEN, JEV_API_KEY, ANTHROPIC_API_KEY as needed
make setup                    # install Python packages
make data                     # download the check-model datasets
make train-check              # train + serve-ready the Nano check model
make test                     # unit tests

make serve-check              # check model API on :8010
make serve-demo               # demo target app on :8200
make serve-dashboard          # backend API + live dashboard on :8100
```

## ZGX Nano setup (zrt / model serving)

```bash
uname -m; nvidia-smi; zrt status; zrt models     # sanity check
zrt pull hf:nvidia/Qwen3-Next-80B-A3B-Instruct-NVFP4   # honeypot + patch writer, ~51 GB
zrt pull hf:google/gemma-4-12B-it                       # patch verifier, ~24 GB

# Serves both behind ONE shared proxy on :8080, routed by model name (not one
# port per model -- see HANDOFF.md 5.4), writer first, then verifier.
scripts/serve_models.sh
```

Every flag in `scripts/serve_models.sh` fixed a real failure we hit on the Nano (full detail in `HANDOFF.md` sections 5.4 and 6.4):
- **Context length:** `zrt serve` doesn't bound it by default. The 80B model defaulted to `max_model_len=262144` and silently OOM'd mid-startup, so we pass `--extra '--max-model-len=8192'`.
- **Kernel compilation:** on first run FlashInfer JIT-compiles CUDA kernels with ~20 parallel `nvcc` jobs, and one got OOM-killed next to the loaded model. `MAX_JOBS=4` fixes it. The first writer start takes ~15–20 min; the kernels are cached after that.
- **Memory split:** auto-sizing gave the writer 79 GB, leaving the verifier too little host RAM (CPU and GPU share the same 121 GB). We now set writer 0.45 and verifier 0.25 explicitly.
- **Proxy race:** right after a `zrt stop`, a fresh `zrt serve` can be deregistered by the proxy 2–3 seconds later even though the backend underneath is fine. The script refuses to start unless `zrt services` is empty.

To view the dashboard from a laptop: `ssh -L 8100:127.0.0.1:8100 hpX@<tailscale-ip>`, then open `http://127.0.0.1:8100`.

## API

- **Check model** (`:8010`) — `GET /health`, `POST /check {"inputs": [str, ...]}` → `{"malicious": bool, "score": float, "worst_input_index": int, "latency_ms": float}`.
- **Demo app** (`:8200`) — `GET /search?q=`, `POST /login`, `GET /files?name=`, `POST /chat`. Every endpoint enforces currently-approved patch rules before responding.
- **Dashboard/backend** (`:8100`) — `GET /` (the dashboard), `GET /api/summary|requests|sessions|patches|llm_calls`, `POST /api/scenario/run`, `POST /api/demo/reset`, `WS /ws` (live summary, once a second).

## Safety boundaries

- No real user data anywhere in the demo — products, accounts, and files are all fabricated, and canary tokens make a leak detectable immediately.
- The "attacker" in every demo/benchmark run is our own red-team script (`chameleon/redteam/scenario.py`), never a real attack against anything outside this project.
- The Nano is never exposed to the public internet; model servers are localhost-only.
- We never claim the Nano can only run one model at a time — false, and something HP judges would catch; the honest reason Jev's check runs in the cloud is that Jev is offered only as a hosted API.

## Limitations (current status)

- [x] Check model trained + served on the Nano
- [x] Honeypot AI, patch writer, verifier, patch pipeline with deterministic tests
- [x] Front door (fusion of Nano check + Jev + approved rules), orchestrator, backend API, live dashboard
- [x] Red-team scenario proving the closed loop (0% → patch → caught)
- [ ] Nano gateway (keyed reverse proxy in front of the honeypot) — not yet built; today the honeypot is called in-process, not over a network boundary
- [ ] Jev integration — client is a stub; TypeSafe AI access is still on the waitlist, so the system currently runs on the Nano check model alone
- [ ] LoRA fine-tune of a small model for the honeypot persona — the Nano check model already satisfies the "trained + hosted on Nano" requirement; the fine-tune is a stretch goal, not yet started
- [ ] Live benchmark numbers with both LLMs serving simultaneously — captured once both are up together on the Nano
- [ ] Demo video, interactive deck, Drive folder, public repo flip — final packaging, not yet done

## References

- HP research this project builds on (not "HP published this exact idea"):
  - [Low-effort AI-built attacks beating defenses](https://www.hp.com/us-en/newsroom/press-releases/2026/hp-research-low-effort-ai-attacks-beating-defenses.html)
  - [Cybercriminals leaning into agentic AI](https://www.hp.com/us-en/newsroom/press-releases/2026/hp-research-cybercriminals-leaning-into-agentic-ai-momentum-to-steal-crypto-wallets.html)
  - [HP Wolf Security Threat Insights Report, September 2026](https://threatresearch.ext.hp.com/hp-wolf-security-threat-insights-report-september-2026/)
- [Unit 42: indirect prompt injection in the wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- Datasets: [HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset) (MIT), [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification)

## Team

HP Edge AI SJSUHack, Secure AI track. Full design history and every decision's rationale: `HANDOFF.md`.
