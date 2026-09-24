# Chameleon Edge

An AI security layer that reroutes malicious requests to a honeypot AI on the HP ZGX Nano, then turns each attack into a tested, independently verified security patch.

Full architecture: see the team's architecture doc.

## Status

- [x] Check model: a malicious-vs-safe classifier, trained and served on the Nano
- [ ] Honeypot AI (Qwen via vLLM)
- [ ] Patch writer, replay and normal-traffic tests
- [ ] Patch verifier (Mistral or Gemma via vLLM)
- [ ] Orchestrator and dashboard

## Check model

Trained on three public datasets, merged into one `malicious / safe` label:

| Dataset | Covers | License |
| --- | --- | --- |
| [HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset) | Web attacks: SQL injection, XSS, command injection, path traversal | MIT |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Prompt injection against AI apps | Check the dataset page |
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Jailbreak prompts | Check the dataset page |

Path traversal is held out of training entirely (`data/check/heldout.csv`), to measure how the model handles an attack type it has never seen.

### Run on the Nano

```bash
python3 -m venv .venv && source .venv/bin/activate
make setup          # install Python packages
make data           # download the datasets into data/raw/
make train-check    # build splits, train, write models/ and results/check_metrics.json
make test           # unit tests
make serve-check    # API on 127.0.0.1:8010 (localhost only)
```

Try it:

```bash
curl -s -X POST 127.0.0.1:8010/check -H 'Content-Type: application/json' \
  -d '{"inputs": ["john smith", "1 union select username, password from users--"]}'
# {"malicious": true, "score": 0.99, "worst_input_index": 1, "latency_ms": 2.1}
```

`inputs` holds one entry per untrusted field of a request (each URL or form parameter value, or a chat message). The request is scored by its most suspicious input.

The Nano is wiped after the event: push code to GitHub and upload `models/` to Hugging Face at the end of each day.
