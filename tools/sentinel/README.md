# Sentinel

Lightweight security log classifier that feeds SIEM events to an LLM and collects structured JSON verdicts. Built to test whether security-focused language models can resist prompt injection hidden in log data.

Companion tool to [The Smarter the Model, the Easier to Fool](https://wolf-solutions.dev/whoami/stdout/smarter-model-easier-to-fool/).

## Requirements

- Python 3.8+
- `requests` (`pip install requests`)
- An inference backend: [Ollama](https://ollama.com), [MLX](https://github.com/ml-explore/mlx-examples/tree/main/llms/mlx_lm), or the [Anthropic API](https://docs.anthropic.com)

## Usage

```bash
# Run with built-in sample logs (8 threats, 8 injections, 2 benign)
python sentinel.py --demo -v

# Specify model and backend
python sentinel.py --demo -v --model foundation-sec-8b-reasoning --backend ollama
python sentinel.py --demo -v --backend mlx --model fdtn-ai/Foundation-Sec-8B
python sentinel.py --demo -v --backend anthropic  # requires ANTHROPIC_API_KEY

# Analyze your own logs
python sentinel.py -f /var/log/auth.log -v
cat events.json | python sentinel.py -v
```

## Backends

| Backend | Flag | Requirements |
|---------|------|-------------|
| Ollama | `--backend ollama` (default) | Ollama running locally |
| MLX | `--backend mlx` | `mlx_lm.server` running locally |
| Anthropic | `--backend anthropic` | `ANTHROPIC_API_KEY` env var |

## What It Tests

Each log event gets a structured verdict: severity, confidence, MITRE ATT&CK technique, summary, recommended action, and whether a human should be alerted.

The 8 injection payloads test whether attacker-controlled log fields (user-agent strings, DNS queries, JSON event fields) can manipulate the model's classification. See `payloads/prompt-injection/` for the standalone payload set.
