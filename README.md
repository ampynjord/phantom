# Phantom

Phantom is a constrained adversary emulation assistant for authorized penetration testing engagements.

## Safety model

- Hard scope validation against domain and IP allowlists
- Rules of Engagement enforcement before every module execution
- Non-destructive modules only in this baseline
- Full JSON line audit trail per run

## Autonomous agent

Run with:

```bash
pip install -r requirements.txt
python agent.py --config phantom.sample.json
```

This runs Phantom as a bounded autonomous agent and writes artifacts to reports and logs.

The decision engine is adaptive: it prioritizes modules based on target type and observed surface, records why each module was selected, and stops early when no authorized path remains.

An optional Mistral-backed planning layer can be enabled. It is advisory only: Phantom still filters every suggested step against scope and RoE, and falls back to local heuristics if the LLM is unavailable or returns invalid output.

## JSON configuration

Example payload:

```json
{
  "engagement_name": "internal-web-review",
  "targets": ["https://portal.example.com", "10.10.10.15"],
  "scope": {
    "domain_allowlist": ["example.com"],
    "ip_allowlist": ["10.10.10.0/24"]
  },
  "roe": {
    "allowed_modules": ["dns_lookup", "tcp_connect", "http_probe", "attack_path_simulation"],
    "default_ports": [80, 443, 8443],
    "max_ports_per_target": 3,
    "http_methods": ["HEAD", "GET"],
    "llm_decisioning_enabled": false,
    "llm_provider": "mistral",
    "llm_model": "mistral-small-latest",
    "llm_timeout_seconds": 15
  }
}
```

The agent prints a short execution summary to stdout. Use `--full-report` to print the full JSON result.

To enable Mistral planning, put the key in a local .env file:

```bash
MISTRAL_API_KEY=your_key_here
python agent.py --config phantom.sample.json --full-report
```

When LLM planning is enabled, target metadata and observed surface details are sent to the configured provider for planning.

Example:

```bash
python agent.py --config phantom.sample.json --full-report
```