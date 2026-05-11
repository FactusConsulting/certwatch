# certwatch

[![Build](https://github.com/FactusConsulting/certwatch/actions/workflows/release.yml/badge.svg)](https://github.com/FactusConsulting/certwatch/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4.svg)](https://dotnet.microsoft.com/)

**Agent-friendly CLI for monitoring SSL/TLS certificate expiry across many hosts.** Designed for both humans (colored table) and agents (stable JSON + Prometheus + GitHub Actions output).

A reference implementation of the principles in [Hvorfor en god CLI ofte slår MCP for AI-agenter](https://ai-ops.dk/blog/cli-vs-mcp-for-ai-agenter) — exit codes that double as severity, multiple structured output formats, stdin support, and explicit `help-ai` guidance.

## What it does

```sh
certwatch check ai-ops.dk factus.dk          # quick table
certwatch check --from-file domains.txt      # bulk check
certwatch check ai-ops.dk --json             # stable JSON
certwatch check ai-ops.dk --prometheus       # Prometheus exposition format
certwatch check ai-ops.dk --github-actions   # CI annotations
echo "factus.dk" | certwatch check           # stdin
certwatch help-ai                            # guidance for AI agents
```

Output:

```
╭────────┬───────────────┬────────────┬──────┬────────╮
│ Status │ Host          │ Expires    │ Days │ Issuer │
├────────┼───────────────┼────────────┼──────┼────────┤
│ ✓ OK   │ ai-ops.dk:443 │ 2026-08-08 │   88 │ WE1    │
│ ✓ OK   │ factus.dk:443 │ 2026-08-08 │   88 │ WE1    │
╰────────┴───────────────┴────────────┴──────┴────────╯
Total 2 · 2 ok · 0 warning · 0 critical · 0 error
```

## Install

Single-file AOT binaries from [Releases](https://github.com/FactusConsulting/certwatch/releases) for Linux, macOS and Windows.

Or build from source:

```sh
git clone https://github.com/FactusConsulting/certwatch.git
cd certwatch
dotnet publish src/certwatch -c Release -o ./publish
```

Requires .NET 10 SDK.

## Exit codes (double as severity)

| Code | Meaning |
| ---- | ------- |
| `0`  | All OK |
| `1`  | At least one host hit warning threshold (--warn-days, default 30) |
| `2`  | At least one host hit critical threshold (--crit-days, default 7) or already expired |
| `74` | Network/handshake error on at least one host (and no critical) |
| `78` | Configuration error (file not found, no input) |

The fact that exit codes communicate severity means you can use `certwatch` directly in shell-conditional CI/scripts:

```sh
certwatch check --from-file domains.txt --quiet
case $? in
  0) echo "all good" ;;
  1) echo "renew within 30 days" ;;
  2) echo "URGENT — expires within 7 days" ; pager.sh ;;
esac
```

## Output formats

### Default — colored table

For humans in a terminal.

### `--json`

Stable snake_case JSON with summary counters:

```json
{
  "total": 2,
  "ok": 2,
  "warning": 0,
  "critical": 0,
  "errors": 0,
  "results": [
    {
      "host": "ai-ops.dk",
      "port": 443,
      "ok": true,
      "severity": "ok",
      "subject": "CN=ai-ops.dk",
      "issuer": "CN=WE1, O=Google Trust Services, C=US",
      "not_after": "2026-08-08T11:18:00Z",
      "days_remaining": 88,
      "subject_alt_names": ["DNS Name=ai-ops.dk", "DNS Name=www.ai-ops.dk"],
      "key_algorithm": "ECDSA",
      "key_size_bits": 256
    }
  ]
}
```

### `--prometheus`

Drop into a node_exporter textfile collector:

```
# HELP certwatch_days_remaining Days until certificate expiry
# TYPE certwatch_days_remaining gauge
certwatch_days_remaining{host="ai-ops.dk",port="443"} 88
certwatch_days_remaining{host="factus.dk",port="443"} 88
```

Schedule via cron:
```sh
*/15 * * * * certwatch check --from-file /etc/certwatch/domains.txt --prometheus > /var/lib/node_exporter/textfile_collector/certwatch.prom.tmp && mv /var/lib/node_exporter/textfile_collector/certwatch.prom{.tmp,}
```

### `--github-actions`

Emit `::warning::` and `::error::` annotations that show inline in PR diffs and workflow logs:

```yaml
- name: Cert health check
  run: certwatch check --from-file domains.txt --github-actions
```

## Input modes

```sh
certwatch check ai-ops.dk factus.dk           # positional args
certwatch check --from-file domains.txt       # file (# = comments)
cat domains.txt | certwatch check             # stdin
```

## License

MIT © Factus Consulting ApS
