# Wazuh MCP SOC

Local MCP server and SOC dashboard toolkit for Wazuh.

It connects to Wazuh Indexer/OpenSearch using the existing local admin
certificate and can help with SOC triage, alert search, vulnerability summaries,
Nginx/web attack analysis, authentication review, FIM visibility, and saved
object dashboard installation.

## Features

- MCP stdio server for local Wazuh analysis.
- No third-party Python dependencies.
- Local CLI mode for testing every MCP tool.
- Saved object backup helper for `.kibana`.
- Dashboard generators for:
  - SOC Priority Queue
  - SOC Triage
  - Nginx Attack Overview
  - Access Anomaly
  - Authentication Overview
  - SSH Brute Force Deep Dive
  - Credential Abuse
  - Compromise Timeline
  - Attacker Intelligence
  - Critical Host
  - Vulnerability Exposure
  - FIM Overview

## Requirements

- Python 3.8+
- Git
- curl
- Wazuh all-in-one or a host with network access to Wazuh Indexer
- Certificate/key access for the Wazuh Indexer API
- Existing Wazuh Dashboard saved object index, usually `.kibana`

## Required Tools

This project uses only the Python standard library. No `pip install` step is
required.

Check required tools:

```bash
python3 --version
git --version
curl --version
```

Install them on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3 git curl
```

Optional: use an MCP-capable client if you want to run the server through MCP.
Dashboard installation and CLI checks only need `python3`.

Default index settings:

```text
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_ALERT_INDEX=wazuh-alerts-4.x-*
WAZUH_VULN_INDEX=wazuh-states-vulnerabilities-*
WAZUH_KIBANA_INDEX=.kibana
```

Default certificate paths:

```text
WAZUH_INDEXER_CERT=/etc/wazuh-indexer/certs/admin.pem
WAZUH_INDEXER_KEY=/etc/wazuh-indexer/certs/admin-key.pem
WAZUH_INDEXER_CA=/etc/wazuh-indexer/certs/root-ca.pem
```

## Installation

Clone the repository:

```bash
git clone https://github.com/syahrulrzk/wazuh-mcp-soc.git
cd wazuh-mcp-soc
```

Copy the example environment file:

```bash
cp .env.example .env
```

Review `.env` and adjust the Indexer URL, index names, or certificate paths if
your Wazuh installation uses different values:

```bash
nano .env
```

Load the environment variables for the current shell if you changed `.env`:

```bash
set -a
. ./.env
set +a
```

Test the connection:

```bash
python3 wazuh_mcp.py --tool health_check
```

If `health_check` returns cluster health and document counts, the MCP server can
read from Wazuh Indexer.

Back up Wazuh Dashboard saved objects before installing dashboards:

```bash
python3 wazuh_mcp.py --tool backup_saved_objects
```

Install dashboards:

```bash
python3 create_nginx_dashboard.py --install
python3 create_access_anomaly_dashboard.py --install
python3 create_auth_dashboard.py --install
python3 create_ssh_bruteforce_dashboard.py --install
python3 create_soc_expansion_dashboards.py --install
python3 create_soc_priority_dashboard.py --install
python3 create_fim_dashboard.py --install
```

Dashboard installer scripts write directly to the local `.kibana` saved object
index. The certificate/user must have permission to write saved objects.

Generated NDJSON files are written to `./dashboards` by default. Override with:

```bash
export WAZUH_MCP_DASHBOARD_DIR=/tmp/wazuh-dashboards
```

## Quick Start

```bash
git clone https://github.com/syahrulrzk/wazuh-mcp-soc.git
cd wazuh-mcp-soc
cp .env.example .env
python3 wazuh_mcp.py --tool health_check
python3 wazuh_mcp.py --tool backup_saved_objects
python3 create_soc_priority_dashboard.py --install
```

The scripts read configuration from environment variables. You can either
export them in your shell or load them from `.env` with your own shell tooling.

## MCP Client Config

Use stdio mode:

```json
{
  "mcpServers": {
    "wazuh-mcp-soc": {
      "command": "/path/to/wazuh-mcp-soc/run.sh"
    }
  }
}
```

## CLI Examples

```bash
python3 wazuh_mcp.py --tool health_check
python3 wazuh_mcp.py --tool top_alerts --args '{"hours":24,"min_level":7,"size":10}'
python3 wazuh_mcp.py --tool search_alerts --args '{"hours":6,"min_level":10,"size":5}'
python3 wazuh_mcp.py --tool vulnerability_summary --args '{"size":10}'
python3 wazuh_mcp.py --tool analyze_nginx_traffic --args '{"hours":24,"size":10}'
python3 wazuh_mcp.py --tool analyze_access_anomalies --args '{"hours":24,"size":10}'
python3 wazuh_mcp.py --tool analyze_authentication_traffic --args '{"hours":24,"size":10}'
python3 wazuh_mcp.py --tool analyze_ssh_bruteforce --args '{"hours":24,"size":10}'
python3 wazuh_mcp.py --tool analyze_soc_priority_queue --args '{"hours":24,"size":10}'
python3 wazuh_mcp.py --tool backup_saved_objects
```

## MCP Tools

- `health_check`: Wazuh Indexer health, document counts, saved object types.
- `top_alerts`: top rules, agents, groups, source IPs, and levels.
- `search_alerts`: alert search by time, minimum rule level, agent, rule ID, and text.
- `agent_summary`: registered agents plus agents producing alerts.
- `vulnerability_summary`: vulnerability count by severity, agent, package, and CVE.
- `analyze_nginx_traffic`: Nginx/web traffic, status codes, methods, URLs, sources, attack categories.
- `analyze_access_anomalies`: attack-like HTTP 200 analysis by source IP.
- `analyze_authentication_traffic`: login success/failure, brute force, target users, source IPs.
- `analyze_ssh_bruteforce`: SSH-specific brute force and login analysis.
- `analyze_soc_priority_queue`: ranked host/source-IP triage queue.
- `backup_saved_objects`: local NDJSON backup of `.kibana`.
- `create_dashboard_ndjson`: minimal generated dashboard with recent high-value alerts.

## Security Notes

This project runs with whatever Indexer permissions your certificate/user has.
Use a read-only or least-privilege account where possible. Dashboard installer
scripts need permission to write saved objects into `.kibana`.

Do not publish:

- `backups/`
- `.env`
- certificates or private keys
- real alert exports
- customer/internal incident data

## License

MIT
