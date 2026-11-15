# Contributing

Thanks for helping improve Wazuh MCP SOC.

## Development

This project intentionally uses only the Python standard library. Keep new
features dependency-free unless there is a strong reason not to.

Before opening a pull request:

```bash
python3 -m py_compile *.py
python3 wazuh_mcp.py --tool health_check
```

## Dashboard Generators

Dashboard scripts generate OpenSearch Dashboards saved objects and can install
them directly into the local `.kibana` saved object index. Keep generated
NDJSON out of commits unless the project policy changes.

## Safety

Never include real customer logs, alert evidence, saved object backups,
certificates, private keys, or passwords in issues or pull requests.
