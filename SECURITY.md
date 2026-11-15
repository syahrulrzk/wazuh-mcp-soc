# Security Policy

This project is intended to run near a Wazuh all-in-one node and can read from
Wazuh Indexer using local certificates.

## Do Not Commit

- Wazuh/OpenSearch private keys, certificates, or passwords.
- `.env` files.
- Saved object backups from `.kibana`.
- Real alert exports, incident evidence, IP allowlists, or customer data.

The repository `.gitignore` excludes common local secrets and generated backup
folders, but review `git status` and `git diff --cached` before every push.

## Reporting Issues

Open a private security advisory or contact the maintainers privately if you
find a vulnerability that could expose credentials, saved object data, or alert
contents.
