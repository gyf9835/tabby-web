# Production deployment (NOT for local dev)

Derived-image recipe for the self-hosted tabby-web (LXC-Debian):
- Dockerfile pins the currently-running upstream digest, adds
  openssh-client/sshpass/pyyaml (CN mirrors), copies the app overlay.
- docker-compose.yml restores the tabby service + adds the
  tabby-connection-gateway service (token auth, compose-internal ws://).
- MCP_VAULT_PASSWORD goes into .env (or disable config encryption in Tabby).

Do NOT run this until the user approves the production rollout.
