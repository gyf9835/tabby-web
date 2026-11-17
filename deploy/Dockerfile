# Derived tabby-web image: adds the tabby MCP server app.
# Pinned to the currently-deployed upstream image digest so no unrelated
# database migrations run (upgrade upstream separately, with a DB backup).
FROM ghcr.io/eugeny/tabby-web@sha256:8f750f089bab81c5e7282ac10283cce356bf7299486e63b1e514101c2b94d81c

USER root
# CN mirrors for apk/pypi; OpenSSH client + sshpass for the SSH tools
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories \
    && apk add --no-cache openssh-client sshpass \
    && /venv/*/bin/pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple "pyyaml==6.0.1"

COPY overlay/ /app/
