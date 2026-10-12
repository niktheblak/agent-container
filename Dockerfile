FROM debian:trixie-slim

ARG UID=10001
ARG GID=10001

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git openssh-client ripgrep jq \
      nodejs npm golang-go \
    && rm -rf /var/lib/apt/lists/* \
    # strip setuid/setgid bits from everything; nothing in here needs them
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null

# the agent itself; swap for whatever you run
RUN npm install -g @anthropic-ai/claude-code

RUN groupadd -g ${GID} agent \
    && useradd -m -u ${UID} -g ${GID} -s /bin/bash agent

USER agent
WORKDIR /work
ENV HOME=/home/agent

ENTRYPOINT ["claude"]
