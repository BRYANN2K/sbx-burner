# syntax=docker/dockerfile:1
# TODO(verify): pin ubuntu:24.04 by digest before release.
FROM ubuntu:24.04

USER root
ENV DEBIAN_FRONTEND=noninteractive
# Platform floor: bash, curl, git, CA store, sudo and the agent user.
# /usr/local/share/ca-certificates must exist: the runtime writes the egress
# proxy CA there before merging it into the bundle.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git sudo jq python3 unzip xz-utils \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /usr/local/share/ca-certificates \
 && if id -u 1000 >/dev/null 2>&1 && [ "$(id -nu 1000)" != "agent" ]; then userdel -r "$(id -nu 1000)" 2>/dev/null || true; fi \
 && if ! id agent >/dev/null 2>&1; then useradd --create-home --home-dir /home/agent --uid 1000 --shell /bin/bash agent; fi \
 && echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent \
 && chmod 0440 /etc/sudoers.d/agent \
 && mkdir -p /home/agent/workspace \
 && chown -R agent:agent /home/agent \
 && touch /etc/sandbox-persistent.sh

ENV BASH_ENV=/etc/sandbox-persistent.sh
USER agent
WORKDIR /home/agent/workspace
ENTRYPOINT ["bash"]
CMD ["-l"]
