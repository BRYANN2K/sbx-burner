# syntax=docker/dockerfile:1
FROM scratch
COPY --chmod=0644 lab-install.sh /usr/local/lib/agent-lab/lab-install.sh
