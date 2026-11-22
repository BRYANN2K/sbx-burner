# syntax=docker/dockerfile:1
FROM scratch
# No --chmod: BuildKit would also apply it to the parent dirs it creates
# (/usr, /usr/local...), and a 0644 /usr breaks every binary in the guest.
COPY lab-install.sh /usr/local/lib/agent-lab/lab-install.sh
