#!/usr/bin/env bash
# Builds a throwaway infrastructure repository with planted misconfigurations:
#   bash evals/make-target.sh /tmp/iac-demo
#   python -m lab run devsecops/iac-scan --target /tmp/iac-demo
#   python -m lab eval devsecops/iac-scan --run runs/<id>
# Nothing here is deployed. The files only describe resources.
set -euo pipefail

dest="${1:?usage: make-target.sh <new-directory>}"
[ ! -e "$dest" ] || { echo "refusing to overwrite $dest" >&2; exit 1; }
mkdir -p "$dest/terraform" "$dest/k8s" "$dest/app"

# Exposure 1: SSH open to the internet. Hygiene: bucket without versioning.
cat >"$dest/terraform/main.tf" <<'TF'
resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "Bastion access"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "lab-demo-logs"
}
TF

# Exposure 2: privileged container with the host filesystem mounted.
cat >"$dest/k8s/deployment.yaml" <<'K8S'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: collector
  namespace: demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: collector
  template:
    metadata:
      labels:
        app: collector
    spec:
      containers:
        - name: collector
          image: registry.example.test/collector:1.4.2
          securityContext:
            privileged: true
          volumeMounts:
            - name: host
              mountPath: /host
      volumes:
        - name: host
          hostPath:
            path: /
K8S

# Hygiene only: runs as root, no HEALTHCHECK, mutable tag.
cat >"$dest/app/Dockerfile" <<'DOCKER'
FROM debian:latest
RUN apt-get update && apt-get install -y curl
COPY . /srv/app
CMD ["/srv/app/run.sh"]
DOCKER

echo "target ready: $dest (2 exposures, several hygiene items)"
