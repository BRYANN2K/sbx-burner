## Security gate: FAILED

| Check | Status | Findings | Blocking |
| --- | --- | --- | --- |
| secrets | fail | 2 | 2 |
| sca | fail | 1 | 1 |
| sast | fail | 1 | 1 |
| iac | fail | 17 | 3 |
| container | skipped | 0 | 0 |
| sbom | pass | 3 | 0 |
| licence | fail | 1 | 1 |

### Why the gate failed

- secrets: 2 blocking finding(s)
- sca: 1 blocking finding(s)
- sast: 1 blocking finding(s)
- iac: 3 blocking finding(s)
- licence: 1 blocking finding(s)

### Blocking findings

| Check | Severity | Rule | Location | Fix |
| --- | --- | --- | --- | --- |
| secrets | high | `github-pat` | `/home/agent/target/scripts/release.sh:2` | - |
| secrets | high | `curl-auth-header` | `/home/agent/target/scripts/release.sh:2` | - |
| sca | critical | `GHSA-xvch-5gv4-984h` | `package-lock.json:minimist@1.2.5` | 0.2.4, 1.2.6 |
| sast | high | `fixtures.python.subprocess-shell-true` | `/home/agent/target/app/tools.py:11` | - |
| iac | high | `KSV-0014` | `k8s/deployment.yaml:17` | Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'. |
| iac | high | `KSV-0017` | `k8s/deployment.yaml:17` | Change 'containers[].securityContext.privileged' to 'false'. |
| iac | high | `KSV-0118` | `k8s/deployment.yaml:15` | To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to |
| licence | high | `licence-denied` | `pkg:npm/lab-pdf-render@0.9.0` | replace the component or get a written exception |

Policy: `gate-policy.yaml` (sha256 `8dc1c9d4ca21`). Full results: `gate.sarif`.
