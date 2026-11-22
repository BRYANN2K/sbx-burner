# Dependency risk table — supply-demo

| package | ecosystem | spec | pinned | install script | repository | scorecard | advisories | verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| express | npm | ^4.19.2 | no (range) | none | github.com/expressjs/express | 8.3 | none known | pin the version, add a lockfile |
| expresss | npm | latest | no | none | none declared | unassessed | unknown | hypothesis: look-alike of express, dormant since 2022 |
| lab-native-helper | npm | * | no | postinstall | none (404) | unassessed | unknown | hypothesis: no public package; install script is a finding |
| PyYAML | pypi | ==5.3.1 | yes | none (wheel) | github.com/yaml/pyyaml | 5.1 | CVE-2020-14343 (critical) | upgrade to >=5.4 |

Registry and scorecard data collected during the run; see
`registry-*.json`, `scorecard-*.json` and `osv.json`.
