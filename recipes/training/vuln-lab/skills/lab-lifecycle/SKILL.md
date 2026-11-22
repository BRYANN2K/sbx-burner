---
name: lab-lifecycle
description: Start, check and reset the local training targets (OWASP Juice Shop on localhost:3000, DVWA on localhost:8081) with docker compose. Use when asked to start the lab, wait for the targets, see why a target is down, or reset / clean up the vulnerable lab.
---

# Lab lifecycle

The targets run in the sandbox's private Docker Engine. `fixtures/lab.sh`
wraps `docker compose` with the pinned `fixtures/compose.yaml`. The three
images were pulled by `tools/install.sh`, so `up` only starts containers and
needs no network.

## 1. Start

```bash
mkdir -p evidence/artifacts
bash fixtures/lab.sh up   > evidence/artifacts/lab-health.txt 2>&1; echo "up exit: $?"
bash fixtures/lab.sh wait >> evidence/artifacts/lab-health.txt 2>&1; echo "wait exit: $?"
bash fixtures/lab.sh status >> evidence/artifacts/lab-health.txt 2>&1
```

`wait` returns when both of these answer `200`:

- `http://localhost:3000/rest/admin/application-version`
- `http://localhost:8081/setup.php`

Record the Juice Shop version for the summary:

```bash
curl -s http://localhost:3000/rest/admin/application-version \
  >> evidence/artifacts/lab-health.txt
```

## 2. When a target does not start

```bash
docker compose -f fixtures/compose.yaml --env-file fixtures/.env logs --tail 80 \
  > evidence/artifacts/lab-logs.txt 2>&1
```

Questions to answer from the log:

1. Is an image missing? It should have been pulled at install. Do not pull
   yourself: the registries are closed for the agent step. Record it and
   stop.
2. Is `dvwa-db` unhealthy? DVWA waits for it. Run `wait` once more.
3. Is a port already taken? Something else listens on 3000 or 8081: reset,
   then start again.

Two failed `wait` calls end the run (see the stop conditions).

## 3. Reset

```bash
bash fixtures/lab.sh reset > evidence/artifacts/reset.txt 2>&1; echo "reset exit: $?"
```

`reset` runs `docker compose down -v --remove-orphans`, deletes the generated
`fixtures/.env`, and checks that neither port answers. Exit code 0 and the
line `reset: containers and volumes removed` are the reset proof. Record both.

## Pitfalls

- Stopping without a reset. The reset is part of the task, also after a
  failure.
- Calling `docker compose` without `--env-file fixtures/.env`: the compose
  file refuses to start without the generated database password.
- Copying `fixtures/.env` into the evidence. It holds a password.
- Reading "containers are up" as "targets are ready". Only `wait` proves it.
