# vuln-node-app (shared group-C target)

`corner-shop-api`: a tiny Express shop used as the user-like target for the
pentest web recipes. Run it only through `burner` / the sandbox — it is
deliberately vulnerable and must never bind a host interface.

- `npm start` → `http://127.0.0.1:3000` (`PORT`, `BIND_ADDR` overridable).
- `build.sh` → `pg/vuln-node-app:latest` for `--target-image` runs and a
  source copy under `$PG_BUILD/app` for path mounts. It builds with the host
  runtime the runner uses (`LAB_HOST_RUNTIME`, else Docker, else Apple
  `container`). Nothing here starts a container on the host.
- Two test accounts with random passwords are generated per build: baked
  into the image as `seed-users.json` and written to
  `$PG_BUILD/app/credentials.json` (`[{username, password}]`, the shape
  api-greybox reads). `POST /api/register` creates more, each with its own
  basket, so two self-registered accounts can prove the basket IDOR.
- `openapi.yaml` → the API contract used by `pentest-api-greybox`; it
  deliberately omits `/api/admin/metrics` (schema-vs-live gap).
- `url`-kind runs are pending across group C: a host-listening URL is not
  reachable from inside the sandbox until `--target-host-port` lands.

## Planted issues

| Route | Issue | Class |
| --- | --- | --- |
| `GET /api/baskets/:id` | any bearer token reads any basket | IDOR / broken access control |
| `GET /api/admin/metrics` | internal metrics, no auth at all | missing authentication |
| `GET /search?q=` | `q` reflected unescaped into HTML | reflected XSS |
| `GET /backup/` | directory listing of database backups | exposed directory listing |

Safe look-alikes (must NOT be reported): `/echo` escapes input,
`/api/profile` checks the caller's token properly, `/api/products*`
is intentionally public. Session tokens are minted at boot, so committed
files carry no credential-shaped literals.
