# timesheet-api

Internal timesheet API. Sessions are `Bearer <user>.<hmac>` tokens signed
with `TS_SIGNING_KEY`; Postgres settings come from the usual `PG*` variables.

```sh
npm start        # 127.0.0.1:8080
npm test
```

Mobile app 1.x sessions (`Bearer m1:<name>`) are accepted until the 2.x
rollout is complete.
