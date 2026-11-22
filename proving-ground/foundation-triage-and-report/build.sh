#!/usr/bin/env bash
# Builds the triage-and-report target under $PG_BUILD/bundle: the committed
# candidates and proof files, plus the CAND-003 transcript, written here so
# its session tokens are random per build and never stored in this repo.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle="${PG_BUILD:?PG_BUILD is set by run.py}/bundle"

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
tok_a="pk_sess_$(rand_hex 20)"
tok_b="pk_sess_$(rand_hex 20)"

rm -rf "$bundle"
mkdir -p "$bundle"
cp -R "$here/project/." "$bundle/"

cat >"$bundle/proof/cand-003-transcript.txt" <<TXT
# customer 2041 reads its own parcel
GET /api/parcels/7702 HTTP/1.1
Host: parcels.lab.internal
Authorization: Bearer ${tok_a}

HTTP/1.1 200 OK
Content-Type: application/json

{"id":7702,"customer":2041,"recipient":"A. Lovelace","address":"12 rue Garibaldi, Lyon","phone":"+33 4 00 00 00 01"}

# the same session reads parcel 7731, owned by customer 3388
GET /api/parcels/7731 HTTP/1.1
Host: parcels.lab.internal
Authorization: Bearer ${tok_a}

HTTP/1.1 200 OK
Content-Type: application/json

{"id":7731,"customer":3388,"recipient":"B. Nakamura","address":"4 place du Theatre, Lille","phone":"+33 3 00 00 00 02"}

# control: customer 3388's own session gets the same record
GET /api/parcels/7731 HTTP/1.1
Host: parcels.lab.internal
Authorization: Bearer ${tok_b}

HTTP/1.1 200 OK
Content-Type: application/json

{"id":7731,"customer":3388,"recipient":"B. Nakamura","address":"4 place du Theatre, Lille","phone":"+33 3 00 00 00 02"}
TXT

echo "built $bundle ($(wc -l <"$bundle/candidates.jsonl" | tr -d ' ') candidates)"
