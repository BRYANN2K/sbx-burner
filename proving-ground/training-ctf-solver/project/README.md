# Survey CTF

Two challenges, one folder each under `handout/`: read `CHALLENGE.md`, solve
with the files next to it.

Check a flag (three tries per challenge):

```sh
bash check.sh <challenge> - < flag.txt    # prints OK <challenge> or WRONG <challenge>
```

`.server/flags.sha256` holds only SHA-256 hashes of the random 128-bit
flags, for `check.sh`. It ships inside this read-only folder, so the usual
"never read `.server/`" rule has no teeth here; reading it gives nothing
usable.
