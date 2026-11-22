---
name: fuzz-triage
description: Fuzz C and Go targets for a bounded time, deduplicate crashes by stack, minimise each reproducer and classify it. Use when asked to fuzz a parser, run libFuzzer, AFL++ or go test -fuzz, or triage fuzzing crashes.
---

# Fuzz and triage crashes

Budget: five minutes of fuzzing per target, then deduplicate, minimise,
classify. A crash counts only when it reproduces.

## 1. Pick the targets

Read the env vars the runner sets (`LAB_TARGET_KIND`, `LAB_TARGET_PATH`,
`LAB_DEMO`):

- `--demo` (`LAB_DEMO=1`): the bundled `fixtures/c-target` (length-prefixed
  record parser) and `fixtures/go-target` (a `FuzzParseField` test). These
  are the demo target; never fuzz them outside demo mode.
- `--target` (`LAB_TARGET_KIND=path`): the user's source at
  `$LAB_TARGET_PATH` (`/home/agent/target`, read-only). Look for harnesses
  (`fuzz_*.c`, `-fsanitize=fuzzer` builds, `Fuzz*` Go tests). Copy sources
  to a work directory — build in the workspace, never in the target.
- `--target-repo` (`LAB_TARGET_KIND=repo`): a repository cloned on the host
  and mounted at the same `$LAB_TARGET_PATH`; same steps as a path.
- No harness for a C target: write one (`LLVMFuzzerTestOneInput` calling the
  parser) or a file driver for AFL++ like `fixtures/c-target/main.c`.

## 2. C track: libFuzzer + sanitizers

```bash
mkdir -p work/c evidence/artifacts work/corpus

# Build the fuzzing binary with the sanitizer triplet.
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  fixtures/c-target/fuzz_record.c fixtures/c-target/record.c -o work/c/fuzz_record

# Seed corpus: at least one well-formed input so mutations reach deep states.
printf 'LR\x01\x03abc\x02\x02zz' > work/corpus/seed

# Fuzz five minutes. Crash artifacts land in evidence/artifacts/.
./work/c/fuzz_record work/corpus -max_total_time=300 \
  -artifact_prefix="$PWD/evidence/artifacts/" -print_final_stats=1 \
  2>&1 | tee evidence/artifacts/c-fuzz-log.txt
# TODO(verify): the libFuzzer crash exit code is documented as 77
# (-error_exitcode default); a sanitizer abort exits differently. Confirm
# on a live run.
```

## 3. C track: AFL++ alternative

```bash
# Plain afl-cc build for speed; keep a separate ASan build for triage.
afl-cc -g -O1 fixtures/c-target/main.c fixtures/c-target/record.c -o work/c/record_afl
clang -g -O1 -fsanitize=address,undefined \
  fixtures/c-target/main.c fixtures/c-target/record.c -o work/c/record_asan

# afl-fuzz in a headless VM needs these env vars:
#   AFL_SKIP_CPUFREQ     no cpufreq sysfs in a microVM
#   AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES   core_pattern/root checks
#   AFL_NO_UI            no terminal for the status screen
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 \
  afl-fuzz -i work/corpus -o work/c/afl-out -V 300 -- ./work/c/record_afl @@
cp work/c/afl-out/default/crashes/id* evidence/artifacts/ 2>/dev/null || true
cp work/c/afl-out/default/fuzzer_stats evidence/artifacts/c-fuzzer-stats.txt
```

## 4. Go track

```bash
cd fixtures/go-target   # or the target package
go test -fuzz=FuzzParseField -fuzztime=300s . 2>&1 \
  | tee "$OLDPWD/evidence/artifacts/go-fuzz-log.txt"
# exit 1 with "Failing input written to testdata/fuzz/FuzzXxx/<hash>" = crash.
cp testdata/fuzz/FuzzParseField/* "$OLDPWD/evidence/artifacts/" 2>/dev/null || true
```

## 5. Deduplicate by stack, not by file

Two inputs hitting the same bug are one crash. The signature is the top
user-code frame: same `SUMMARY` type + same `file:line` = same crash.

```bash
# Re-run every candidate on the sanitizer build; keep the report.
# libFuzzer names its output crash-<sha1>; tag each as a candidate (a plain
# `mv crash-* out` fails the moment there are two crash files).
i=0; for c in evidence/artifacts/crash-*; do
  mv "$c" "evidence/artifacts/crash-candidate-$i.bin"; i=$((i + 1))
done
for c in evidence/artifacts/crash-candidate-*.bin; do
  ./work/c/record_asan "$c" 2>&1 | grep -E 'SUMMARY|#[0-9]+ .* in ' \
    | head -3 | sed "s|^|$(basename "$c"): |"
done   # same SUMMARY + file:line = same crash; keep one reproducer per stack
./work/c/record_asan evidence/artifacts/crash-c-record.bin \
  > evidence/artifacts/c-record-stack.txt 2>&1   # aborts: crash confirmed
grep -E 'SUMMARY|#[0-9]+ .* in ' evidence/artifacts/c-record-stack.txt
```

## 6. Minimise, then classify

```bash
# libFuzzer minimiser:
./work/c/fuzz_record -minimize_crash=1 -runs=10000 evidence/artifacts/crash-candidate.bin \
  -exact_artifact_path=evidence/artifacts/crash-c-record.bin
# AFL++ minimiser:
afl-tmin -i evidence/artifacts/crash-candidate.bin \
  -o evidence/artifacts/crash-c-record.bin -- ./work/c/record_afl @@
# Go: the fuzzer already minimises; the testdata file is the reproducer.
```

Name the final input `crash-<target>.bin` and its report `<target>-stack.txt`.
Classify from the stack: `stack-buffer-overflow` (CWE-787 off-by-one write),
`heap-buffer-overflow`, `SEGV` (CWE-476 null deref), `index out of range`
panic (CWE-129), `runtime error` from UBSan (CWE-758 or narrower). The `poc`
is the single command that re-crashes the minimal input.

## 7. Stats and evidence

Write `evidence/artifacts/fuzz-stats.json`, one object per target:
`{"tool", "seconds", "execs", "unique_crashes"}`. libFuzzer prints
`stat::number_of_executed_units`; afl-fuzz writes `execs_done` in
`fuzzer_stats`; `go test` prints `fuzz: elapsed` with execs. Sum into
`metrics.execs` and `metrics.unique_crashes`.

## Pitfalls

- Counting crash files instead of crashes. Dedupe on the stack signature.
- Reporting a crash without the input that causes it. No reproducer, no
  finding: it goes to `hypotheses`.
- Forgetting seeds. A corpus with no valid input wastes the budget on the
  parser's first byte.
- Fuzzing longer than five minutes because "it almost found something".
  Write the stats and stop.
- Building inside `/home/agent/target`. It is read-only; copy sources to the
  workspace first.
