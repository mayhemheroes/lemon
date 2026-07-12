#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral functional oracle for Lemon.
#
# Upstream ships only a trivial `make test` target (runs test/test_helloworld.lm and checks the
# exit status — it asserts NOTHING about behavior, so a no-op `exit(0)` interpreter would "pass").
# This oracle therefore RUNS the pre-built clean `lemon` binary (built by mayhem/build.sh) over a
# set of scripts and DIFFS stdout against golden expected output — so a PATCH that breaks language
# behavior (or neuters the program to exit 0) FAILS here. It never compiles anything.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

LEMON="$SRC/lemon-oracle"
TESTS_DIR="$SRC/mayhem/tests"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$LEMON" ]; then
  echo "FATAL: $LEMON missing — mayhem/build.sh must build it (test.sh does not compile)" >&2
  emit_ctrf "lemon-behavioral" 0 1 0
  exit 1
fi

passed=0
failed=0

# ── Golden-output behavioral tests: stdout must match the recorded expected output exactly ────
for exp in "$TESTS_DIR"/*.expected; do
  name="$(basename "$exp" .expected)"
  script="$TESTS_DIR/$name.lm"
  got="$("$LEMON" "$script" 2>&1)"
  want="$(cat "$exp")"
  if [ "$got" = "$want" ]; then
    echo "PASS golden:$name"
    passed=$((passed + 1))
  else
    echo "FAIL golden:$name"
    echo "  --- expected ---"; echo "$want" | sed 's/^/  /'
    echo "  --- got ---";      echo "$got"  | sed 's/^/  /'
    failed=$((failed + 1))
  fi
done

# ── Upstream suite: test/test_helloworld.lm (the only runnable upstream test), asserted on output.
if [ -f "$SRC/test/test_helloworld.lm" ]; then
  got="$("$LEMON" test/test_helloworld.lm 2>&1)"
  if [ "$got" = "Hello World" ]; then
    echo "PASS upstream:test_helloworld"
    passed=$((passed + 1))
  else
    echo "FAIL upstream:test_helloworld (got: $got)"
    failed=$((failed + 1))
  fi
fi

# ── Negative test: a syntax error must be REPORTED (non-zero exit + diagnostic), not swallowed. ─
printf 'def f(var x) { return x + ;\n' > /tmp/lemon_bad.lm
err="$("$LEMON" /tmp/lemon_bad.lm 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -qi 'error'; then
  echo "PASS negative:syntax_error_detected"
  passed=$((passed + 1))
else
  echo "FAIL negative:syntax_error_detected (rc=$rc, out: $err)"
  failed=$((failed + 1))
fi

emit_ctrf "lemon-behavioral" "$passed" "$failed" 0
