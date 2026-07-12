#!/usr/bin/env bash
#
# mayhem/build.sh — build the Lemon fuzz target + the functional test oracle.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Everything is
# ADDITIVE: no upstream file is edited. Two independent builds are produced:
#   1. an in-process libFuzzer harness `/mayhem/lemon_fuzz` (LLVMFuzzerTestOneInput over the Lemon
#      compiler front-end: lexer→parser→compiler→peephole→codegen), for local `mayhem run` fuzzing.
#   2. the DEPLOYED Mayhem target `/mayhem/lemon_fuzz-standalone`: the SAME harness linked against
#      LLVM's run-once StandaloneFuzzTargetMain and driven as a FILE-INPUT target (`@@`), also its own
#      crash reproducer. Built with -fsanitize=fuzzer-no-link so SanitizerCoverage edge counters are
#      present (Mayhem records coverage) while a per-input process turns lemon's shallow front-end
#      crashes into DEFECTS instead of stalling an in-process loop — the exact pattern the integrated
#      `ichbins` compiler uses.
#   3. a CLEAN (upstream-flags) statically-linked `lemon` binary that mayhem/test.sh RUNS as the
#      behavioral oracle (test.sh never compiles).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS STANDALONE_FUZZ_MAIN

# Relax ONLY the benign UBSan `nonnull-attribute` check, keeping ASan and the rest of UBSan
# halting. Lemon's parser makes an empty NAME/NUMBER syntax node for a zero-length token (e.g. the
# name after a stray token like `@`): syntax_make_name_node()/syntax_make_number_node()
# (src/syntax.c) call `memcpy(dst, buffer, length)` with buffer=NULL, length=0. That is harmless
# (a 0-byte copy) but trips UBSan's nonnull-attribute check (memcpy declares its src non-null) on
# essentially every non-trivial input, aborting exploration before it starts. This is the
# sanctioned narrow relax (PORTING.md "benign UB that floods under halting UBSan"); real
# memory-safety UB (out-of-bounds/UAF via ASan; signed overflow, shifts, etc. via the rest of
# UBSan) still halts and is reported as a defect.
UBSAN_RELAX="-fno-sanitize=nonnull-attribute"

cd "$SRC"

# Lemon's own compile-time definitions (mirror the upstream Makefile's Linux build, with both
# built-in modules enabled). c89/pedantic is dropped for the sanitized build so the ASan/UBSan
# instrumentation and clang extensions link cleanly; the CLEAN oracle build (step 2) keeps the
# project's exact upstream flags.
LEMON_DEFS=(-DLINUX -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -DMODULE_OS -DMODULE_SOCKET -DSTATICLIB)
LEMON_INCS=(-I"$SRC" -I"$SRC/src")

# The library sources exactly as the upstream Makefile's SRCS lists them (main.c is the CLI entry,
# excluded here — the target supplies its own; opcode.c is intentionally not part of the library,
# matching upstream).
LIB_SRCS=(
  src/lemon.c src/hash.c src/shell.c src/mpool.c src/arena.c src/table.c src/token.c
  src/input.c src/lexer.c src/scope.c src/syntax.c src/parser.c src/symbol.c src/extend.c
  src/compiler.c src/peephole.c src/generator.c src/allocator.c src/collector.c src/machine.c
  src/lnil.c src/ltype.c src/lkarg.c src/lvarg.c src/ltable.c src/lvkarg.c src/larray.c
  src/lframe.c src/lclass.c src/lsuper.c src/lobject.c src/lmodule.c src/lnumber.c src/lstring.c
  src/linteger.c src/lboolean.c src/linstance.c src/literator.c src/lfunction.c src/lsentinel.c
  src/laccessor.c src/lexception.c src/lcoroutine.c src/ldictionary.c src/lcontinuation.c
  lib/builtin.c lib/os.c lib/socket.c
)

# ── 1) The Lemon fuzz harness + deployed file-input target ─────────────────────────────────────
# ASan + UBSan, HALTING (-fno-sanitize-recover), DWARF-3. The harness (mayhem/fuzz_compile.c) exposes
# LLVMFuzzerTestOneInput, which drives the compiler front-end (no bytecode execution — executing
# attacker scripts just self-DoSes and drowns real bugs).
#
# Engine + coverage choice, established against this target's own run history AND the integrated
# `ichbins` C compiler (which crashes on random bytes exactly like lemon and reports ~105k edges):
#   * FILE-INPUT standalone driver, NOT the in-process libFuzzer loop: lemon's front-end has real
#     shallow crashes (a NULL-deref compiling `var ;`, src/compiler.c:1009; several OOB reads). A
#     per-input process reports each as a DEFECT while the run stays healthy; an in-process libFuzzer
#     loop instead dies at Mayhem's regression-sanity phase the moment one crashing input lands in the
#     accumulated testsuite.tar ("failed to fuzz for 5 iterations" → critical error).
#   * -fsanitize=fuzzer-no-link (SanitizerCoverage, NO libFuzzer main): a plain sanitized CLI is NOT
#     recognized as a fuzz target — Mayhem falls back to sanitizer-"compatible analysis" and records
#     0 edges (observed on this target's runs 18–20). Linking the harness against LLVM's
#     StandaloneFuzzTargetMain keeps the SanCov-instrumented fuzz-target structure, so Mayhem reads
#     edge coverage from the file-input binary.
echo ">> building in-process libFuzzer harness /mayhem/lemon_fuzz (ASan+UBSan halting, DWARF-3)"
# shellcheck disable=SC2086
"$CC" $SANITIZER_FLAGS $UBSAN_RELAX $LIB_FUZZING_ENGINE $DEBUG_FLAGS -fPIC \
      "${LEMON_DEFS[@]}" "${LEMON_INCS[@]}" \
      "${LIB_SRCS[@]}" mayhem/fuzz_compile.c \
      -lm -ldl -o /mayhem/lemon_fuzz

echo ">> building deployed file-input target /mayhem/lemon_fuzz-standalone (SanCov edge counters)"
# shellcheck disable=SC2086
"$CC" $SANITIZER_FLAGS $UBSAN_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS -fPIC \
      "${LEMON_DEFS[@]}" "${LEMON_INCS[@]}" \
      "$STANDALONE_FUZZ_MAIN" "${LIB_SRCS[@]}" mayhem/fuzz_compile.c \
      -lm -ldl -o /mayhem/lemon_fuzz-standalone

# ── 2) The CLEAN functional oracle: a statically-linked `lemon` built with upstream's flags ────
# NOTE: the upstream Makefile emits ./lemon into $SRC (=/mayhem); the fuzz binaries use distinct
# names so this build never clobbers them.
echo ">> building clean lemon oracle binary (upstream flags)"
make clean >/dev/null 2>&1 || true
# COVERAGE_FLAGS (empty by default) instruments only this oracle build when set.
make -j"$MAYHEM_JOBS" STATIC=1 CC="$CC" AR=llvm-ar \
     CFLAGS="-std=c89 -pedantic -Wall -Wextra -Wno-unused-parameter -I. -I./src -DLINUX -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -fPIC -O2 -DNDEBUG -DMODULE_OS -DMODULE_SOCKET -DSTATICLIB $COVERAGE_FLAGS" \
     LDFLAGS="-lm -ldl $COVERAGE_FLAGS"
cp -f lemon /mayhem/lemon-oracle

echo ">> build.sh done: /mayhem/lemon_fuzz-standalone (target+reproducer) /mayhem/lemon_fuzz /mayhem/lemon-oracle (test.sh)"
