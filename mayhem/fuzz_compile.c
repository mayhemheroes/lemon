/*
 * fuzz_compile.c — libFuzzer-style harness for the Lemon compiler front-end.
 *
 * LLVMFuzzerTestOneInput feeds the fuzz bytes straight to lemon_compile(), exercising the SAME
 * front-end code path as the upstream `lemon` CLI — lexer, parser, compiler, peephole optimizer,
 * bytecode generator and collector — WITHOUT running the compiled bytecode (no
 * lemon_machine_execute): executing attacker-controlled scripts just self-DoSes (os.exit/os.system,
 * `while (1) {}`, unbounded allocation) and drowns real front-end memory-safety bugs under
 * "uncontrolled resource consumption" timeouts. Fuzzing the language processor is the target.
 *
 * The DEPLOYED Mayhem target links this harness against LLVM's StandaloneFuzzTargetMain (a run-once,
 * read-one-file driver) and is fuzzed as a FILE-INPUT target (`/mayhem/lemon_fuzz-standalone @@`):
 * lemon's front-end has real shallow crashes (a NULL-deref compiling `var ;`, src/compiler.c:1009;
 * several OOB reads), so a per-input process reports each as a DEFECT while the run stays healthy,
 * whereas an in-process libFuzzer loop dies at Mayhem's regression-sanity phase the moment one such
 * input lands in the accumulated corpus. -fsanitize=fuzzer-no-link keeps SanitizerCoverage edge
 * counters so Mayhem records coverage (this is the same pattern the integrated `ichbins` compiler
 * uses).
 */
#include "lemon.h"
#include "input.h"
#include "lstring.h"
#include "lib/builtin.h"

#ifdef MODULE_OS
#include "lib/os.h"
#endif

#ifdef MODULE_SOCKET
#include "lib/socket.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Disable ONLY LeakSanitizer while keeping ASan (heap overflow/UAF/etc.) and UBSan halting.
 *
 * Lemon's custom pool allocator never reclaims its large-allocation path: allocator_alloc()
 * (src/allocator.c) sends any request with (size>>3) >= ALLOCATOR_POOL_SIZE (32) straight to
 * malloc() with a NULL pool back-pointer, and allocator_destroy() only walks the pools — so those
 * blocks are leaked on teardown, exactly as the upstream CLI leaks them on exit. lexer_scan_name()
 * allocates a fixed LEMON_NAME_MAX (256) byte buffer for EVERY identifier/keyword token, which
 * lands on that leaked large-allocation path, so LSan fires on essentially every non-trivial input
 * and makes leak detection unusable for coverage-driven fuzzing. This is the sanctioned
 * process-lifetime-allocation case for detect_leaks=0 (see PORTING.md harness-quality policy); the
 * leak is a real, known upstream defect recorded in the integration notes, not hidden by relaxing
 * ASan/UBSan (which stay on and halting).
 */
const char *
__asan_default_options(void)
{
	return "detect_leaks=0";
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lemon *lemon;
	char *buffer;

	lemon = lemon_create();
	if (!lemon) {
		return 0;
	}
	builtin_init(lemon);

#ifdef MODULE_OS
	lobject_set_item(lemon,
	                 lemon->l_modules,
	                 lstring_create(lemon, "os", 2),
	                 os_module(lemon));
#endif

#ifdef MODULE_SOCKET
	lobject_set_item(lemon,
	                 lemon->l_modules,
	                 lstring_create(lemon, "socket", 6),
	                 socket_module(lemon));
#endif

	/*
	 * input_set_buffer stores the pointer directly (no copy) and reads up to
	 * `size` bytes; keep a private, NUL-terminated copy alive across the
	 * compile and free it afterwards (lemon_destroy does not own it).
	 */
	buffer = malloc(size + 1);
	if (!buffer) {
		lemon_destroy(lemon);
		return 0;
	}
	if (size) {
		memcpy(buffer, data, size);
	}
	buffer[size] = '\0';

	lemon_input_set_buffer(lemon, "fuzz.lm", buffer, (int)size);
	lemon_compile(lemon);

	lemon_destroy(lemon);
	free(buffer);

	return 0;
}
