ACtrace
=======

Yet another x86/ptrace debugger

This debugger find unaligned access by setting the AC (Access Check)
bit in the tracee EFLAGS.

Alignment checks can be disabled with the following `clac` and `stac`
functions:

```
static void stac(void) {
	__asm__("pushf\n\t"
	    "orl $0x00040000, (%rsp)\n\t"
	    "popf\n\t");
}

static void clac(void) {
	__asm__("pushf\n\t"
	    "andl $~0x00040000, (%rsp)\n\t"
	    "popf\n\t");
}

int my_func() {
	/* Code that will be checked for alignment violation */

	clac();

	/* code that will not be checkde */

	stac();

	/* Code that will be checked for alignment violation */
}
```
