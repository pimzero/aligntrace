#include <assert.h>
#include <err.h>
#include <libunwind-ptrace.h>
#include <seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <asm/ptrace.h>

#define arrsze(X) (sizeof(X) / sizeof(*(X)))

enum {
	PTRACE_EVENT_mmap = 1,
	PTRACE_EVENT_munmap,
	PTRACE_EVENT_clone,
};

static struct {
	FILE* out;
	char** ignore;
	char** argv;
} conf;

static int ptrace_traceme(void) {
	return ptrace(PTRACE_TRACEME, 0, 0, 0);
}

static int ptrace_execve(const char* filename, char* const argv[],
			 char* const envp[]) {
	/* Hook mmap and munmap for ignored mapping */
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (!ctx)
		err(1, "seccomp_init");
	struct {
		int event;
		int sys;
	} rules[] = {
		{ PTRACE_EVENT_mmap, SCMP_SYS(mmap) },
		{ PTRACE_EVENT_clone, SCMP_SYS(clone) },
		{ PTRACE_EVENT_clone, SCMP_SYS(fork) },
		{ PTRACE_EVENT_clone, SCMP_SYS(vfork) },
	};

	for (size_t i = 0; i < arrsze(rules); i++) {
		if (seccomp_rule_add(ctx, SCMP_ACT_TRACE(rules[i].event),
				     rules[i].sys, 0) < 0)
			err(1, "seccomp_rule_add");
	}

	if (seccomp_load(ctx) < 0)
		err(1, "seccomp_load");

	if (ptrace_traceme() < 0)
		err(1, "ptrace_traceme");

	if (execvpe(filename, argv, envp) < 0)
		err(1, "execvpe");

	assert(0);
}

static pid_t ptrace_fork_exec(const char* filename, char* const argv[],
			      char* const envp[]) {
	pid_t pid = fork();

	if (pid < 0)
		return pid;

	if (!pid)
		ptrace_execve(filename, argv, envp);

	return pid;
}

#define ptrace_peekuser(Pid, Reg) \
	ptrace(PTRACE_PEEKUSER, Pid, offsetof(struct user_regs_struct, Reg), -1)

static long get_eflags(pid_t pid) {
	return ptrace_peekuser(pid, eflags);
}

static int set_eflags(pid_t pid, long eflags) {
	size_t eflags_offset = offsetof(struct user_regs_struct, eflags);
	return ptrace(PTRACE_POKEUSER, pid, eflags_offset, eflags);
}

static long set_ac(pid_t pid) {
	return set_eflags(pid, get_eflags(pid) | X86_EFLAGS_AC);
}

static long clear_ac(pid_t pid) {
	return set_eflags(pid, get_eflags(pid) & ~(long)(X86_EFLAGS_AC));
}

static struct user_regs_struct get_regs(pid_t pid) {
	struct user_regs_struct regs = { 0 };
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(1, "ptrace(GETREGS)");
	return regs;
}

static void pr_backtrace(pid_t pid, size_t bt) {
	void* handle = _UPT_create(pid);

	unw_cursor_t c;
	unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);

	if (unw_init_remote(&c, as, handle) != 0)
		errx(1, "unw_init_remote");

	char buf[512];
	unw_word_t off;
	int rv;

	do {
		if (unw_get_proc_name(&c, buf, sizeof(buf), &off) != 0)
			break;
			//errx(1, "unw_get_proc_name");
		unw_proc_info_t pi;
		if (unw_get_proc_info(&c, &pi) < 0)
			errx(1, "unw_get_proc_info");

		fprintf(conf.out, " - %s+%#lx (ip: %#lx)\n", buf, off,
			pi.start_ip + off);

		rv = unw_step(&c);
		if (rv < 0)
			errx(1, "unw_step");
	} while (rv > 0 && --bt);

	_UPT_destroy(handle);
}

struct object_list {
	struct object_list* next;
	long long start;
	long long end;
};

static struct object_list* ignore_list;

static int ignore_ip(long long int ip) {
	for (struct object_list* itr = ignore_list; itr; itr = itr->next)
		if (ip >= itr->start && ip < itr->end)
			return 1;

	return 0;
}

static void add_ignore_range(long long int start, long long int end) {
	struct object_list* obj = calloc(1, sizeof(*obj));
	if (!obj)
		err(1, "calloc");

	obj->start = start;
	obj->end = end;
	obj->next = ignore_list;

	ignore_list = obj;
	// TODO: handle merge ?
}

static void handle_sigbus(pid_t pid) {
	struct user_regs_struct regs = get_regs(pid);

	if (clear_ac(pid) < 0)
		err(1, "clear_ac");

	if (ignore_ip(regs.rip))
		return;

	fprintf(conf.out, "Backtrace (%#llx):\n", get_regs(pid).rip);
	pr_backtrace(pid, -1);
}

static int same_files(char* a, char* b) {
	struct stat st1, st2;

	if (stat(a, &st1) < 0 || stat(b, &st2) < 0)
		return 0;

	return st1.st_ino == st2.st_ino && st1.st_dev == st2.st_dev;
}

static int fd_in_pid_is(pid_t pid, int fd, char* file) {
	char buf[512];
	snprintf(buf, sizeof(buf), "/proc/%d/fd/%d", pid, fd);

	return same_files(file, buf);
}

static void handle_seccomp(pid_t pid) {
	long msg = 0;
	struct user_regs_struct regs;
	ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
	switch (msg) {
	case PTRACE_EVENT_mmap:
		regs = get_regs(pid);
		if (!(regs.rdx & PROT_EXEC))
			break;
		if (regs.r10 & MAP_ANONYMOUS)
			break;

		if (!regs.rdi) {
			if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
				err(1, "ptrace_syscall");
			if (waitpid(pid, NULL, __WALL) < 0)
				err(1, "waitpid");
			regs = get_regs(pid);
		}

		for (size_t i = 0; conf.ignore[i]; i++)
			if (fd_in_pid_is(pid, regs.r8, conf.ignore[i]))
				add_ignore_range(regs.rdi, regs.rdi + regs.rsi);
		break;
	case PTRACE_EVENT_clone:
		if (clear_ac(pid) < 0)
			err(1, "clear_ac");

		if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
			err(1, "ptrace_syscall");
		if (waitpid(pid, NULL, __WALL) < 0)
			err(1, "waitpid");

		if (set_ac(pid) < 0)
			err(1, "set_ac");
		break;
	default:
		fprintf(conf.out, "Unknown seccomp event\n");
	};
}

struct map_entry {
	unsigned long start;
	unsigned long end;
	int r:1;
	int w:1;
	int x:1;
	int p:1;
	size_t offset;
	dev_t dev;
	ino_t inode;
	char* path;
};

static void ignore_range_form_map_entry(struct map_entry* entry) {
	for (size_t i = 0; conf.ignore[i]; i++) {
		if (!entry->path || strcmp(entry->path, conf.ignore[i]))
			continue;
		add_ignore_range(entry->start, entry->end);
		return;
	}
}

static void iterate_maps(pid_t pid, void (*f)(struct map_entry* entry)) {
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;

	char fname[127];
	sprintf(fname, "/proc/%d/maps", pid);

	FILE *stream = fopen(fname, "r");
	if (!stream)
		err(1, "fopen");

	struct map_entry entry;

	/* TODO: can we do this with only scanf, and no getline ? */
	while ((nread = getline(&line, &len, stream)) != -1) {
		char perms[5];
		int dev_major, dev_minor;
		sscanf(line, "%lx-%lx %4c %lx %x:%x %ld %ms",
		       &entry.start, &entry.end, perms, &entry.offset,
		       &dev_major, &dev_minor, &entry.inode, &entry.path);
		entry.dev = makedev(dev_major, dev_minor);
		entry.r = perms[0] == 'r';
		entry.w = perms[1] == 'w';
		entry.x = perms[2] == 'x';
		entry.p = perms[3] == 'p';

		f(&entry);

		free(entry.path);
	}

	free(line);
	fclose(stream);
}

static void handle_init(pid_t pid) {
	if (!ignore_list)
		iterate_maps(pid, ignore_range_form_map_entry);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
}

static void handle_signal(pid_t pid, int status) {
	int sig = 0, singlestep = 0;
	switch WSTOPSIG(status) {
	case SIGTRAP:
		if (status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))) {
			handle_seccomp(pid);
		} else {
			handle_init(pid);
			set_ac(pid);
		}
		break;
	case SIGBUS:
		singlestep = 1;
		handle_sigbus(pid);
		break;
	default:
		sig = WSTOPSIG(status);
	}
	ptrace(singlestep ? PTRACE_SINGLESTEP : PTRACE_CONT, pid, 0, sig);
}

static void init_config(void) {
	static char* ignored_objects[] = {
		"/usr/lib/libc-2.29.so",
		"/usr/lib/ld-2.29.so",
		NULL,
	};

	conf.out = stderr;
	conf.ignore = ignored_objects;
}

enum {
	FLAG_CONTINUE,
	FLAG_STOP_PARSING
};

static int flag_break(char* argv0, char*** argv) {
	(void) argv0;
	++*argv;

	return FLAG_STOP_PARSING;
}

static int flag_ignore(char* argv0, char*** argv) {
	(void) argv0;

	++*argv;
	conf.ignore = *argv;

	while (**argv && strcmp("}", **argv))
		++*argv;
	if (!**argv)
		errx(1, "\"-{\" argument without ending \"}\" argument");
	**argv = NULL;

	return FLAG_CONTINUE;
}

static int flag_out(char* argv0, char*** argv) {
	(void) argv0;

	if (!(conf.out = fopen(*++*argv, "w")))
		err(1, "fopen");

	return FLAG_CONTINUE;
}

static int print_list_ignore() {
	fprintf(conf.out, "Ingored libs: {");
	for (size_t i = 0; conf.ignore[i]; i++)
		fprintf(conf.out, " %s", conf.ignore[i]);
	fprintf(conf.out, " }\n");

	return FLAG_CONTINUE;
}

static int flag_help(char* argv0, char*** argv);

static struct {
	char* flag;
	int (*func)(char* argv0, char*** argv);
	char* help;
} flags[] = {
	{ "-h", flag_help,   "         \tshow this help and exit" },
	{ "--", flag_break,  "         \tstop argument parsing" },
	{ "-{", flag_ignore, " lib... }\tignore libraries between \"-{\" and \"}\"" },
	{ "-o", flag_out,    " file    \toutput file" },
	{ "--list-ignored-libs", (void*)print_list_ignore, "\tlist ignored libs" },
};

static void print_help(char* argv0, int dump_conf) {
	fprintf(stderr, "%s flags:\n", argv0);
	for (size_t i = 0; i < arrsze(flags); i++)
		fprintf(stderr, "  %s%s\n", flags[i].flag, flags[i].help);

	if (dump_conf) {
		print_list_ignore();
	}
}

static int flag_help(char* argv0, char*** argv) {
	(void) argv;
	print_help(argv0, 1);

	exit(0);
}

static void parse_args(int argc, char** argv) {
	argc--;
	char* argv0 = *argv;
	while (*++argv) {
		if (!*argv || *argv[0] != '-') {
			break;
		}
		for (size_t i = 0; i < arrsze(flags); i++) {
			if (strcmp(flags[i].flag, *argv))
				continue;
			if (flags[i].func(argv0, &argv))
				goto stop;
			goto next;
		}
		fprintf(stderr,"Unknwon flag \"%s\"\n", *argv);
		print_help(argv0, 0);
		exit(1);
next:
		;
	}
stop:
	if (!*argv)
		errx(1, "Missing command");

	conf.argv = argv;
}

int main(int argc, char** argv, char** envp) {
	int status;

	init_config();
	parse_args(argc, argv);

	if (argc < 1)
		errx(1, "Not enough arguments");

	pid_t pid = ptrace_fork_exec(conf.argv[0], conf.argv, envp);
	if (pid < 0)
		err(1, "fork");

	while((pid = waitpid(-1, &status, __WALL)) > 0) {
		if (WIFEXITED(status)) {
			fprintf(conf.out, "child exited with status %d\n",
				WEXITSTATUS(status));
			return 0;
		}

		if (WIFSTOPPED(status))
			handle_signal(pid, status);
		else
			ptrace(PTRACE_CONT, pid, 0, 0);
	}
}
