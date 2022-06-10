// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "xdp_dropall.skel.h"

static struct env {
	bool verbose;
	int ifindex;
} env;

const char *argp_program_version = "xdp_dropall 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF xdp_dropall demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./xdp_dropall ifindex [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "ifindex", 'i', "IFINDEX", -1, "Network interface index to attach to." },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		errno = 0;
		env.ifindex = -1;
		env.ifindex = strtol(arg, NULL, 10);
		if (errno || env.ifindex <= 0) {
			fprintf(stderr, "Invalid ifindex: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct xdp_dropall_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = xdp_dropall_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = xdp_dropall_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	env.ifindex = 2;

	/* Attach tracepoints */
	// struct bpf_link bpf_program__attach_xdp(const struct bpf_program, int ifindex)
	/*
	 * struct bpf_link {
	 *		atomic64_t refcnt;
	 * 		u32 id;
	 * 		enum bpf_link_type type;
	 * 		const struct bpf_link_ops *ops;
	 * 		struct bpf_prog *prog;
	 * 		struct work_struct work;
	 * };
	 */
	struct bpf_link* link = bpf_program__attach_xdp(skel->progs.drop_all, env.ifindex);
	//printf("ERRNO: %i\n", errno);
	/*
	err = xdp_dropall_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	*/

	for (int i = 0; i < 10; ++i) {
		if (exiting)
			break;
		sleep(1);
	}

cleanup:
	/* Clean up */
	xdp_dropall_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
