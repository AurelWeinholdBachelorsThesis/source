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

const char *argp_program_version = "xdp_dropall 0.0";
const char *argp_program_bug_address = "<aurel@weinhold.org>";
static char args_doc[] = "ifindex port"; // arguments
const char doc[] =
"\nBPF xdp_dropall demo application.\n"
"\n"
"It drops all incoming packages on the eXpress Data Path\n"
"\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, OPTION_ARG_OPTIONAL, "Verbose debug output. Currently not supported." },
	{ NULL },
};


struct arguments {
	bool verbose;
	int ifindex;
	int port;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct arguments *env = (struct arguments*)state->input;
	switch (key) {
	case 'v':
		env->verbose = true;
		break;
	case ARGP_KEY_ARG:
		if(state->arg_num > 2)
			argp_usage(state);

		// first argument: ifindex
		if (state->arg_num == 0)
			env->ifindex = atoi(arg);
		// second argument: port
		if (state->arg_num == 1)
			env->port = atoi(arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = doc,
	.args_doc = args_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/*
	 * TODO(Aurel): Figure out how to handle verbose setting.
	 * if (level == LIBBPF_DEBUG && !env.verbose)
	 * 	return 0;
	 */
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct xdp_dropall_bpf *obj;

	// argument default values
	struct arguments env = {
		.verbose = false,
		.ifindex = -1,
		.port = -1
	};

	/* Parse command line options */
	int err;
	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		exit(err);

	if (env.ifindex < 0) {
		fprintf(stderr, "Invalid ifindex\n");
		exit(EXIT_FAILURE);
	}
	if (env.port <= 0) {
		fprintf(stderr, "Invalid port\n");
		exit(EXIT_FAILURE);
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	obj = xdp_dropall_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		exit(EXIT_FAILURE);
	}

	/* Load & verify BPF programs */
	err = xdp_dropall_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach to XDP stage */
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
	struct bpf_link* link = bpf_program__attach_xdp(obj->progs.drop_port, env.ifindex);
	if (!link) {
		fprintf(stderr, "Failed to attach eBPF to XDP.\n");
		goto cleanup;
	}

	while(1) {
		if (exiting)
			break;
	};

cleanup:
	/* Clean up */
	xdp_dropall_bpf__destroy(obj);

	return err < 0 ? -err : 0;
}
