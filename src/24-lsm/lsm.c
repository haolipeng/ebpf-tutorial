// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>

#include "lsm.skel.h"

char *CMD_ARGS[] = {"ls", NULL};

#define GET_PAGE_ADDR(ADDR, PAGE_SIZE)					\
	(char *)(((unsigned long) (ADDR + PAGE_SIZE)) & ~(PAGE_SIZE-1))

int stack_mprotect(void)
{
	void *buf;
	long sz;
	int ret;

	sz = sysconf(_SC_PAGESIZE);
    printf("PAGESIZE: %ld\n", sz);
	if (sz < 0)
		return sz;

	buf = alloca(sz * 3);
	ret = mprotect(GET_PAGE_ADDR(buf, sz), sz, PROT_READ | PROT_WRITE | PROT_EXEC);
	return ret;
}

int exec_cmd(int *monitored_pid)
{
	int child_pid, child_status;

	child_pid = fork();
	if (child_pid == 0) {
		*monitored_pid = getpid();
		execvp(CMD_ARGS[0], CMD_ARGS);
		return -EINVAL;
	} else if (child_pid > 0) {
		waitpid(child_pid, &child_status, 0);
		return child_status;
	}

	return -EINVAL;
}

int main(void)
{
	struct lsm_bpf *skel = NULL;
	int err;

	skel = lsm_bpf__open_and_load();
	if (!skel)	goto close_prog;

	err = lsm_bpf__attach(skel);
	if (err)	goto close_prog;

	err = exec_cmd(&skel->bss->monitored_pid);
	if (err < 0)	goto close_prog;

	fprintf(stdout, "bprm_count = %d\n", skel->bss->bprm_count);

	skel->bss->monitored_pid = getpid();
	err = stack_mprotect();

	fprintf(stdout, "mprotect_count = %d\n", skel->bss->mprotect_count);
	fprintf(stdout, "want err=1(EPERM), got %d\n", errno);

	if (errno != EPERM)	goto close_prog;


close_prog:
	lsm_bpf__destroy(skel);
	return 0;
}
