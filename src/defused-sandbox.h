/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEFUSED_SANDBOX_H
#define DEFUSED_SANDBOX_H

#include "defused_proto.h"

#include <sys/types.h>

/* The client's mount namespace is entered only by a forked child under a
 * seccomp allowlist; these run that child and return its result. */
int defused_sandbox_mount(int pidfd, int mountfd, int mnt_fd,
                          struct defused_error *err);
int defused_sandbox_unmount(int pidfd, int proc_fd, int parent_fd,
                            const char *name, bool lazy, long mnt_id, uid_t uid,
                            struct defused_error *err);

/* The mnt_id of fd, read from "self/fdinfo/<fd>" under proc_fd with raw
 * syscalls only. fdinfo comes straight from the VFS, so this works even when
 * the FUSE server behind fd is dead. */
int defused_fd_mnt_id(int proc_fd, int fd, long *out_id);

#ifdef DEFUSED_TEST
int defused_test_install_seccomp(enum defused_op op);
int defused_test_mountinfo_owner(const char *line, long mnt_id, uid_t *out_uid);
pid_t defused_test_fdinfo_pid(const char *text);
int defused_test_fdinfo_mnt_id(const char *text, long *out_id);
#endif

#endif /* DEFUSED_SANDBOX_H */
