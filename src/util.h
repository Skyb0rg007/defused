/*
 * SPDX-FileCopyrightText: 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef DEFUSED_UTIL_H
#define DEFUSED_UTIL_H

#include <sys/vfs.h>

int begins_with(const char *s, const char *beg);
int opt_eq(const char *s, unsigned len, const char *opt);
int libfuse_strtol(const char *str, long *res);
int send_fd(int sock_fd, int fd);
int count_fuse_fs(const char *progname);
int check_nonroot_fstype(const char *progname, const struct statfs *fs_buf);
int close_inherited_fds(int cfd);
char *fuse_mnt_resolve_path(const char *progname, const char *orig);

#endif /* DEFUSED_UTIL_H */
