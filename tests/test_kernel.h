/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Skips tests on kernels lacking features defused needs. Probes features
 * rather than the version, since distributions backport them.
 */

#ifndef DEFUSED_TEST_KERNEL_H
#define DEFUSED_TEST_KERNEL_H

#include "test_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Skips <asm-generic/fcntl.h>, which clashes with <fcntl.h>. */
#define _ASM_GENERIC_FCNTL_H
#include <linux/fcntl.h>
#include <linux/pidfd.h>
/* SO_PEERPIDFD, which musl lacks. */
#include <asm/socket.h>

/* Only an older kernel's errno counts as missing; other failures are left
 * for the test to report. */
static bool kernel_lacks_so_peerpidfd(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == -1)
        return false;
    int fd = -1;
    socklen_t len = sizeof(fd);
    bool lacks = getsockopt(sv[0], SOL_SOCKET, SO_PEERPIDFD, &fd, &len) == -1 &&
                 errno == ENOPROTOOPT;
    if (fd >= 0)
        close(fd);
    close(sv[0]);
    close(sv[1]);
    return lacks;
}

static bool kernel_lacks_pidfd_mnt_namespace(void) {
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd == -1)
        return errno == ENOSYS;
    int ns_fd = ioctl(pidfd, PIDFD_GET_MNT_NAMESPACE, NULL);
    bool lacks = ns_fd == -1 && (errno == ENOTTY || errno == EINVAL);
    if (ns_fd >= 0)
        close(ns_fd);
    close(pidfd);
    return lacks;
}

static bool kernel_lacks_mnt_id_unique(void) {
    struct {
        unsigned int handle_bytes;
        int handle_type;
        unsigned char f_handle[MAX_HANDLE_SZ];
    } handle = {.handle_bytes = MAX_HANDLE_SZ};
    uint64_t mnt_id;
    return syscall(SYS_name_to_handle_at, AT_FDCWD, "/", &handle, &mnt_id,
                   AT_HANDLE_FID | AT_HANDLE_MNT_ID_UNIQUE) == -1 &&
           errno == EINVAL;
}

static void test_require_kernel(void) {
    const char *missing =
        kernel_lacks_so_peerpidfd() ? "SO_PEERPIDFD (Linux 6.5)"
        : kernel_lacks_pidfd_mnt_namespace()
            ? "PIDFD_GET_MNT_NAMESPACE (Linux 6.11)"
        : kernel_lacks_mnt_id_unique() ? "AT_HANDLE_MNT_ID_UNIQUE (Linux 6.12)"
                                       : NULL;
    if (missing) {
        fprintf(stderr, "SKIP: this kernel lacks %s, which defused needs\n",
                missing);
        exit(MESON_EXIT_SKIP);
    }
}

#endif /* DEFUSED_TEST_KERNEL_H */
