/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The kernel calls defused makes by number: some have no libc wrapper, and
 * the child's seccomp allowlist has to name the exact entries it reaches.
 * Scalars are widened to a full register, the width a filter compares.
 */

#ifndef DEFUSED_SYSCALL_H
#define DEFUSED_SYSCALL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* struct mnt_id_req, which musl does not declare. */
#include <linux/mount.h>

static inline int sys_setns(int fd, int nstype) {
    return (int)syscall(SYS_setns, (long)fd, (long)nstype);
}

static inline ssize_t sys_write(int fd, const void *buf, size_t count) {
    return (ssize_t)syscall(SYS_write, (long)fd, buf, (long)count);
}

static inline int sys_fchdir(int fd) {
    return (int)syscall(SYS_fchdir, (long)fd);
}

/* musl prototypes ioctl()'s request as int, which the _IO* constants do
 * not fit. The kernel takes an unsigned int, so pass the number itself. */
static inline int sys_ioctl(int fd, unsigned long request, void *arg) {
    return (int)syscall(SYS_ioctl, (long)fd, (long)request, arg);
}

static inline void sys_exit_group(int status) {
    (void)syscall(SYS_exit_group, (long)status);
}

static inline void sys_exit(int status) {
    (void)syscall(SYS_exit, (long)status);
}

/* handle is a struct file_handle, whose flexible array member callers lay
 * out themselves. */
static inline int sys_name_to_handle_at(int dir_fd, const char *name,
                                        void *handle, uint64_t *mnt_id,
                                        int flags) {
    return (int)syscall(SYS_name_to_handle_at, (long)dir_fd, name, handle,
                        mnt_id, (long)flags);
}

static inline int sys_umount2(const char *target, int flags) {
    return (int)syscall(SYS_umount2, target, (long)flags);
}

static inline int sys_move_mount(int from_fd, const char *from, int to_fd,
                                 const char *to, unsigned int flags) {
    return (int)syscall(SYS_move_mount, (long)from_fd, from, (long)to_fd, to,
                        (long)flags);
}

static inline int sys_statmount(const struct mnt_id_req *req, void *buf,
                                size_t size, unsigned int flags) {
    return (int)syscall(SYS_statmount, req, buf, (long)size, (long)flags);
}

static inline ssize_t sys_listmount(const struct mnt_id_req *req, uint64_t *ids,
                                    size_t nr_ids, unsigned int flags) {
    return (ssize_t)syscall(SYS_listmount, req, ids, (long)nr_ids, (long)flags);
}

static inline int sys_fsopen(const char *fsname, unsigned int flags) {
    return (int)syscall(SYS_fsopen, fsname, (long)flags);
}

static inline int sys_fsconfig(int fd, unsigned int cmd, const char *key,
                               const void *value, int aux) {
    return (int)syscall(SYS_fsconfig, (long)fd, (long)cmd, key, value,
                        (long)aux);
}

static inline int sys_fsmount(int fd, unsigned int flags,
                              unsigned int attr_flags) {
    return (int)syscall(SYS_fsmount, (long)fd, (long)flags, (long)attr_flags);
}

static inline int sys_close_range(unsigned int first, unsigned int last,
                                  unsigned int flags) {
    return (int)syscall(SYS_close_range, (long)first, (long)last, (long)flags);
}

#endif /* DEFUSED_SYSCALL_H */
