/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Scope-based resource cleanup, after systemd's coding style: a resource is
 * released when the variable holding it goes out of scope, and ownership is
 * handed off with TAKE_FD()/TAKE_PTR() so the handler becomes a no-op.
 *
 * File descriptors are "empty" at -EBADF (any negative value is treated as
 * unset), pointers at NULL.
 */

#ifndef DEFUSED_COMMON_H
#define DEFUSED_COMMON_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define _cleanup_(x) __attribute__((__cleanup__(x)))

/* Defines func##p(), a _cleanup_ handler that calls func() on a non-empty
 * value. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, empty)                    \
    static inline void func##p(type *p) {                                      \
        if (*p != (empty))                                                     \
            func(*p);                                                          \
    }                                                                          \
    struct defused_useless_struct_to_allow_trailing_semicolon_
#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                                \
    DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, NULL)

/* close() that is a no-op on an unset fd, preserves errno, and returns the
 * empty value so it can be used as `fd = safe_close(fd);`. */
static inline int safe_close(int fd) {
    if (fd >= 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
    }
    return -EBADF;
}

static inline void closep(int *fd) { safe_close(*fd); }
#define _cleanup_close_ _cleanup_(closep)

#define EBADF_PAIR {-EBADF, -EBADF}
static inline void close_pairp(int (*p)[2]) {
    safe_close((*p)[0]);
    safe_close((*p)[1]);
}
#define _cleanup_close_pair_ _cleanup_(close_pairp)

static inline void freep(void *p) { free(*(void **)p); }
#define _cleanup_free_ _cleanup_(freep)

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE *, fclose);
#define _cleanup_fclose_ _cleanup_(fclosep)

/* Ownership transfer: yields the held value and marks the variable empty.
 * Written as inline helpers rather than statement expressions so they stay
 * within -Wpedantic. */
static inline int take_fd(int *fd) {
    int r = *fd;
    *fd = -EBADF;
    return r;
}
#define TAKE_FD(fd) take_fd(&(fd))

static inline void *take_ptr(void **p) {
    void *r = *p;
    *p = NULL;
    return r;
}
#define TAKE_PTR(ptr) ((__typeof__(ptr))take_ptr((void **)&(ptr)))

#endif /* DEFUSED_COMMON_H */
