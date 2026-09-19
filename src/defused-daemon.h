/* SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website> */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEFUSED_DAEMON_H
#define DEFUSED_DAEMON_H

/* handle_connection() owns sock_fd. Returns only on a fatal error. */
int defused_run_fork_daemon(int (*handle_connection)(int sock_fd))
    __attribute__((__nonnull__(1), __warn_unused_result__));

#endif /* DEFUSED_DAEMON_H */
