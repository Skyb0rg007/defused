/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Shared scaffolding for the tests: a CHECK() that records a failure and
 * carries on, and a self-imposed timeout.
 */

#ifndef DEFUSED_TEST_UTIL_H
#define DEFUSED_TEST_UTIL_H

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

/* Meson reads 77 as a skip. */
#define MESON_EXIT_SKIP 77

/* Unused in tests that report through return codes rather than CHECK(). */
__attribute__((unused)) static int failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define TEST_TIMEOUT_SECONDS 60

static void test_timeout_handler(int sig) {
    (void)sig;
    static const char msg[] = "FAIL: test timed out\n";
    (void)!write(2, msg, sizeof(msg) - 1);
    _exit(1);
}

/* Every test bounds itself: nixpkgs' mesonCheckPhase disables Meson's own
 * per-test timeout, so a hang would otherwise run until CI kills the job. */
static void test_set_timeout(void) {
    struct sigaction sa = {.sa_handler = test_timeout_handler};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) == 0)
        alarm(TEST_TIMEOUT_SECONDS);
}

#endif /* DEFUSED_TEST_UTIL_H */
