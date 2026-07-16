/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Exercises the defused.h Varlink protocol against a real `defused` process
 * without requiring root or CAP_SYS_ADMIN. The requests intentionally stop
 * before the real mount(2) call, since that's the one part of request
 * handling that needs privilege to succeed.
 */
#define _GNU_SOURCE
#include "defused.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>
#include <unistd.h>

static int spawn_defused(const char *defused_path, int *client_sock,
                         pid_t *out_pid) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        return -errno;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Mimic systemd's Accept=yes handoff (sd_listen_fds(3)) rather than
         * the old inetd-style stdin convention. */
        close(sv[0]);
        if (sv[1] != 3) {
            dup2(sv[1], 3);
            close(sv[1]);
        }
        char pidbuf[16];
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int)getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "1", 1);
        execl(defused_path, "defused", NULL);
        perror("exec");
        _exit(127);
    }

    close(sv[1]);
    *client_sock = sv[0];
    *out_pid = pid;
    return 0;
}

static int send_mount_req(int sock, const struct defused_mount_req *req,
                          int dev_fd, int mnt_fd, struct defused_resp *resp) {
    sd_varlink *link = NULL;
    sd_json_variant *reply = NULL;
    const char *error_id = NULL;
    int ret = sd_varlink_connect_fd(&link, sock);
    if (ret < 0)
        return ret;
    sock = -1;

    ret = sd_varlink_set_allow_fd_passing_input(link, true);
    if (ret < 0)
        goto out;
    ret = sd_varlink_set_allow_fd_passing_output(link, true);
    if (ret < 0)
        goto out;
    ret = sd_varlink_push_fd(link, dev_fd);
    if (ret < 0)
        goto out;
    ret = sd_varlink_push_fd(link, mnt_fd);
    if (ret < 0)
        goto out;

    ret = sd_varlink_callbo(
        link, DEFUSED_VARLINK_METHOD_MOUNT, &reply, &error_id,
        SD_JSON_BUILD_PAIR_UNSIGNED("fuseFileDescriptor", 0),
        SD_JSON_BUILD_PAIR_UNSIGNED("mountpointFileDescriptor", 1),
        SD_JSON_BUILD_PAIR_UNSIGNED("mountFlags", req->mount_flags),
        SD_JSON_BUILD_PAIR_UNSIGNED("maxRead", req->max_read),
        SD_JSON_BUILD_PAIR_UNSIGNED("blockSize", req->blksize),
        SD_JSON_BUILD_PAIR_STRING("fsName", req->fsname),
        SD_JSON_BUILD_PAIR_STRING("subtype", req->subtype));
    if (ret < 0)
        goto out;
    if (error_id != NULL) {
        fprintf(stderr, "FAIL: Varlink error %s\n", error_id);
        ret = -EBADMSG;
        goto out;
    }

    struct service_response {
        uint32_t status;
        int32_t sys_errno;
    } parsed = {};
    static const sd_json_dispatch_field dispatch_table[] = {
        {"status", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,
         offsetof(struct service_response, status), SD_JSON_MANDATORY},
        {"sysErrno", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int32,
         offsetof(struct service_response, sys_errno), SD_JSON_MANDATORY},
        {},
    };
    ret = sd_json_dispatch(reply, dispatch_table, 0, &parsed);
    if (ret < 0)
        goto out;
    resp->status = parsed.status;
    resp->sys_errno = parsed.sys_errno;

out:
    sd_json_variant_unref(reply);
    sd_varlink_flush_close_unref(link);
    if (sock >= 0)
        close(sock);
    return ret;
}

/* Runs one mount request against a fresh defused instance and reports the
 * response status via *out_status, without asserting what it should be --
 * callers decide what counts as a pass. */
static int run_mount_req(const char *defused_path,
                         const struct defused_mount_req *req, const char *path,
                         const char *dev_path, uint32_t *out_status) {
    int sock;
    pid_t pid;
    int ret = spawn_defused(defused_path, &sock, &pid);
    if (ret < 0)
        return ret;

    int mnt_fd = open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (mnt_fd < 0) {
        ret = -errno;
        perror(path);
        return ret;
    }
    int dev_fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        ret = -errno;
        perror(dev_path);
        close(mnt_fd);
        return ret;
    }

    struct defused_resp resp;
    ret = send_mount_req(sock, req, dev_fd, mnt_fd, &resp);
    close(dev_fd);
    close(mnt_fd);
    close(sock);

    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (ret < 0) {
        if (WIFEXITED(wstatus))
            fprintf(stderr, "FAIL: service exited with status %d\n",
                    WEXITSTATUS(wstatus));
        else if (WIFSIGNALED(wstatus))
            fprintf(stderr, "FAIL: service killed by signal %d\n",
                    WTERMSIG(wstatus));
        return ret;
    }
    if (!WIFEXITED(wstatus)) {
        fprintf(stderr, "FAIL: service did not exit normally\n");
        return -ECHILD;
    }
    *out_status = resp.status;
    return 0;
}

static int run_mount_req_expect(const char *defused_path,
                                const struct defused_mount_req *req,
                                const char *path, uint32_t expect_status) {
    uint32_t status;
    int ret = run_mount_req(defused_path, req, path, "/dev/null", &status);
    if (ret < 0)
        return ret;
    if (status != expect_status) {
        fprintf(stderr, "FAIL: expected status %u, got %u\n", expect_status,
                status);
        return -EINVAL;
    }
    return 0;
}

/* The mountpoint ownership check happens before the polkit check, so it
 * takes a real self-owned mountpoint (and a real /dev/fuse fd, since
 * check_fuse_device_fd() validates the device major/minor) to reach
 * check_polkit_authorized() at all. Skips gracefully if this sandbox has
 * no /dev/fuse, rather than asserting anything about polkit's specific
 * answer -- what matters here is that an unauthorized request never gets
 * past this gate to the privileged mount syscalls, not what a particular
 * polkit configuration decides. */
static int test_polkit_gate(const char *defused_path) {
    int probe = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (probe < 0) {
        fprintf(stderr,
                "SKIP: /dev/fuse not usable here (%s), skipping polkit gate "
                "test\n",
                strerror(errno));
        return 0;
    }
    close(probe);

    char dir[] = "/tmp/defused-polkit-test-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return -errno;
    }

    struct defused_mount_req req = {};
    uint32_t status = DEFUSED_OK;
    int ret = run_mount_req(defused_path, &req, dir, "/dev/fuse", &status);
    rmdir(dir);
    if (ret < 0)
        return ret;

    /* Without an interactive polkit agent, an AUTH_ADMIN_KEEP action can
     * never succeed; either polkit is reachable and says no
     * (DEFUSED_ERR_NOT_ALLOWED), or it isn't reachable at all in this
     * sandbox and the check fails closed (DEFUSED_ERR_MOUNT_FAILED). Either
     * is a pass -- DEFUSED_OK (or any earlier, deterministic error) would
     * mean the gate was skipped or something regressed before it. */
    if (status != DEFUSED_ERR_NOT_ALLOWED &&
        status != DEFUSED_ERR_MOUNT_FAILED) {
        fprintf(stderr,
                "FAIL: expected the polkit gate to block the mount (got "
                "status %u)\n",
                status);
        return -EINVAL;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/defused\n", argv[0]);
        return 2;
    }

    struct defused_mount_req bad_opt = {
        .mount_flags = 1u << 31, /* never in DEFUSED_MOUNT_FLAGS_MASK */
    };
    if (run_mount_req_expect(argv[1], &bad_opt, ".", DEFUSED_ERR_BAD_OPTION) !=
        0)
        return 1;

    if (getuid() != 0) {
        struct defused_mount_req root_owned = {};
        if (run_mount_req_expect(argv[1], &root_owned, "/",
                                 DEFUSED_ERR_NOT_ALLOWED) != 0)
            return 1;

        if (test_polkit_gate(argv[1]) != 0)
            return 1;
    }

    return 0;
}
