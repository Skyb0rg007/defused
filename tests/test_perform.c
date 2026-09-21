/*
 * SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Drives defused-mount.c directly. Nothing here needs privilege: a
 * well-formed request gets as far as fsopen(), which is where an
 * unprivileged run stops, so "mount failed" means "accepted, and refused
 * only by the kernel" as against "bad mount option"/"malformed request",
 * which mean defused refused it. That distinction is what makes the
 * privileged flags observable without root.
 */
#define _GNU_SOURCE
#include "common.h"
#include "defused-mount.h"
#include "test_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Removed with its scope. */
struct scratch {
    char dir[sizeof("/tmp/defused-perform-XXXXXX")];
};

static void scratch_done(struct scratch *s) {
    if (s->dir[0] != '\0')
        rmdir(s->dir);
}

static int scratch_create(struct scratch *s) {
    strcpy(s->dir, "/tmp/defused-perform-XXXXXX");
    if (mkdtemp(s->dir) == NULL) {
        perror("mkdtemp");
        s->dir[0] = '\0';
        return -errno;
    }
    return 0;
}

static struct defused_request mount_req(uint32_t flags, const char *fsname,
                                        const char *subtype) {
    struct defused_request req = {
        .magic = DEFUSED_MAGIC, .op = DEFUSED_OP_MOUNT, .mount_flags = flags};
    if (fsname != NULL)
        strcpy(req.fsname, fsname);
    if (subtype != NULL)
        strcpy(req.subtype, subtype);
    return req;
}

static struct defused_request umount_req(const char *name) {
    struct defused_request req = {.magic = DEFUSED_MAGIC,
                                  .op = DEFUSED_OP_UNMOUNT};
    strcpy(req.name, name);
    return req;
}

static void expect(uint32_t got, uint32_t want, const char *why) {
    if (got == want)
        return;
    fprintf(stderr, "FAIL: %s: expected %s, got %s\n", why,
            defused_error_description(want), defused_error_description(got));
    failures++;
}

static void test_mount_shape(void) {
    struct defused_error err;
    const struct {
        struct defused_request req;
        uint32_t unprivileged, privileged;
        const char *why;
    } cases[] = {
        {mount_req(0, NULL, NULL), DEFUSED_OK, DEFUSED_OK, "a plain mount"},
        {mount_req(DEFUSED_MOUNT_RDONLY, NULL, NULL), DEFUSED_OK, DEFUSED_OK,
         "ro"},
        /* The three libfuse marks unsafe. */
        {mount_req(DEFUSED_MOUNT_ALLOW_SUID, NULL, NULL),
         DEFUSED_ERR_BAD_OPTION, DEFUSED_OK, "suid"},
        {mount_req(DEFUSED_MOUNT_ALLOW_DEV, NULL, NULL), DEFUSED_ERR_BAD_OPTION,
         DEFUSED_OK, "dev"},
        {mount_req(DEFUSED_MOUNT_BLKDEV, "/dev/loop0", NULL),
         DEFUSED_ERR_BAD_OPTION, DEFUSED_OK, "blkdev"},
        {mount_req(0, "/dev/loop0", NULL), DEFUSED_ERR_MALFORMED, DEFUSED_OK,
         "an fsname with a slash"},
        {mount_req(DEFUSED_MOUNT_BLKDEV, NULL, NULL), DEFUSED_ERR_BAD_OPTION,
         DEFUSED_ERR_MALFORMED, "blkdev without an fsname"},
        {mount_req(0, NULL, "a/b"), DEFUSED_ERR_MALFORMED,
         DEFUSED_ERR_MALFORMED, "a subtype with a slash"},
        {mount_req(1u << 31, NULL, NULL), DEFUSED_ERR_BAD_OPTION,
         DEFUSED_ERR_BAD_OPTION, "an unknown flag bit"},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        err = (struct defused_error){0};
        (void)defused_check_mount_request(&cases[i].req, false, &err);
        expect(err.code, cases[i].unprivileged, cases[i].why);

        err = (struct defused_error){0};
        (void)defused_check_mount_request(&cases[i].req, true, &err);
        expect(err.code, cases[i].privileged, cases[i].why);
    }
}

static void test_mountpoint_and_device(const char *dir) {
    struct defused_error err = {0};
    struct stat st;
    _cleanup_close_ int dir_fd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    CHECK(defused_check_mountpoint(dir_fd, &st, &err) == 0);
    expect(err.code, DEFUSED_OK, "a directory is a mountpoint");

    char link[sizeof("/tmp/defused-perform-XXXXXX") + sizeof("/link")];
    snprintf(link, sizeof(link), "%s/link", dir);
    if (symlink("target", link) == 0) {
        _cleanup_close_ int link_fd =
            open(link, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (link_fd >= 0) {
            err = (struct defused_error){0};
            CHECK(defused_check_mountpoint(link_fd, &st, &err) < 0);
            expect(err.code, DEFUSED_ERR_MALFORMED, "a symlink mountpoint");
        }
        unlink(link);
    }

    /* A character device, but not 10:229. */
    _cleanup_close_ int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
        err = (struct defused_error){0};
        CHECK(defused_check_fuse_device(null_fd, &err) < 0);
        expect(err.code, DEFUSED_ERR_MALFORMED, "/dev/null as the FUSE device");
    }
    _cleanup_close_ int fuse_ro = open("/dev/fuse", O_RDONLY | O_CLOEXEC);
    if (fuse_ro >= 0) {
        err = (struct defused_error){0};
        CHECK(defused_check_fuse_device(fuse_ro, &err) < 0);
        expect(err.code, DEFUSED_ERR_MALFORMED, "/dev/fuse opened read-only");
    }
}

static void test_umount_shape(const char *dir) {
    _cleanup_close_ int dir_fd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    static const char *const bad_names[] = {"", ".", "..", "a/b"};
    for (size_t i = 0; i < ARRAY_SIZE(bad_names); i++) {
        struct defused_request req = umount_req(bad_names[i]);
        struct defused_error err = {0};
        uint64_t mnt_id = 0;
        CHECK(defused_check_umount_request(&req, dir_fd, &mnt_id, &err) < 0);
        expect(err.code, DEFUSED_ERR_MALFORMED, "a name that is no basename");
    }

    /* A plain directory shares its parent's mount id. */
    char sub[sizeof("/tmp/defused-perform-XXXXXX") + sizeof("/plain")];
    snprintf(sub, sizeof(sub), "%s/plain", dir);
    if (mkdir(sub, 0700) == 0) {
        struct defused_request req = umount_req("plain");
        struct defused_error err = {0};
        uint64_t mnt_id = 0;
        CHECK(defused_check_umount_request(&req, dir_fd, &mnt_id, &err) < 0);
        expect(err.code, DEFUSED_ERR_NOT_A_FUSE_MOUNT,
               "unmounting a plain directory");
        rmdir(sub);
    }
}

/* defused_perform() end to end. It reports through *err rather than its
 * return value, exactly like defused_call(). */
static void test_perform(const char *dir) {
    _cleanup_close_ int dir_fd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    struct defused_error err;

    /* Only unprivileged: with the privilege it asks for, this would
     * really mount something on the scratch directory. */
    _cleanup_close_ int dev_fd =
        geteuid() == 0 ? -EBADF : open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        fprintf(stderr, "SKIP: %s, so the mount attempt is skipped\n",
                geteuid() == 0 ? "running as root"
                               : "/dev/fuse is not usable here");
    } else {
        /* Accepted, privileged flags and all, and stopped only by the
         * kernel. */
        struct defused_request req =
            mount_req(DEFUSED_MOUNT_ALLOW_SUID | DEFUSED_MOUNT_ALLOW_DEV,
                      "privfs", "priv");
        CHECK(defused_perform(&req, (const int[]){dev_fd, dir_fd}, &err) == 0);
        expect(err.code, DEFUSED_ERR_MOUNT_FAILED,
               "a privileged mount request unprivileged");
        CHECK(err.sys_errno != 0);
        CHECK(err.detail[0] != '\0');

        /* An unknown flag bit stops earlier, and says so differently. */
        req = mount_req(1u << 31, NULL, NULL);
        CHECK(defused_perform(&req, (const int[]){dev_fd, dir_fd}, &err) == 0);
        expect(err.code, DEFUSED_ERR_BAD_OPTION, "an unknown flag bit");
    }
    /* The working directory survives an unmount. Safe at any privilege:
     * nothing is mounted on this name. */
    char before[4096], after[4096];
    CHECK(getcwd(before, sizeof(before)) != NULL);
    struct defused_request u = umount_req("nothing-here");
    CHECK(defused_perform(&u, (const int[]){dir_fd}, &err) == 0);
    expect(err.code, DEFUSED_ERR_MALFORMED, "unmounting a missing name");
    CHECK(getcwd(after, sizeof(after)) != NULL);
    CHECK(strcmp(before, after) == 0);
}

int main(void) {
    test_set_timeout();

    _cleanup_(scratch_done) struct scratch scratch = {};
    if (scratch_create(&scratch) < 0)
        return 1;

    test_mount_shape();
    test_mountpoint_and_device(scratch.dir);
    test_umount_shape(scratch.dir);
    test_perform(scratch.dir);

    return failures ? 1 : 0;
}
