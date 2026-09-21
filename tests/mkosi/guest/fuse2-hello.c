// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: GPL-2.0-or-later

/* A libfuse2 filesystem, so the tests cover the fusermount (not
 * fusermount3) name that libfuse2 execs. It serves one file, /hello.
 * Nothing in the distribution ships a libfuse2 filesystem any more. */

#define FUSE_USE_VERSION 26

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <string.h>
#include <sys/stat.h>

static const char *hello_path = "/hello";
static const char hello_str[] = "Hello World!\n";

static int hello_getattr(const char *path, struct stat *st) {
    memset(st, 0, sizeof *st);
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    } else if (strcmp(path, hello_path) == 0) {
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = sizeof hello_str - 1;
    } else {
        return -ENOENT;
    }
    return 0;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi) {
    (void)offset;
    (void)fi;
    if (strcmp(path, "/") != 0)
        return -ENOENT;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, hello_path + 1, NULL, 0);
    return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi) {
    if (strcmp(path, hello_path) != 0)
        return -ENOENT;
    if ((fi->flags & 3) != O_RDONLY)
        return -EACCES;
    return 0;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void)fi;
    if (strcmp(path, hello_path) != 0)
        return -ENOENT;
    size_t len = sizeof hello_str - 1;
    if ((size_t)offset >= len)
        return 0;
    if (offset + size > len)
        size = len - offset;
    memcpy(buf, hello_str + offset, size);
    return (int)size;
}

static struct fuse_operations hello_ops = {
    .getattr = hello_getattr,
    .readdir = hello_readdir,
    .open = hello_open,
    .read = hello_read,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &hello_ops, NULL);
}
