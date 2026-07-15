/*
 * SPDX-FileCopyrightText: 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define GETMNTENT getmntent
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Copied from references/libfuse/util/fusermount.c */
int begins_with(const char *s, const char *beg)
{
	if (strncmp(s, beg, strlen(beg)) == 0)
		return 1;
	else
		return 0;
}

/* Copied from references/libfuse/util/fusermount.c */
int opt_eq(const char *s, unsigned len, const char *opt)
{
	if(strlen(opt) == len && strncmp(s, opt, len) == 0)
		return 1;
	else
		return 0;
}

/* SPDX-SnippetBegin
 * SPDX-SnippetCopyrightText: 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copied from references/libfuse/lib/util.c
 */
int libfuse_strtol(const char *str, long *res)
{
	char *endptr;
	int base = 10;
	long val;

	errno = 0;

	if (!str)
		return -EINVAL;

	val = strtol(str, &endptr, base);

	if (errno)
	       return -errno;

	if (endptr == str || *endptr != '\0')
		return -EINVAL;

	*res = val;
	return 0;
}
/* SPDX-SnippetEnd */

/* Copied from references/libfuse/util/fusermount.c */
int send_fd(int sock_fd, int fd)
{
	int retval;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	size_t cmsgbuf[CMSG_SPACE(sizeof(fd)) / sizeof(size_t)];
	int *p_fds;
	char sendchar = 0;

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int *) CMSG_DATA(p_cmsg);
	*p_fds = fd;
	msg.msg_controllen = p_cmsg->cmsg_len;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	/* "To pass file descriptors or credentials you need to send/read at
	 * least one byte" (man 7 unix) */
	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	while ((retval = sendmsg(sock_fd, &msg, 0)) == -1 && errno == EINTR);
	if (retval != 1) {
		perror("sending file descriptor");
		return -1;
	}
	return 0;
}

/* Copied from references/libfuse/util/fuser_conf.c */
static int count_fuse_fs_mtab(const char *progname)
{
	const struct mntent *entp;
	int count = 0;
	const char *mtab = _PATH_MOUNTED;
	FILE *fp = setmntent(mtab, "r");

	if (fp == NULL) {
		fprintf(stderr, "%s: failed to open %s: %s\n", progname, mtab,
			strerror(errno));
		return -1;
	}
	while ((entp = GETMNTENT(fp)) != NULL) {
		if (strcmp(entp->mnt_type, "fuse") == 0 ||
		    strncmp(entp->mnt_type, "fuse.", 5) == 0)
			count++;
	}
	endmntent(fp);
	return count;
}

/* Copied from references/libfuse/util/fuser_conf.c */
int count_fuse_fs(const char *progname)
{
	return count_fuse_fs_mtab(progname);
}

/* Copied from references/libfuse/util/fuser_conf.c */
int check_nonroot_fstype(const char *progname, const struct statfs *fs_buf)
{
	size_t i;

	/* Do not permit mounting over anything in procfs - it has a couple
	 * places to which we have "write access" without being supposed to be
	 * able to just put anything we want there.
	 * Luckily, without allow_other, we can't get other users to actually
	 * use any fake information we try to put there anyway.
	 * Use a whitelist to be safe.
	 */

	/* Define permitted filesystems for the mount target. This was
	 * originally the same list as used by the ecryptfs mount helper
	 * (https://bazaar.launchpad.net/~ecryptfs/ecryptfs/trunk/view/head:/src/utils/mount.ecryptfs_private.c#L225)
	 * but got expanded as we found more filesystems that needed to be
	 * overlaid.
	 */
	__typeof(fs_buf->f_type) f_type_whitelist[] = {
		0x61756673 /* AUFS_SUPER_MAGIC */,
		0x00000187 /* AUTOFS_SUPER_MAGIC */,
		0xCA451A4E /* BCACHEFS_STATFS_MAGIC */,
		0x9123683E /* BTRFS_SUPER_MAGIC */,
		0x00C36400 /* CEPH_SUPER_MAGIC */,
		0xFF534D42 /* CIFS_MAGIC_NUMBER */,
		0x0000F15F /* ECRYPTFS_SUPER_MAGIC */,
		0X2011BAB0 /* EXFAT_SUPER_MAGIC */,
		0x0000EF53 /* EXT[234]_SUPER_MAGIC */,
		0xF2F52010 /* F2FS_SUPER_MAGIC */,
		0x65735546 /* FUSE_SUPER_MAGIC */,
		0x01161970 /* GFS2_MAGIC */,
		0x47504653 /* GPFS_SUPER_MAGIC */,
		0x0000482b /* HFSPLUS_SUPER_MAGIC */,
		0x000072B6 /* JFFS2_SUPER_MAGIC */,
		0x3153464A /* JFS_SUPER_MAGIC */,
		0x0BD00BD0 /* LL_SUPER_MAGIC */,
		0X00004D44 /* MSDOS_SUPER_MAGIC */,
		0x0000564C /* NCP_SUPER_MAGIC */,
		0x00006969 /* NFS_SUPER_MAGIC */,
		0x00003434 /* NILFS_SUPER_MAGIC */,
		0x5346544E /* NTFS_SB_MAGIC */,
		0x7366746E /* NTFS3_SUPER_MAGIC */,
		0x5346414f /* OPENAFS_SUPER_MAGIC */,
		0x794C7630 /* OVERLAYFS_SUPER_MAGIC */,
		0xAAD7AAEA /* PANFS_SUPER_MAGIC */,
		0x52654973 /* REISERFS_SUPER_MAGIC */,
		0xFE534D42 /* SMB2_SUPER_MAGIC */,
		0x73717368 /* SQUASHFS_MAGIC */,
		0x01021994 /* TMPFS_MAGIC */,
		0x24051905 /* UBIFS_SUPER_MAGIC */,
		0x18031977 /* WEKAFS_SUPER_MAGIC */,
#if __SIZEOF_LONG__ > 4
		0x736675005346544e /* UFSD */,
#endif
		0x58465342 /* XFS_SB_MAGIC */,
		0x2FC12FC1 /* ZFS_SUPER_MAGIC */,
		0x858458f6 /* RAMFS_MAGIC */,
	};
	for (i = 0; i < ARRAY_SIZE(f_type_whitelist); i++) {
		if (f_type_whitelist[i] == fs_buf->f_type)
			return 0;
	}

	fprintf(stderr, "%s: mounting over filesystem type %#010lx is forbidden\n",
		progname, (unsigned long)fs_buf->f_type);
	return -1;
}

/* Copied from references/libfuse/util/fusermount.c */
static void close_range_loop(int min_fd, int max_fd, int cfd)
{
	for (int fd = min_fd; fd <= max_fd; fd++)
		if (fd != cfd)
			close(fd);
}

/*
 * Close all inherited fds that are not needed
 * Ideally these wouldn't come up at all, applications should better
 * use FD_CLOEXEC / O_CLOEXEC
 *
 * Copied from references/libfuse/util/fusermount.c
 */
int close_inherited_fds(int cfd)
{
	int rc = -1;
	int nullfd;

	/* We can't even report an error */
	if (cfd <= STDERR_FILENO)
		return -EINVAL;

#ifdef HAVE_CLOSE_RANGE
	if (cfd < STDERR_FILENO + 2) {
		close_range_loop(STDERR_FILENO + 1, cfd - 1, cfd);
	} else {
		rc = close_range(STDERR_FILENO + 1, cfd - 1, 0);
		if (rc < 0)
			goto fallback;
	}

	/* Close high range */
	rc = close_range(cfd + 1, ~0U, 0);
#else
	goto fallback; /* make use of fallback to avoid compiler warnings */
#endif

fallback:
	if (rc < 0) {
		int max_fd = sysconf(_SC_OPEN_MAX) - 1;

		close_range_loop(STDERR_FILENO + 1, max_fd, cfd);
	}

	nullfd = open("/dev/null", O_RDWR);
	if (nullfd < 0) {
		perror("fusermount: cannot open /dev/null");
		return -errno;
	}

	/* Redirect stdin, stdout, stderr to /dev/null */
	dup2(nullfd, STDIN_FILENO);
	dup2(nullfd, STDOUT_FILENO);
	dup2(nullfd, STDERR_FILENO);
	if (nullfd > STDERR_FILENO)
		close(nullfd);

	return 0;
}

/* SPDX-SnippetBegin
 * SPDX-SnippetCopyrightText: 2001-2007 Miklos Szeredi <miklos@szeredi.hu>
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copied from references/libfuse/lib/mount_util.c
 */
char *fuse_mnt_resolve_path(const char *progname, const char *orig)
{
	char buf[PATH_MAX];
	char *copy;
	char *dst;
	char *end;
	const char *lastcomp;
	const char *toresolv;

	if (!orig[0]) {
		fprintf(stderr, "%s: invalid mountpoint '%s'\n", progname,
			orig);
		return NULL;
	}

	copy = strdup(orig);
	if (copy == NULL) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		return NULL;
	}

	toresolv = copy;
	lastcomp = NULL;
	for (end = copy + strlen(copy) - 1; end > copy && *end == '/'; end --);
	if (end[0] != '/') {
		char *tmp;
		end[1] = '\0';
		tmp = strrchr(copy, '/');
		if (tmp == NULL) {
			lastcomp = copy;
			toresolv = ".";
		} else {
			lastcomp = tmp + 1;
			if (tmp == copy)
				toresolv = "/";
		}
		if (strcmp(lastcomp, ".") == 0 || strcmp(lastcomp, "..") == 0) {
			lastcomp = NULL;
			toresolv = copy;
		}
		else if (tmp)
			tmp[0] = '\0';
	}
	if (realpath(toresolv, buf) == NULL) {
		fprintf(stderr, "%s: bad mount point %s: %s\n", progname, orig,
			strerror(errno));
		free(copy);
		return NULL;
	}
	if (lastcomp == NULL)
		dst = strdup(buf);
	else {
		dst = (char *) malloc(strlen(buf) + 1 + strlen(lastcomp) + 1);
		if (dst) {
			unsigned buflen = strlen(buf);
			if (buflen && buf[buflen-1] == '/')
				sprintf(dst, "%s%s", buf, lastcomp);
			else
				sprintf(dst, "%s/%s", buf, lastcomp);
		}
	}
	free(copy);
	if (dst == NULL)
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
	return dst;
}
/* SPDX-SnippetEnd */
