#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <sys/mount.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <setjmp.h>
#include <linux/loop.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/sendfile.h>
#include <malloc.h>

#include "config.h"

#define ksbtry(var) do { \
	            jmp_buf jmp; \
	            jmp_buf *jmpp_old = jmpp; \
	            jmpp = &jmp; \
	            int _ret = setjmp (jmp); \
	            var = _ret; \
	            if (_ret == 0)
#define ksbcatch(e) else if (_ret == (e))
#define ksbcatch_all else
#define ksbend jmpp = jmpp_old; } while (0)
#define ksbthrow(e) longjmp (*jmpp, (e))

#define ksblog(level, ...) do { fprintf (stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)

struct flags
{
  const char *name;
  int mask;
  int value;
};

static jmp_buf *jmpp;

char *
ksbflags (const struct flags *flagsp, int flags)
{
  char *data;
  size_t datasize;
  int flags_save = flags;
  FILE *fp = open_memstream (&data, &datasize);
  if (fp == NULL)
    {
      ksblog (LOG_ERR, "open_memstream: %s", strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }

  const char *delim = "";
  for (const struct flags * f = flagsp; f->name; f++)
    {
      if ((f->mask & flags) == f->value)
	{
	  if (fprintf (fp, "%s%s", delim, f->name) == -1)
	    {
	      ksblog (LOG_ERR, "fprintf: %s", strerror (errno));
	      fclose (fp);
	      free (data);
	      ksbthrow (EXIT_FAILURE);
	    }
	  delim = "|";
	  flags_save &= ~f->mask;
	}
    }
  if (flags_save)
    {
      if (fprintf (fp, "%s0x%x", delim, flags_save) == -1)
	{
	  ksblog (LOG_ERR, "fprintf: %s", strerror (errno));
	  fclose (fp);
	  free (data);
	  ksbthrow (EXIT_FAILURE);
	}
    }
  fclose (fp);
  data[datasize] = '\0';
  return data;
}

#define flagmask(mask, value) { #value, mask, value }
#define flagvalue(value) { #value, value, value }
#define flagend { NULL, 0, 0 }

static struct flags unshare_flags[] = {
  flagvalue (CLONE_FILES),
  flagvalue (CLONE_FS),
  flagvalue (CLONE_NEWNS),
  flagvalue (CLONE_NEWIPC),
  flagvalue (CLONE_NEWNET),
  flagvalue (CLONE_NEWPID),
  flagvalue (CLONE_NEWUSER),
  flagvalue (CLONE_NEWUTS),
  flagvalue (CLONE_SYSVSEM),
  flagend
};

static struct flags mount_flags[] = {
  flagvalue (MS_RDONLY),
  flagvalue (MS_NOSUID),
  flagvalue (MS_NODEV),
  flagvalue (MS_NOEXEC),
  flagvalue (MS_SYNCHRONOUS),
  flagvalue (MS_REMOUNT),
  flagvalue (MS_MANDLOCK),
  flagvalue (MS_DIRSYNC),
  flagvalue (MS_NOATIME),
  flagvalue (MS_NODIRATIME),
  flagvalue (MS_BIND),
  flagvalue (MS_MOVE),
  flagvalue (MS_REC),
  flagvalue (MS_SILENT),
  flagvalue (MS_POSIXACL),
  flagvalue (MS_UNBINDABLE),
  flagvalue (MS_PRIVATE),
  flagvalue (MS_SLAVE),
  flagvalue (MS_SHARED),
  flagvalue (MS_RELATIME),
  flagvalue (MS_KERNMOUNT),
  flagvalue (MS_I_VERSION),
  flagvalue (MS_STRICTATIME),
  flagvalue (MS_LAZYTIME),
  flagvalue (MS_ACTIVE),
  flagvalue (MS_NOUSER),
  flagend
};

static struct flags open_flags[] = {
  flagmask (O_ACCMODE, O_RDONLY),
  flagmask (O_ACCMODE, O_WRONLY),
  flagmask (O_ACCMODE, O_RDWR),
  flagvalue (O_CREAT),
  flagvalue (O_EXCL),
  flagvalue (O_NOCTTY),
  flagvalue (O_TRUNC),
  flagvalue (O_APPEND),
  flagvalue (O_NONBLOCK),
  flagvalue (O_NDELAY),
  flagvalue (O_SYNC),
  flagvalue (O_FSYNC),
  flagvalue (O_ASYNC),
  flagvalue (O_LARGEFILE),
  flagvalue (O_DIRECTORY),
  flagvalue (O_NOFOLLOW),
  flagvalue (O_CLOEXEC),
  flagvalue (O_DIRECT),
  flagvalue (O_NOATIME),
  flagvalue (O_PATH),
  flagvalue (O_DSYNC),
  flagvalue (O_TMPFILE),
  flagend
};

static struct flags loop_info_flags[] = {
  flagvalue (LO_FLAGS_READ_ONLY),
  flagvalue (LO_FLAGS_AUTOCLEAR),
  flagvalue (LO_FLAGS_PARTSCAN),
  flagvalue (LO_FLAGS_DIRECT_IO),
  flagend
};

static void
ksbunshare (int flags)
{
  if (unshare (flags) == -1)
    {
      int err = errno;
      char *f = ksbflags (unshare_flags, flags);
      ksblog (LOG_ERR, "unshare(%s): %s", f, strerror (err));
      free (f);
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbmount (const char *source, const char *target, const char *fstype,
	  int flags, const char *data)
{
  if (mount (source, target, fstype, flags, data) == -1)
    {
      int err = errno;
      char *f = ksbflags (mount_flags, flags);
      ksblog (LOG_ERR, "mount(%s, %s, %s, %s, %s): %s", source, target,
	      fstype, f, data, strerror (err));
      free (f);
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbmkdir (const char *pathname, mode_t mode)
{
  if (mkdir (pathname, mode) == -1)
    {
      ksblog (LOG_ERR, "mkdir(%s, 0%o): %s", pathname, mode,
	      strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbmkdir_nc (const char *pathname, mode_t mode)
{
  if (mkdir (pathname, mode) == -1 && errno != EEXIST)
    {
      ksblog (LOG_ERR, "mkdir(%s, 0%o): %s", pathname, mode,
	      strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}


static int
ksbopen (const char *pathname, int flags, ...)
{
  int fd;
  if (flags & O_CREAT || flags & O_TMPFILE)
    {
      va_list ap;
      va_start (ap, flags);
      int mode = va_arg (ap, int);
      va_end (ap);
      fd = open (pathname, flags, mode);
      if (fd == -1)
	{
	  int err = errno;
	  char *f = ksbflags (open_flags, flags);
	  ksblog (LOG_ERR, "open(%s, %s, 0%o): %s", pathname, f, mode,
		  strerror (err));
	  free (f);
	  ksbthrow (EXIT_FAILURE);
	}
    }
  else
    {
      fd = open (pathname, flags);
      if (fd == -1)
	{
	  int err = errno;
	  char *f = ksbflags (open_flags, flags);
	  ksblog (LOG_ERR, "open(%s, %s): %s", pathname, f, strerror (err));
	  free (f);
	  ksbthrow (EXIT_FAILURE);
	}
    }
  return fd;
}

static void
ksbclose (int fd)
{
  if (close (fd) == -1)
    {
      ksblog (LOG_ERR, "close(%d): %s", fd, strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}

static int
ksbloopgetfree (void)
{
  int fd = ksbopen ("/dev/loop-control", O_RDWR);
  int loopdevno = ioctl (fd, LOOP_CTL_GET_FREE);
  if (loopdevno == -1)
    {
      ksblog (LOG_ERR, "ioctl(%d, LOOP_CTL_GET_FREE): %s", fd,
	      strerror (errno));
      ksbclose (fd);
      ksbthrow (EXIT_FAILURE);
    }
  ksbclose (fd);
  return loopdevno;
}

static void
ksbloopset (int fd_loop, int fd_backfile)
{
  if (ioctl (fd_loop, LOOP_SET_FD, fd_backfile) == -1)
    {
      ksblog (LOG_ERR, "ioctl(%d, LOOP_SET_FD, %d): %s", fd_loop, fd_backfile,
	      strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbloopsetstatusflag (int fd_loop, int flags)
{
  struct loop_info loop_info;
  if (ioctl (fd_loop, LOOP_GET_STATUS, &loop_info) == -1)
    {
      ksblog (LOG_ERR, "ioctl(%d, LOOP_GET_STATUS, %p): %s", fd_loop,
	      &loop_info, strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
  loop_info.lo_flags = flags;
  if (ioctl (fd_loop, LOOP_SET_STATUS, &loop_info) == -1)
    {
      int err = errno;
      char *f = ksbflags (loop_info_flags, loop_info.lo_flags);
      ksblog (LOG_ERR, "ioctl(%d, LOOP_GET_STATUS, %p(lo_flags=%s): %s",
	      fd_loop, &loop_info, f, strerror (err));
      free (f);
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbcleanupfd (int *fdp)
{
  if (*fdp != -1)
    ksbclose (*fdp);
}

#define fdint __attribute__((cleanup (ksbcleanupfd))) int

static void
ksbloopmount (const char *path_backfile, const char *path_target,
	      const char *fstype, int flags, const char *data)
{
  fdint fd_backfile = ksbopen (path_backfile, O_RDWR);
  int loopdevno = ksbloopgetfree ();
  size_t sz = snprintf (NULL, 0, "/dev/loop%d", loopdevno);
  char loopdevname[sz + 1];
  snprintf (loopdevname, sizeof (loopdevname), "/dev/loop%d", loopdevno);
  fdint fd_loop = ksbopen (loopdevname, O_RDWR);
  ksbloopset (fd_loop, fd_backfile);
  int f = LO_FLAGS_AUTOCLEAR;
  if (flags & MS_RDONLY)
    f |= LO_FLAGS_READ_ONLY;
  ksbloopsetstatusflag (fd_loop, f);
  ksbmount (loopdevname, path_target, fstype, flags, data);
}

static void
ksbchdir (const char *dir)
{
  if (chdir (dir) == -1)
    {
      ksblog (LOG_ERR, "chdir(%s): %s", dir, strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbchroot (const char *dir)
{
  if (chroot (dir) == -1)
    {
      ksblog (LOG_ERR, "chroot(%s): %s", dir, strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbsetuid (uid_t uid)
{
  if (setuid (uid) == -1)
    {
      ksblog (LOG_ERR, "setuid(%d): %s", uid, strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbsetgid (gid_t gid)
{
  if (setgid (gid) == -1)
    {
      ksblog (LOG_ERR, "setgid(%d): %s", gid, strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
}

static void
ksbenvvinit (char ***envvp)
{
  *envvp = malloc (sizeof (char **));
  if (*envvp == NULL)
    {
      ksblog (LOG_ERR, "malloc(%zu): %s", sizeof (char **), strerror (errno));
      ksbthrow (EXIT_FAILURE);
    }
  **envvp = NULL;
}

static void
ksbenvvput (char ***envvp, char *env)
{
  size_t size = malloc_usable_size (*envvp);
  size_t cap = size / sizeof (char **);
  int idx = 0;
  while (idx < cap && (*envvp)[idx])
    idx++;
  while (idx + 1 >= cap)
    {
      cap *= 2;
      size_t size_new = cap * sizeof (char **);
      char **envv_new = realloc (*envvp, size_new);
      if (envv_new == NULL)
	{
	  ksblog (LOG_ERR, "realloc(%zu): %s", size_new, strerror (errno));
	  ksbthrow (EXIT_FAILURE);
	}
      *envvp = envv_new;
    }
  (*envvp)[idx++] = env;
  (*envvp)[idx] = NULL;
}

static void
ksbenvvcpy (char ***envvp, const char *name)
{
  size_t l = strlen (name);
  for (char **e = environ; *e; e++)
    {
      if (strncmp (name, *e, l) == 0 && (*e)[l] == '=')
	{
	  ksbenvvput (envvp, *e);
	  break;
	}
    }
}

#if 0
static void
ksbenvvfree (char **envv)
{
  free (envv);
}
#endif

#ifndef DATADIR
#define DATADIR "/usr/local/share"
#endif

int
main (int argc, char *argv[])
{
  const char *lowerimage = DATADIR "/debian.img";
  const char *lowerfstype = "ext4";
  const char *loweropt = NULL;
  const char *rwimage = NULL;
  const char *rwfstype = "ext4";
  const char *rwopt = NULL;
  int opt;
  while ((opt = getopt (argc, argv, "f:t:o:F:T:O:vh")) != -1)
    {
      switch (opt)
	{
	case 'f':
	  lowerimage = optarg;
	  break;
	case 't':
	  lowerfstype = optarg;
	  break;
	case 'o':
	  loweropt = optarg;
	  break;
	case 'F':
	  rwimage = optarg;
	  break;
	case 'T':
	  rwfstype = optarg;
	  break;
	case 'O':
	  rwopt = optarg;
	  break;
	case 'v':
	  fprintf (stdout, "%s\n", PACKAGE_STRING);
	  exit (EXIT_SUCCESS);
	case 'h':
	  fprintf (stdout, "%s\n", PACKAGE_STRING);
	  fprintf (stdout, "\n");
	  fprintf (stdout, "Usage:\n");
	  fprintf (stdout, "  %s [options] [--] [cmd [arg ...]]\n", argv[0]);
	  fprintf (stdout, "\n");
	  fprintf (stdout, "Options:\n");
	  fprintf (stdout, "  -f file    : lower image file      [%s]\n",
		   lowerimage);
	  fprintf (stdout, "  -t fstype  : lower filesystem name [%s]\n",
		   lowerfstype);
	  fprintf (stdout, "  -o options : lower mount options   [%s]\n",
		   loweropt);
	  fprintf (stdout, "  -F file    : rw    image file      [%s]\n",
		   rwimage);
	  fprintf (stdout, "  -T fstype  : rw    filesystem name [%s]\n",
		   rwfstype);
	  fprintf (stdout, "  -O options : rw    mount options   [%s]\n",
		   rwopt);
	  fprintf (stdout, "\n");
	  fprintf (stdout, "  -v         : print version and exit\n");
	  fprintf (stdout, "  -h         : print usage   and exit\n");
	  fprintf (stdout, "\n");
	  exit (EXIT_SUCCESS);

	default:
	  exit (EXIT_FAILURE);

	}
    }
  argc -= optind;
  argv += optind;
  ksbtry (int ret)
  {
    ksbunshare (CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS);
    pid_t pid = fork ();
    if (pid == 0)
      {
	ksbtry (int ret)
	{
	  ksbsetuid (0);
	  ksbsetgid (0);
	  {
	    fdint rfd = ksbopen ("/etc/resolv.conf", O_RDONLY);
	    ksbmount ("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
	    ksbmount ("tmpfs", "/mnt", "tmpfs", 0, NULL);
	    ksbmkdir ("/mnt/lower", 0755);
	    ksbmkdir ("/mnt/root", 0755);
	    ksbmkdir ("/mnt/rw", 0755);
	    ksbloopmount (lowerimage, "/mnt/lower", lowerfstype, MS_RDONLY,
			  loweropt);
	    if (rwimage)
	      ksbloopmount (rwimage, "/mnt/rw", rwfstype, 0, rwopt);
	    ksbmkdir_nc ("/mnt/rw/upper", 0755);
	    ksbmkdir_nc ("/mnt/rw/work", 0755);
	    ksbmount ("overlay", "/mnt/root", "overlay", 0,
		      "lowerdir=/mnt/lower,upperdir=/mnt/rw/upper,workdir=/mnt/rw/work");
	    fdint wfd = ksbopen ("/mnt/root/etc/resolv.conf", O_WRONLY);
	    if (sendfile (wfd, rfd, NULL, 0xffffffff) == -1)
	      {
		ksblog (LOG_ERR, "sendfile(%d, %d, NULL, 0xffffffff): %s",
			wfd, rfd, strerror (errno));
		ksbthrow (EXIT_FAILURE);
	      }
	    ksbmount ("proc", "/mnt/root/proc", "proc",
		      MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, NULL);
	    ksbmount ("/sys", "/mnt/root/sys", NULL, MS_BIND, NULL);
	    ksbmount ("/dev", "/mnt/root/dev", NULL, MS_BIND, NULL);
	    ksbmount ("/dev/pts", "/mnt/root/dev/pts", NULL, MS_BIND, NULL);
	    ksbmkdir_nc ("/mnt/root/run", 0755);
	    ksbmount ("none", "/mnt/root/run", "tmpfs", MS_NOSUID | MS_NODEV,
		      "mode=755");
	    ksbmkdir_nc ("/mnt/root/run/lock", 0755);
	    ksbmkdir_nc ("/mnt/root/run/shm", 0755);
	    ksbmkdir_nc ("/mnt/root/run/user", 0755);
	    ksbmount ("none", "/mnt/root/run/lock", "tmpfs",
		      MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, NULL);
	    ksbmount ("none", "/mnt/root/run/shm", "tmpfs",
		      MS_NOSUID | MS_NODEV | MS_NOATIME, NULL);
	    ksbmount ("none", "/mnt/root/run/user", "tmpfs",
		      MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME,
		      "mode=755");
	  }
	  ksbchdir ("/mnt/root/root");
	  ksbchroot ("/mnt/root");
	  ksbchdir ("/root");
	  char **envv;
	  ksbenvvinit (&envv);
	  ksbenvvcpy (&envv, "LANG");
	  ksbenvvcpy (&envv, "SHELL");
	  ksbenvvcpy (&envv, "TERM");
	  ksbenvvput (&envv, "HOME=/root");
	  ksbenvvput (&envv, "USER=root");
	  ksbenvvput (&envv, "LOGNAME=root");
	  ksbenvvput (&envv,
		      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
	  if (argc <= 1)
	    {
	      char *argv[] = { getenv ("SHELL"), NULL };
	      if (argv[0] == NULL || *argv[0] == '\0')
		argv[0] = "/bin/sh";
	      execvpe (*argv, argv, envv);
	      ksblog (LOG_ERR, "%s: %s", *argv, strerror (errno));
	    }
	  else
	    {
	      execvpe (*argv, argv, envv);
	      ksblog (LOG_ERR, "%s: %s", *argv, strerror (errno));
	    }
	  ksbthrow (EXIT_FAILURE);
	}
	ksbcatch_all
	{
	  exit (ret);
	}
	ksbend;
      }
    int status = 0;
    while (1)
      {
	if (waitpid (pid, &status, 0) == -1)
	  {
	    if (errno == EINTR)
	      continue;
	    perror ("waitpid");
	    ksbthrow (EXIT_FAILURE);
	  }
	if (WIFEXITED (status))
	  {
	    exit (WEXITSTATUS (status));
	  }
	if (WIFSIGNALED (status))
	  {
	    exit (WTERMSIG (status) + 128);
	  }
	exit (EXIT_FAILURE);
      }
  }
  ksbcatch_all
  {
    exit (ret);
  }
  ksbend;
}
