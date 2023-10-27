/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)errno.h	8.5 (Berkeley) 1/21/94
 */

/*
    Do not use these errno values as return values! They are only to be used
    when sending errno values over the network, where different operating
    systems can have different integer values for the below errno values.
*/

#ifndef TCM_COMPAT_STABLE_ERRNO_H_
#define TCM_COMPAT_STABLE_ERRNO_H_

#include <errno.h>

enum {
    TCM_EPERM   = 1,  /* Operation not permitted */
    TCM_ENOENT  = 2,  /* No such file or directory */
    TCM_ESRCH   = 3,  /* No such process */
    TCM_EINTR   = 4,  /* Interrupted system call */
    TCM_EIO     = 5,  /* Input/output error */
    TCM_ENXIO   = 6,  /* Device not configured */
    TCM_E2BIG   = 7,  /* Argument list too long */
    TCM_ENOEXEC = 8,  /* Exec format error */
    TCM_EBADF   = 9,  /* Bad file descriptor */
    TCM_ECHILD  = 10, /* No child processes */
    TCM_EDEADLK = 11, /* Resource deadlock avoided */
    TCM_ENOMEM  = 12, /* Cannot allocate memory */
    TCM_EACCES  = 13, /* Permission denied */
    TCM_EFAULT  = 14, /* Bad address */
    TCM_ENOTBLK = 15, /* Block device required */
    TCM_EBUSY   = 16, /* Device busy */
    TCM_EEXIST  = 17, /* File exists */
    TCM_EXDEV   = 18, /* Cross-device link */
    TCM_ENODEV  = 19, /* Operation not supported by device */
    TCM_ENOTDIR = 20, /* Not a directory */
    TCM_EISDIR  = 21, /* Is a directory */
    TCM_EINVAL  = 22, /* Invalid argument */
    TCM_ENFILE  = 23, /* Too many open files in system */
    TCM_EMFILE  = 24, /* Too many open files */
    TCM_ENOTTY  = 25, /* Inappropriate ioctl for device */
    TCM_ETXTBSY = 26, /* Text file busy */
    TCM_EFBIG   = 27, /* File too large */
    TCM_ENOSPC  = 28, /* No space left on device */
    TCM_ESPIPE  = 29, /* Illegal seek */
    TCM_EROFS   = 30, /* Read-only filesystem */
    TCM_EMLINK  = 31, /* Too many links */
    TCM_EPIPE   = 32, /* Broken pipe */

    /* math software */
    TCM_EDOM   = 33, /* Numerical argument out of domain */
    TCM_ERANGE = 34, /* Result too large */

    /* non-blocking and interrupt i/o */
    TCM_EAGAIN      = 35, /* Resource temporarily unavailable */
    TCM_EINPROGRESS = 36, /* Operation now in progress */
    TCM_EALREADY    = 37, /* Operation already in progress */

    /* ipc/network software -- argument errors */
    TCM_ENOTSOCK        = 38, /* Socket operation on non-socket */
    TCM_EDESTADDRREQ    = 39, /* Destination address required */
    TCM_EMSGSIZE        = 40, /* Message too long */
    TCM_EPROTOTYPE      = 41, /* Protocol wrong type for socket */
    TCM_ENOPROTOOPT     = 42, /* Protocol not available */
    TCM_EPROTONOSUPPORT = 43, /* Protocol not supported */
    TCM_ESOCKTNOSUPPORT = 44, /* Socket type not supported */
    TCM_EOPNOTSUPP      = 45, /* Operation not supported */
    TCM_EPFNOSUPPORT    = 46, /* Protocol family not supported */
    TCM_EAFNOSUPPORT = 47, /* Address family not supported by protocol family */
    TCM_EADDRINUSE   = 48, /* Address already in use */
    TCM_EADDRNOTAVAIL = 49, /* Can't assign requested address */

    /* ipc/network software -- operational errors */
    TCM_ENETDOWN     = 50, /* Network is down */
    TCM_ENETUNREACH  = 51, /* Network is unreachable */
    TCM_ENETRESET    = 52, /* Network dropped connection on reset */
    TCM_ECONNABORTED = 53, /* Software caused connection abort */
    TCM_ECONNRESET   = 54, /* Connection reset by peer */
    TCM_ENOBUFS      = 55, /* No buffer space available */
    TCM_EISCONN      = 56, /* Socket is already connected */
    TCM_ENOTCONN     = 57, /* Socket is not connected */
    TCM_ESHUTDOWN    = 58, /* Can't send after socket shutdown */
    TCM_ETOOMANYREFS = 59, /* Too many references: can't splice */
    TCM_ETIMEDOUT    = 60, /* Operation timed out */
    TCM_ECONNREFUSED = 61, /* Connection refused */

    TCM_ELOOP        = 62, /* Too many levels of symbolic links */
    TCM_ENAMETOOLONG = 63, /* File name too long */

    /* should be rearranged */
    TCM_EHOSTDOWN    = 64, /* Host is down */
    TCM_EHOSTUNREACH = 65, /* No route to host */
    TCM_ENOTEMPTY    = 66, /* Directory not empty */

    /* quotas & mush */
    TCM_EPROCLIM = 67, /* Too many processes */
    TCM_EUSERS   = 68, /* Too many users */
    TCM_EDQUOT   = 69, /* Disc quota exceeded */

    /* Network File System */
    TCM_ESTALE        = 70, /* Stale NFS file handle */
    TCM_EREMOTE       = 71, /* Too many levels of remote in path */
    TCM_EBADRPC       = 72, /* RPC struct is bad */
    TCM_ERPCMISMATCH  = 73, /* RPC version wrong */
    TCM_EPROGUNAVAIL  = 74, /* RPC prog. not avail */
    TCM_EPROGMISMATCH = 75, /* Program version wrong */
    TCM_EPROCUNAVAIL  = 76, /* Bad procedure for program */

    TCM_ENOLCK          = 77, /* No locks available */
    TCM_ENOSYS          = 78, /* Function not implemented */
    TCM_EFTYPE          = 79, /* Inappropriate file type or format */
    TCM_EAUTH           = 80, /* Authentication error */
    TCM_ENEEDAUTH       = 81, /* Need authenticator */
    TCM_EIDRM           = 82, /* Identifier removed */
    TCM_ENOMSG          = 83, /* No message of desired type */
    TCM_EOVERFLOW       = 84, /* Value too large to be stored in data type */
    TCM_ECANCELED       = 85, /* Operation canceled */
    TCM_EILSEQ          = 86, /* Illegal byte sequence */
    TCM_ENOATTR         = 87, /* Attribute not found */
    TCM_EDOOFUS         = 88, /* Programming error */
    TCM_EBADMSG         = 89, /* Bad message */
    TCM_EMULTIHOP       = 90, /* Multihop attempted */
    TCM_ENOLINK         = 91, /* Link has been severed */
    TCM_EPROTO          = 92, /* Protocol error */
    TCM_ENOTCAPABLE     = 93, /* Capabilities insufficient */
    TCM_ECAPMODE        = 94, /* Not permitted in capability mode */
    TCM_ENOTRECOVERABLE = 95, /* State not recoverable */
    TCM_EOWNERDEAD      = 96, /* Previous owner died */
    TCM_EINTEGRITY      = 97  /* Integrity check failed */
};

#define TCM_EWOULDBLOCK TCM_EAGAIN
#define TCM_ENOTSUP TCM_EOPNOTSUPP
#define TCM_MAX_ERRNO 1024

/* ----- Negative for errno values unsupported by the OS ----- */

#ifdef EPERM
#define TCM_SYS_EPERM EPERM
#else
#define TCM_SYS_EPERM (TCM_EPERM + TCM_MAX_ERRNO)
#endif
#ifdef ENOENT
#define TCM_SYS_ENOENT ENOENT
#else
#define TCM_SYS_ENOENT (TCM_ENOENT + TCM_MAX_ERRNO)
#endif
#ifdef ESRCH
#define TCM_SYS_ESRCH ESRCH
#else
#define TCM_SYS_ESRCH (TCM_ESRCH + TCM_MAX_ERRNO)
#endif
#ifdef EINTR
#define TCM_SYS_EINTR EINTR
#else
#define TCM_SYS_EINTR (TCM_EINTR + TCM_MAX_ERRNO)
#endif
#ifdef EIO
#define TCM_SYS_EIO EIO
#else
#define TCM_SYS_EIO (TCM_EIO + TCM_MAX_ERRNO)
#endif
#ifdef ENXIO
#define TCM_SYS_ENXIO ENXIO
#else
#define TCM_SYS_ENXIO (TCM_ENXIO + TCM_MAX_ERRNO)
#endif
#ifdef E2BIG
#define TCM_SYS_E2BIG E2BIG
#else
#define TCM_SYS_E2BIG (TCM_E2BIG + TCM_MAX_ERRNO)
#endif
#ifdef ENOEXEC
#define TCM_SYS_ENOEXEC ENOEXEC
#else
#define TCM_SYS_ENOEXEC (TCM_ENOEXEC + TCM_MAX_ERRNO)
#endif
#ifdef EBADF
#define TCM_SYS_EBADF EBADF
#else
#define TCM_SYS_EBADF (TCM_EBADF + TCM_MAX_ERRNO)
#endif
#ifdef ECHILD
#define TCM_SYS_ECHILD ECHILD
#else
#define TCM_SYS_ECHILD (TCM_ECHILD + TCM_MAX_ERRNO)
#endif
#ifdef EDEADLK
#define TCM_SYS_EDEADLK EDEADLK
#else
#define TCM_SYS_EDEADLK (TCM_EDEADLK + TCM_MAX_ERRNO)
#endif
#ifdef ENOMEM
#define TCM_SYS_ENOMEM ENOMEM
#else
#define TCM_SYS_ENOMEM (TCM_ENOMEM + TCM_MAX_ERRNO)
#endif
#ifdef EACCES
#define TCM_SYS_EACCES EACCES
#else
#define TCM_SYS_EACCES (TCM_EACCES + TCM_MAX_ERRNO)
#endif
#ifdef EFAULT
#define TCM_SYS_EFAULT EFAULT
#else
#define TCM_SYS_EFAULT (TCM_EFAULT + TCM_MAX_ERRNO)
#endif
#ifdef ENOTBLK
#define TCM_SYS_ENOTBLK ENOTBLK
#else
#define TCM_SYS_ENOTBLK (TCM_ENOTBLK + TCM_MAX_ERRNO)
#endif
#ifdef EBUSY
#define TCM_SYS_EBUSY EBUSY
#else
#define TCM_SYS_EBUSY (TCM_EBUSY + TCM_MAX_ERRNO)
#endif
#ifdef EEXIST
#define TCM_SYS_EEXIST EEXIST
#else
#define TCM_SYS_EEXIST (TCM_EEXIST + TCM_MAX_ERRNO)
#endif
#ifdef EXDEV
#define TCM_SYS_EXDEV EXDEV
#else
#define TCM_SYS_EXDEV (TCM_EXDEV + TCM_MAX_ERRNO)
#endif
#ifdef ENODEV
#define TCM_SYS_ENODEV ENODEV
#else
#define TCM_SYS_ENODEV (TCM_ENODEV + TCM_MAX_ERRNO)
#endif
#ifdef ENOTDIR
#define TCM_SYS_ENOTDIR ENOTDIR
#else
#define TCM_SYS_ENOTDIR (TCM_ENOTDIR + TCM_MAX_ERRNO)
#endif
#ifdef EISDIR
#define TCM_SYS_EISDIR EISDIR
#else
#define TCM_SYS_EISDIR (TCM_EISDIR + TCM_MAX_ERRNO)
#endif
#ifdef EINVAL
#define TCM_SYS_EINVAL EINVAL
#else
#define TCM_SYS_EINVAL (TCM_EINVAL + TCM_MAX_ERRNO)
#endif
#ifdef ENFILE
#define TCM_SYS_ENFILE ENFILE
#else
#define TCM_SYS_ENFILE (TCM_ENFILE + TCM_MAX_ERRNO)
#endif
#ifdef EMFILE
#define TCM_SYS_EMFILE EMFILE
#else
#define TCM_SYS_EMFILE (TCM_EMFILE + TCM_MAX_ERRNO)
#endif
#ifdef ENOTTY
#define TCM_SYS_ENOTTY ENOTTY
#else
#define TCM_SYS_ENOTTY (TCM_ENOTTY + TCM_MAX_ERRNO)
#endif
#ifdef ETXTBSY
#define TCM_SYS_ETXTBSY ETXTBSY
#else
#define TCM_SYS_ETXTBSY (TCM_ETXTBSY + TCM_MAX_ERRNO)
#endif
#ifdef EFBIG
#define TCM_SYS_EFBIG EFBIG
#else
#define TCM_SYS_EFBIG (TCM_EFBIG + TCM_MAX_ERRNO)
#endif
#ifdef ENOSPC
#define TCM_SYS_ENOSPC ENOSPC
#else
#define TCM_SYS_ENOSPC (TCM_ENOSPC + TCM_MAX_ERRNO)
#endif
#ifdef ESPIPE
#define TCM_SYS_ESPIPE ESPIPE
#else
#define TCM_SYS_ESPIPE (TCM_ESPIPE + TCM_MAX_ERRNO)
#endif
#ifdef EROFS
#define TCM_SYS_EROFS EROFS
#else
#define TCM_SYS_EROFS (TCM_EROFS + TCM_MAX_ERRNO)
#endif
#ifdef EMLINK
#define TCM_SYS_EMLINK EMLINK
#else
#define TCM_SYS_EMLINK (TCM_EMLINK + TCM_MAX_ERRNO)
#endif
#ifdef EPIPE
#define TCM_SYS_EPIPE EPIPE
#else
#define TCM_SYS_EPIPE (TCM_EPIPE + TCM_MAX_ERRNO)
#endif
#ifdef EDOM
#define TCM_SYS_EDOM EDOM
#else
#define TCM_SYS_EDOM (TCM_EDOM + TCM_MAX_ERRNO)
#endif
#ifdef ERANGE
#define TCM_SYS_ERANGE ERANGE
#else
#define TCM_SYS_ERANGE (TCM_ERANGE + TCM_MAX_ERRNO)
#endif
#ifdef EAGAIN
#define TCM_SYS_EAGAIN EAGAIN
#else
#define TCM_SYS_EAGAIN (TCM_EAGAIN + TCM_MAX_ERRNO)
#endif
#ifdef EWOULDBLOCK
#define TCM_SYS_EWOULDBLOCK EWOULDBLOCK
#else
#define TCM_SYS_EWOULDBLOCK (TCM_EWOULDBLOCK + TCM_MAX_ERRNO)
#endif
#ifdef EAGAIN
#define TCM_SYS_EAGAIN EAGAIN
#else
#define TCM_SYS_EAGAIN (TCM_EAGAIN + TCM_MAX_ERRNO)
#endif
#ifdef EINPROGRESS
#define TCM_SYS_EINPROGRESS EINPROGRESS
#else
#define TCM_SYS_EINPROGRESS (TCM_EINPROGRESS + TCM_MAX_ERRNO)
#endif
#ifdef EALREADY
#define TCM_SYS_EALREADY EALREADY
#else
#define TCM_SYS_EALREADY (TCM_EALREADY + TCM_MAX_ERRNO)
#endif
#ifdef ENOTSOCK
#define TCM_SYS_ENOTSOCK ENOTSOCK
#else
#define TCM_SYS_ENOTSOCK (TCM_ENOTSOCK + TCM_MAX_ERRNO)
#endif
#ifdef EDESTADDRREQ
#define TCM_SYS_EDESTADDRREQ EDESTADDRREQ
#else
#define TCM_SYS_EDESTADDRREQ (TCM_EDESTADDRREQ + TCM_MAX_ERRNO)
#endif
#ifdef EMSGSIZE
#define TCM_SYS_EMSGSIZE EMSGSIZE
#else
#define TCM_SYS_EMSGSIZE (TCM_EMSGSIZE + TCM_MAX_ERRNO)
#endif
#ifdef EPROTOTYPE
#define TCM_SYS_EPROTOTYPE EPROTOTYPE
#else
#define TCM_SYS_EPROTOTYPE (TCM_EPROTOTYPE + TCM_MAX_ERRNO)
#endif
#ifdef ENOPROTOOPT
#define TCM_SYS_ENOPROTOOPT ENOPROTOOPT
#else
#define TCM_SYS_ENOPROTOOPT (TCM_ENOPROTOOPT + TCM_MAX_ERRNO)
#endif
#ifdef EPROTONOSUPPORT
#define TCM_SYS_EPROTONOSUPPORT EPROTONOSUPPORT
#else
#define TCM_SYS_EPROTONOSUPPORT (TCM_EPROTONOSUPPORT + TCM_MAX_ERRNO)
#endif
#ifdef ESOCKTNOSUPPORT
#define TCM_SYS_ESOCKTNOSUPPORT ESOCKTNOSUPPORT
#else
#define TCM_SYS_ESOCKTNOSUPPORT (TCM_ESOCKTNOSUPPORT + TCM_MAX_ERRNO)
#endif
#ifdef EOPNOTSUPP
#define TCM_SYS_EOPNOTSUPP EOPNOTSUPP
#else
#define TCM_SYS_EOPNOTSUPP (TCM_EOPNOTSUPP + TCM_MAX_ERRNO)
#endif
#ifdef ENOTSUP
#define TCM_SYS_ENOTSUP ENOTSUP
#else
#define TCM_SYS_ENOTSUP (TCM_ENOTSUP + TCM_MAX_ERRNO)
#endif
#ifdef EOPNOTSUPP
#define TCM_SYS_EOPNOTSUPP EOPNOTSUPP
#else
#define TCM_SYS_EOPNOTSUPP (TCM_EOPNOTSUPP + TCM_MAX_ERRNO)
#endif
#ifdef EPFNOSUPPORT
#define TCM_SYS_EPFNOSUPPORT EPFNOSUPPORT
#else
#define TCM_SYS_EPFNOSUPPORT (TCM_EPFNOSUPPORT + TCM_MAX_ERRNO)
#endif
#ifdef EAFNOSUPPORT
#define TCM_SYS_EAFNOSUPPORT EAFNOSUPPORT
#else
#define TCM_SYS_EAFNOSUPPORT (TCM_EAFNOSUPPORT + TCM_MAX_ERRNO)
#endif
#ifdef EADDRINUSE
#define TCM_SYS_EADDRINUSE EADDRINUSE
#else
#define TCM_SYS_EADDRINUSE (TCM_EADDRINUSE + TCM_MAX_ERRNO)
#endif
#ifdef EADDRNOTAVAIL
#define TCM_SYS_EADDRNOTAVAIL EADDRNOTAVAIL
#else
#define TCM_SYS_EADDRNOTAVAIL (TCM_EADDRNOTAVAIL + TCM_MAX_ERRNO)
#endif
#ifdef ENETDOWN
#define TCM_SYS_ENETDOWN ENETDOWN
#else
#define TCM_SYS_ENETDOWN (TCM_ENETDOWN + TCM_MAX_ERRNO)
#endif
#ifdef ENETUNREACH
#define TCM_SYS_ENETUNREACH ENETUNREACH
#else
#define TCM_SYS_ENETUNREACH (TCM_ENETUNREACH + TCM_MAX_ERRNO)
#endif
#ifdef ENETRESET
#define TCM_SYS_ENETRESET ENETRESET
#else
#define TCM_SYS_ENETRESET (TCM_ENETRESET + TCM_MAX_ERRNO)
#endif
#ifdef ECONNABORTED
#define TCM_SYS_ECONNABORTED ECONNABORTED
#else
#define TCM_SYS_ECONNABORTED (TCM_ECONNABORTED + TCM_MAX_ERRNO)
#endif
#ifdef ECONNRESET
#define TCM_SYS_ECONNRESET ECONNRESET
#else
#define TCM_SYS_ECONNRESET (TCM_ECONNRESET + TCM_MAX_ERRNO)
#endif
#ifdef ENOBUFS
#define TCM_SYS_ENOBUFS ENOBUFS
#else
#define TCM_SYS_ENOBUFS (TCM_ENOBUFS + TCM_MAX_ERRNO)
#endif
#ifdef EISCONN
#define TCM_SYS_EISCONN EISCONN
#else
#define TCM_SYS_EISCONN (TCM_EISCONN + TCM_MAX_ERRNO)
#endif
#ifdef ENOTCONN
#define TCM_SYS_ENOTCONN ENOTCONN
#else
#define TCM_SYS_ENOTCONN (TCM_ENOTCONN + TCM_MAX_ERRNO)
#endif
#ifdef ESHUTDOWN
#define TCM_SYS_ESHUTDOWN ESHUTDOWN
#else
#define TCM_SYS_ESHUTDOWN (TCM_ESHUTDOWN + TCM_MAX_ERRNO)
#endif
#ifdef ETOOMANYREFS
#define TCM_SYS_ETOOMANYREFS ETOOMANYREFS
#else
#define TCM_SYS_ETOOMANYREFS (TCM_ETOOMANYREFS + TCM_MAX_ERRNO)
#endif
#ifdef ETIMEDOUT
#define TCM_SYS_ETIMEDOUT ETIMEDOUT
#else
#define TCM_SYS_ETIMEDOUT (TCM_ETIMEDOUT + TCM_MAX_ERRNO)
#endif
#ifdef ECONNREFUSED
#define TCM_SYS_ECONNREFUSED ECONNREFUSED
#else
#define TCM_SYS_ECONNREFUSED (TCM_ECONNREFUSED + TCM_MAX_ERRNO)
#endif
#ifdef ELOOP
#define TCM_SYS_ELOOP ELOOP
#else
#define TCM_SYS_ELOOP (TCM_ELOOP + TCM_MAX_ERRNO)
#endif
#ifdef ENAMETOOLONG
#define TCM_SYS_ENAMETOOLONG ENAMETOOLONG
#else
#define TCM_SYS_ENAMETOOLONG (TCM_ENAMETOOLONG + TCM_MAX_ERRNO)
#endif
#ifdef EHOSTDOWN
#define TCM_SYS_EHOSTDOWN EHOSTDOWN
#else
#define TCM_SYS_EHOSTDOWN (TCM_EHOSTDOWN + TCM_MAX_ERRNO)
#endif
#ifdef EHOSTUNREACH
#define TCM_SYS_EHOSTUNREACH EHOSTUNREACH
#else
#define TCM_SYS_EHOSTUNREACH (TCM_EHOSTUNREACH + TCM_MAX_ERRNO)
#endif
#ifdef ENOTEMPTY
#define TCM_SYS_ENOTEMPTY ENOTEMPTY
#else
#define TCM_SYS_ENOTEMPTY (TCM_ENOTEMPTY + TCM_MAX_ERRNO)
#endif
#ifdef EPROCLIM
#define TCM_SYS_EPROCLIM EPROCLIM
#else
#define TCM_SYS_EPROCLIM (TCM_EPROCLIM + TCM_MAX_ERRNO)
#endif
#ifdef EUSERS
#define TCM_SYS_EUSERS EUSERS
#else
#define TCM_SYS_EUSERS (TCM_EUSERS + TCM_MAX_ERRNO)
#endif
#ifdef EDQUOT
#define TCM_SYS_EDQUOT EDQUOT
#else
#define TCM_SYS_EDQUOT (TCM_EDQUOT + TCM_MAX_ERRNO)
#endif
#ifdef ESTALE
#define TCM_SYS_ESTALE ESTALE
#else
#define TCM_SYS_ESTALE (TCM_ESTALE + TCM_MAX_ERRNO)
#endif
#ifdef EREMOTE
#define TCM_SYS_EREMOTE EREMOTE
#else
#define TCM_SYS_EREMOTE (TCM_EREMOTE + TCM_MAX_ERRNO)
#endif
#ifdef EBADRPC
#define TCM_SYS_EBADRPC EBADRPC
#else
#define TCM_SYS_EBADRPC (TCM_EBADRPC + TCM_MAX_ERRNO)
#endif
#ifdef ERPCMISMATCH
#define TCM_SYS_ERPCMISMATCH ERPCMISMATCH
#else
#define TCM_SYS_ERPCMISMATCH (TCM_ERPCMISMATCH + TCM_MAX_ERRNO)
#endif
#ifdef EPROGUNAVAIL
#define TCM_SYS_EPROGUNAVAIL EPROGUNAVAIL
#else
#define TCM_SYS_EPROGUNAVAIL (TCM_EPROGUNAVAIL + TCM_MAX_ERRNO)
#endif
#ifdef EPROGMISMATCH
#define TCM_SYS_EPROGMISMATCH EPROGMISMATCH
#else
#define TCM_SYS_EPROGMISMATCH (TCM_EPROGMISMATCH + TCM_MAX_ERRNO)
#endif
#ifdef EPROCUNAVAIL
#define TCM_SYS_EPROCUNAVAIL EPROCUNAVAIL
#else
#define TCM_SYS_EPROCUNAVAIL (TCM_EPROCUNAVAIL + TCM_MAX_ERRNO)
#endif
#ifdef ENOLCK
#define TCM_SYS_ENOLCK ENOLCK
#else
#define TCM_SYS_ENOLCK (TCM_ENOLCK + TCM_MAX_ERRNO)
#endif
#ifdef ENOSYS
#define TCM_SYS_ENOSYS ENOSYS
#else
#define TCM_SYS_ENOSYS (TCM_ENOSYS + TCM_MAX_ERRNO)
#endif
#ifdef EFTYPE
#define TCM_SYS_EFTYPE EFTYPE
#else
#define TCM_SYS_EFTYPE (TCM_EFTYPE + TCM_MAX_ERRNO)
#endif
#ifdef EAUTH
#define TCM_SYS_EAUTH EAUTH
#else
#define TCM_SYS_EAUTH (TCM_EAUTH + TCM_MAX_ERRNO)
#endif
#ifdef ENEEDAUTH
#define TCM_SYS_ENEEDAUTH ENEEDAUTH
#else
#define TCM_SYS_ENEEDAUTH (TCM_ENEEDAUTH + TCM_MAX_ERRNO)
#endif
#ifdef EIDRM
#define TCM_SYS_EIDRM EIDRM
#else
#define TCM_SYS_EIDRM (TCM_EIDRM + TCM_MAX_ERRNO)
#endif
#ifdef ENOMSG
#define TCM_SYS_ENOMSG ENOMSG
#else
#define TCM_SYS_ENOMSG (TCM_ENOMSG + TCM_MAX_ERRNO)
#endif
#ifdef EOVERFLOW
#define TCM_SYS_EOVERFLOW EOVERFLOW
#else
#define TCM_SYS_EOVERFLOW (TCM_EOVERFLOW + TCM_MAX_ERRNO)
#endif
#ifdef ECANCELED
#define TCM_SYS_ECANCELED ECANCELED
#else
#define TCM_SYS_ECANCELED (TCM_ECANCELED + TCM_MAX_ERRNO)
#endif
#ifdef EILSEQ
#define TCM_SYS_EILSEQ EILSEQ
#else
#define TCM_SYS_EILSEQ (TCM_EILSEQ + TCM_MAX_ERRNO)
#endif
#ifdef ENOATTR
#define TCM_SYS_ENOATTR ENOATTR
#else
#define TCM_SYS_ENOATTR (TCM_ENOATTR + TCM_MAX_ERRNO)
#endif
#ifdef EDOOFUS
#define TCM_SYS_EDOOFUS EDOOFUS
#else
#define TCM_SYS_EDOOFUS (TCM_EDOOFUS + TCM_MAX_ERRNO)
#endif
#ifdef EBADMSG
#define TCM_SYS_EBADMSG EBADMSG
#else
#define TCM_SYS_EBADMSG (TCM_EBADMSG + TCM_MAX_ERRNO)
#endif
#ifdef EMULTIHOP
#define TCM_SYS_EMULTIHOP EMULTIHOP
#else
#define TCM_SYS_EMULTIHOP (TCM_EMULTIHOP + TCM_MAX_ERRNO)
#endif
#ifdef ENOLINK
#define TCM_SYS_ENOLINK ENOLINK
#else
#define TCM_SYS_ENOLINK (TCM_ENOLINK + TCM_MAX_ERRNO)
#endif
#ifdef EPROTO
#define TCM_SYS_EPROTO EPROTO
#else
#define TCM_SYS_EPROTO (TCM_EPROTO + TCM_MAX_ERRNO)
#endif
#ifdef ENOTCAPABLE
#define TCM_SYS_ENOTCAPABLE ENOTCAPABLE
#else
#define TCM_SYS_ENOTCAPABLE (TCM_ENOTCAPABLE + TCM_MAX_ERRNO)
#endif
#ifdef ECAPMODE
#define TCM_SYS_ECAPMODE ECAPMODE
#else
#define TCM_SYS_ECAPMODE (TCM_ECAPMODE + TCM_MAX_ERRNO)
#endif
#ifdef ENOTRECOVERABLE
#define TCM_SYS_ENOTRECOVERABLE ENOTRECOVERABLE
#else
#define TCM_SYS_ENOTRECOVERABLE (TCM_ENOTRECOVERABLE + TCM_MAX_ERRNO)
#endif
#ifdef EOWNERDEAD
#define TCM_SYS_EOWNERDEAD EOWNERDEAD
#else
#define TCM_SYS_EOWNERDEAD (TCM_EOWNERDEAD + TCM_MAX_ERRNO)
#endif
#ifdef EINTEGRITY
#define TCM_SYS_EINTEGRITY EINTEGRITY
#else
#define TCM_SYS_EINTEGRITY (TCM_EINTEGRITY + TCM_MAX_ERRNO)
#endif

#endif