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
    systems can have different integer values for the below errno macros.
*/

#ifndef _TCM_COMPAT_STABLE_ERRNO_H_
#define _TCM_COMPAT_STABLE_ERRNO_H_

#include <errno.h>

#define	TCM_EPERM		1		/* Operation not permitted */
#define	TCM_ENOENT		2		/* No such file or directory */
#define	TCM_ESRCH		3		/* No such process */
#define	TCM_EINTR		4		/* Interrupted system call */
#define	TCM_EIO		5		/* Input/output error */
#define	TCM_ENXIO		6		/* Device not configured */
#define	TCM_E2BIG		7		/* Argument list too long */
#define	TCM_ENOEXEC		8		/* Exec format error */
#define	TCM_EBADF		9		/* Bad file descriptor */
#define	TCM_ECHILD		10		/* No child processes */
#define	TCM_EDEADLK		11		/* Resource deadlock avoided */
					/* 11 was EAGAIN */
#define	TCM_ENOMEM		12		/* Cannot allocate memory */
#define	TCM_EACCES		13		/* Permission denied */
#define	TCM_EFAULT		14		/* Bad address */
#define	TCM_ENOTBLK		15		/* Block device required */

#define	TCM_EBUSY		16		/* Device busy */
#define	TCM_EEXIST		17		/* File exists */
#define	TCM_EXDEV		18		/* Cross-device link */
#define	TCM_ENODEV		19		/* Operation not supported by device */
#define	TCM_ENOTDIR		20		/* Not a directory */
#define	TCM_EISDIR		21		/* Is a directory */
#define	TCM_EINVAL		22		/* Invalid argument */
#define	TCM_ENFILE		23		/* Too many open files in system */
#define	TCM_EMFILE		24		/* Too many open files */
#define	TCM_ENOTTY		25		/* Inappropriate ioctl for device */
#define	TCM_ETXTBSY		26		/* Text file busy */

#define	TCM_EFBIG		27		/* File too large */
#define	TCM_ENOSPC		28		/* No space left on device */
#define	TCM_ESPIPE		29		/* Illegal seek */
#define	TCM_EROFS		30		/* Read-only filesystem */
#define	TCM_EMLINK		31		/* Too many links */
#define	TCM_EPIPE		32		/* Broken pipe */

/* math software */
#define	TCM_EDOM		33		/* Numerical argument out of domain */
#define	TCM_ERANGE		34		/* Result too large */

/* non-blocking and interrupt i/o */
#define	TCM_EAGAIN		35		/* Resource temporarily unavailable */
#define	TCM_EWOULDBLOCK	TCM_EAGAIN		/* Operation would block */
#define	TCM_EINPROGRESS	36		/* Operation now in progress */
#define	TCM_EALREADY	37		/* Operation already in progress */

/* ipc/network software -- argument errors */
#define	TCM_ENOTSOCK	38		/* Socket operation on non-socket */
#define	TCM_EDESTADDRREQ	39		/* Destination address required */
#define	TCM_EMSGSIZE	40		/* Message too long */
#define	TCM_EPROTOTYPE	41		/* Protocol wrong type for socket */
#define	TCM_ENOPROTOOPT	42		/* Protocol not available */
#define	TCM_EPROTONOSUPPORT	43		/* Protocol not supported */
#define	TCM_ESOCKTNOSUPPORT	44		/* Socket type not supported */
#define	TCM_EOPNOTSUPP	45		/* Operation not supported */
#define	TCM_ENOTSUP		TCM_EOPNOTSUPP	/* Operation not supported */
#define	TCM_EPFNOSUPPORT	46		/* Protocol family not supported */
#define	TCM_EAFNOSUPPORT	47		/* Address family not supported by protocol family */
#define	TCM_EADDRINUSE	48		/* Address already in use */
#define	TCM_EADDRNOTAVAIL	49		/* Can't assign requested address */

/* ipc/network software -- operational errors */
#define	TCM_ENETDOWN	50		/* Network is down */
#define	TCM_ENETUNREACH	51		/* Network is unreachable */
#define	TCM_ENETRESET	52		/* Network dropped connection on reset */
#define	TCM_ECONNABORTED	53		/* Software caused connection abort */
#define	TCM_ECONNRESET	54		/* Connection reset by peer */
#define	TCM_ENOBUFS		55		/* No buffer space available */
#define	TCM_EISCONN		56		/* Socket is already connected */
#define	TCM_ENOTCONN	57		/* Socket is not connected */
#define	TCM_ESHUTDOWN	58		/* Can't send after socket shutdown */
#define	TCM_ETOOMANYREFS	59		/* Too many references: can't splice */
#define	TCM_ETIMEDOUT	60		/* Operation timed out */
#define	TCM_ECONNREFUSED	61		/* Connection refused */

#define	TCM_ELOOP		62		/* Too many levels of symbolic links */
#define	TCM_ENAMETOOLONG	63		/* File name too long */

/* should be rearranged */
#define	TCM_EHOSTDOWN	64		/* Host is down */
#define	TCM_EHOSTUNREACH	65		/* No route to host */
#define	TCM_ENOTEMPTY	66		/* Directory not empty */

/* quotas & mush */
#define	TCM_EPROCLIM	67		/* Too many processes */
#define	TCM_EUSERS		68		/* Too many users */
#define	TCM_EDQUOT		69		/* Disc quota exceeded */

/* Network File System */
#define	TCM_ESTALE		70		/* Stale NFS file handle */
#define	TCM_EREMOTE		71		/* Too many levels of remote in path */
#define	TCM_EBADRPC		72		/* RPC struct is bad */
#define	TCM_ERPCMISMATCH	73		/* RPC version wrong */
#define	TCM_EPROGUNAVAIL	74		/* RPC prog. not avail */
#define	TCM_EPROGMISMATCH	75		/* Program version wrong */
#define	TCM_EPROCUNAVAIL	76		/* Bad procedure for program */

#define	TCM_ENOLCK		77		/* No locks available */
#define	TCM_ENOSYS		78		/* Function not implemented */

#define	TCM_EFTYPE		79		/* Inappropriate file type or format */
#define	TCM_EAUTH		80		/* Authentication error */
#define	TCM_ENEEDAUTH	81		/* Need authenticator */
#define	TCM_EIDRM		82		/* Identifier removed */
#define	TCM_ENOMSG		83		/* No message of desired type */
#define	TCM_EOVERFLOW	84		/* Value too large to be stored in data type */
#define	TCM_ECANCELED	85		/* Operation canceled */
#define	TCM_EILSEQ		86		/* Illegal byte sequence */
#define	TCM_ENOATTR		87		/* Attribute not found */

#define	TCM_EDOOFUS		88		/* Programming error */

#define	TCM_EBADMSG		89		/* Bad message */
#define	TCM_EMULTIHOP	90		/* Multihop attempted */
#define	TCM_ENOLINK		91		/* Link has been severed */
#define	TCM_EPROTO		92		/* Protocol error */

#define	TCM_ENOTCAPABLE	93		/* Capabilities insufficient */
#define	TCM_ECAPMODE	94		/* Not permitted in capability mode */
#define	TCM_ENOTRECOVERABLE	95		/* State not recoverable */
#define	TCM_EOWNERDEAD	96		/* Previous owner died */
#define	TCM_EINTEGRITY	97		/* Integrity check failed */

/* ----- Return -1 for errno values unsupported by the OS ----- */

#ifdef EPERM
    #define TCM_SYS_EPERM EPERM
#else
    #define TCM_SYS_EPERM -TCM_EPERM 
#endif
#ifdef ENOENT
    #define TCM_SYS_ENOENT ENOENT
#else
    #define TCM_SYS_ENOENT -TCM_ENOENT 
#endif
#ifdef ESRCH
    #define TCM_SYS_ESRCH ESRCH
#else
    #define TCM_SYS_ESRCH -TCM_ESRCH 
#endif
#ifdef EINTR
    #define TCM_SYS_EINTR EINTR
#else
    #define TCM_SYS_EINTR -TCM_EINTR 
#endif
#ifdef EIO
    #define TCM_SYS_EIO EIO
#else
    #define TCM_SYS_EIO -TCM_EIO 
#endif
#ifdef ENXIO
    #define TCM_SYS_ENXIO ENXIO
#else
    #define TCM_SYS_ENXIO -TCM_ENXIO 
#endif
#ifdef E2BIG
    #define TCM_SYS_E2BIG E2BIG
#else
    #define TCM_SYS_E2BIG -TCM_E2BIG 
#endif
#ifdef ENOEXEC
    #define TCM_SYS_ENOEXEC ENOEXEC
#else
    #define TCM_SYS_ENOEXEC -TCM_ENOEXEC 
#endif
#ifdef EBADF
    #define TCM_SYS_EBADF EBADF
#else
    #define TCM_SYS_EBADF -TCM_EBADF 
#endif
#ifdef ECHILD
    #define TCM_SYS_ECHILD ECHILD
#else
    #define TCM_SYS_ECHILD -TCM_ECHILD 
#endif
#ifdef EDEADLK
    #define TCM_SYS_EDEADLK EDEADLK
#else
    #define TCM_SYS_EDEADLK -TCM_EDEADLK 
#endif
#ifdef ENOMEM
    #define TCM_SYS_ENOMEM ENOMEM
#else
    #define TCM_SYS_ENOMEM -TCM_ENOMEM 
#endif
#ifdef EACCES
    #define TCM_SYS_EACCES EACCES
#else
    #define TCM_SYS_EACCES -TCM_EACCES 
#endif
#ifdef EFAULT
    #define TCM_SYS_EFAULT EFAULT
#else
    #define TCM_SYS_EFAULT -TCM_EFAULT 
#endif
#ifdef ENOTBLK
    #define TCM_SYS_ENOTBLK ENOTBLK
#else
    #define TCM_SYS_ENOTBLK -TCM_ENOTBLK 
#endif
#ifdef EBUSY
    #define TCM_SYS_EBUSY EBUSY
#else
    #define TCM_SYS_EBUSY -TCM_EBUSY 
#endif
#ifdef EEXIST
    #define TCM_SYS_EEXIST EEXIST
#else
    #define TCM_SYS_EEXIST -TCM_EEXIST 
#endif
#ifdef EXDEV
    #define TCM_SYS_EXDEV EXDEV
#else
    #define TCM_SYS_EXDEV -TCM_EXDEV 
#endif
#ifdef ENODEV
    #define TCM_SYS_ENODEV ENODEV
#else
    #define TCM_SYS_ENODEV -TCM_ENODEV 
#endif
#ifdef ENOTDIR
    #define TCM_SYS_ENOTDIR ENOTDIR
#else
    #define TCM_SYS_ENOTDIR -TCM_ENOTDIR 
#endif
#ifdef EISDIR
    #define TCM_SYS_EISDIR EISDIR
#else
    #define TCM_SYS_EISDIR -TCM_EISDIR 
#endif
#ifdef EINVAL
    #define TCM_SYS_EINVAL EINVAL
#else
    #define TCM_SYS_EINVAL -TCM_EINVAL 
#endif
#ifdef ENFILE
    #define TCM_SYS_ENFILE ENFILE
#else
    #define TCM_SYS_ENFILE -TCM_ENFILE 
#endif
#ifdef EMFILE
    #define TCM_SYS_EMFILE EMFILE
#else
    #define TCM_SYS_EMFILE -TCM_EMFILE 
#endif
#ifdef ENOTTY
    #define TCM_SYS_ENOTTY ENOTTY
#else
    #define TCM_SYS_ENOTTY -TCM_ENOTTY 
#endif
#ifdef ETXTBSY
    #define TCM_SYS_ETXTBSY ETXTBSY
#else
    #define TCM_SYS_ETXTBSY -TCM_ETXTBSY 
#endif
#ifdef EFBIG
    #define TCM_SYS_EFBIG EFBIG
#else
    #define TCM_SYS_EFBIG -TCM_EFBIG 
#endif
#ifdef ENOSPC
    #define TCM_SYS_ENOSPC ENOSPC
#else
    #define TCM_SYS_ENOSPC -TCM_ENOSPC 
#endif
#ifdef ESPIPE
    #define TCM_SYS_ESPIPE ESPIPE
#else
    #define TCM_SYS_ESPIPE -TCM_ESPIPE 
#endif
#ifdef EROFS
    #define TCM_SYS_EROFS EROFS
#else
    #define TCM_SYS_EROFS -TCM_EROFS 
#endif
#ifdef EMLINK
    #define TCM_SYS_EMLINK EMLINK
#else
    #define TCM_SYS_EMLINK -TCM_EMLINK 
#endif
#ifdef EPIPE
    #define TCM_SYS_EPIPE EPIPE
#else
    #define TCM_SYS_EPIPE -TCM_EPIPE 
#endif
#ifdef EDOM
    #define TCM_SYS_EDOM EDOM
#else
    #define TCM_SYS_EDOM -TCM_EDOM 
#endif
#ifdef ERANGE
    #define TCM_SYS_ERANGE ERANGE
#else
    #define TCM_SYS_ERANGE -TCM_ERANGE 
#endif
#ifdef EAGAIN
    #define TCM_SYS_EAGAIN EAGAIN
#else
    #define TCM_SYS_EAGAIN -TCM_EAGAIN 
#endif
#ifdef EWOULDBLOCK
    #define TCM_SYS_EWOULDBLOCK EWOULDBLOCK
#else
    #define TCM_SYS_EWOULDBLOCK -TCM_EWOULDBLOCK 
#endif
#ifdef EAGAIN
    #define TCM_SYS_EAGAIN EAGAIN
#else
    #define TCM_SYS_EAGAIN -TCM_EAGAIN 
#endif
#ifdef EINPROGRESS
    #define TCM_SYS_EINPROGRESS EINPROGRESS
#else
    #define TCM_SYS_EINPROGRESS -TCM_EINPROGRESS 
#endif
#ifdef EALREADY
    #define TCM_SYS_EALREADY EALREADY
#else
    #define TCM_SYS_EALREADY -TCM_EALREADY 
#endif
#ifdef ENOTSOCK
    #define TCM_SYS_ENOTSOCK ENOTSOCK
#else
    #define TCM_SYS_ENOTSOCK -TCM_ENOTSOCK 
#endif
#ifdef EDESTADDRREQ
    #define TCM_SYS_EDESTADDRREQ EDESTADDRREQ
#else
    #define TCM_SYS_EDESTADDRREQ -TCM_EDESTADDRREQ 
#endif
#ifdef EMSGSIZE
    #define TCM_SYS_EMSGSIZE EMSGSIZE
#else
    #define TCM_SYS_EMSGSIZE -TCM_EMSGSIZE 
#endif
#ifdef EPROTOTYPE
    #define TCM_SYS_EPROTOTYPE EPROTOTYPE
#else
    #define TCM_SYS_EPROTOTYPE -TCM_EPROTOTYPE 
#endif
#ifdef ENOPROTOOPT
    #define TCM_SYS_ENOPROTOOPT ENOPROTOOPT
#else
    #define TCM_SYS_ENOPROTOOPT -TCM_ENOPROTOOPT 
#endif
#ifdef EPROTONOSUPPORT
    #define TCM_SYS_EPROTONOSUPPORT EPROTONOSUPPORT
#else
    #define TCM_SYS_EPROTONOSUPPORT -TCM_EPROTONOSUPPORT 
#endif
#ifdef ESOCKTNOSUPPORT
    #define TCM_SYS_ESOCKTNOSUPPORT ESOCKTNOSUPPORT
#else
    #define TCM_SYS_ESOCKTNOSUPPORT -TCM_ESOCKTNOSUPPORT 
#endif
#ifdef EOPNOTSUPP
    #define TCM_SYS_EOPNOTSUPP EOPNOTSUPP
#else
    #define TCM_SYS_EOPNOTSUPP -TCM_EOPNOTSUPP 
#endif
#ifdef ENOTSUP
    #define TCM_SYS_ENOTSUP ENOTSUP
#else
    #define TCM_SYS_ENOTSUP -TCM_ENOTSUP 
#endif
#ifdef EOPNOTSUPP
    #define TCM_SYS_EOPNOTSUPP EOPNOTSUPP
#else
    #define TCM_SYS_EOPNOTSUPP -TCM_EOPNOTSUPP 
#endif
#ifdef EPFNOSUPPORT
    #define TCM_SYS_EPFNOSUPPORT EPFNOSUPPORT
#else
    #define TCM_SYS_EPFNOSUPPORT -TCM_EPFNOSUPPORT 
#endif
#ifdef EAFNOSUPPORT
    #define TCM_SYS_EAFNOSUPPORT EAFNOSUPPORT
#else
    #define TCM_SYS_EAFNOSUPPORT -TCM_EAFNOSUPPORT 
#endif
#ifdef EADDRINUSE
    #define TCM_SYS_EADDRINUSE EADDRINUSE
#else
    #define TCM_SYS_EADDRINUSE -TCM_EADDRINUSE 
#endif
#ifdef EADDRNOTAVAIL
    #define TCM_SYS_EADDRNOTAVAIL EADDRNOTAVAIL
#else
    #define TCM_SYS_EADDRNOTAVAIL -TCM_EADDRNOTAVAIL 
#endif
#ifdef ENETDOWN
    #define TCM_SYS_ENETDOWN ENETDOWN
#else
    #define TCM_SYS_ENETDOWN -TCM_ENETDOWN 
#endif
#ifdef ENETUNREACH
    #define TCM_SYS_ENETUNREACH ENETUNREACH
#else
    #define TCM_SYS_ENETUNREACH -TCM_ENETUNREACH 
#endif
#ifdef ENETRESET
    #define TCM_SYS_ENETRESET ENETRESET
#else
    #define TCM_SYS_ENETRESET -TCM_ENETRESET 
#endif
#ifdef ECONNABORTED
    #define TCM_SYS_ECONNABORTED ECONNABORTED
#else
    #define TCM_SYS_ECONNABORTED -TCM_ECONNABORTED 
#endif
#ifdef ECONNRESET
    #define TCM_SYS_ECONNRESET ECONNRESET
#else
    #define TCM_SYS_ECONNRESET -TCM_ECONNRESET 
#endif
#ifdef ENOBUFS
    #define TCM_SYS_ENOBUFS ENOBUFS
#else
    #define TCM_SYS_ENOBUFS -TCM_ENOBUFS 
#endif
#ifdef EISCONN
    #define TCM_SYS_EISCONN EISCONN
#else
    #define TCM_SYS_EISCONN -TCM_EISCONN 
#endif
#ifdef ENOTCONN
    #define TCM_SYS_ENOTCONN ENOTCONN
#else
    #define TCM_SYS_ENOTCONN -TCM_ENOTCONN 
#endif
#ifdef ESHUTDOWN
    #define TCM_SYS_ESHUTDOWN ESHUTDOWN
#else
    #define TCM_SYS_ESHUTDOWN -TCM_ESHUTDOWN 
#endif
#ifdef ETOOMANYREFS
    #define TCM_SYS_ETOOMANYREFS ETOOMANYREFS
#else
    #define TCM_SYS_ETOOMANYREFS -TCM_ETOOMANYREFS 
#endif
#ifdef ETIMEDOUT
    #define TCM_SYS_ETIMEDOUT ETIMEDOUT
#else
    #define TCM_SYS_ETIMEDOUT -TCM_ETIMEDOUT 
#endif
#ifdef ECONNREFUSED
    #define TCM_SYS_ECONNREFUSED ECONNREFUSED
#else
    #define TCM_SYS_ECONNREFUSED -TCM_ECONNREFUSED 
#endif
#ifdef ELOOP
    #define TCM_SYS_ELOOP ELOOP
#else
    #define TCM_SYS_ELOOP -TCM_ELOOP 
#endif
#ifdef ENAMETOOLONG
    #define TCM_SYS_ENAMETOOLONG ENAMETOOLONG
#else
    #define TCM_SYS_ENAMETOOLONG -TCM_ENAMETOOLONG 
#endif
#ifdef EHOSTDOWN
    #define TCM_SYS_EHOSTDOWN EHOSTDOWN
#else
    #define TCM_SYS_EHOSTDOWN -TCM_EHOSTDOWN 
#endif
#ifdef EHOSTUNREACH
    #define TCM_SYS_EHOSTUNREACH EHOSTUNREACH
#else
    #define TCM_SYS_EHOSTUNREACH -TCM_EHOSTUNREACH 
#endif
#ifdef ENOTEMPTY
    #define TCM_SYS_ENOTEMPTY ENOTEMPTY
#else
    #define TCM_SYS_ENOTEMPTY -TCM_ENOTEMPTY 
#endif
#ifdef EPROCLIM
    #define TCM_SYS_EPROCLIM EPROCLIM
#else
    #define TCM_SYS_EPROCLIM -TCM_EPROCLIM 
#endif
#ifdef EUSERS
    #define TCM_SYS_EUSERS EUSERS
#else
    #define TCM_SYS_EUSERS -TCM_EUSERS 
#endif
#ifdef EDQUOT
    #define TCM_SYS_EDQUOT EDQUOT
#else
    #define TCM_SYS_EDQUOT -TCM_EDQUOT 
#endif
#ifdef ESTALE
    #define TCM_SYS_ESTALE ESTALE
#else
    #define TCM_SYS_ESTALE -TCM_ESTALE 
#endif
#ifdef EREMOTE
    #define TCM_SYS_EREMOTE EREMOTE
#else
    #define TCM_SYS_EREMOTE -TCM_EREMOTE 
#endif
#ifdef EBADRPC
    #define TCM_SYS_EBADRPC EBADRPC
#else
    #define TCM_SYS_EBADRPC -TCM_EBADRPC 
#endif
#ifdef ERPCMISMATCH
    #define TCM_SYS_ERPCMISMATCH ERPCMISMATCH
#else
    #define TCM_SYS_ERPCMISMATCH -TCM_ERPCMISMATCH 
#endif
#ifdef EPROGUNAVAIL
    #define TCM_SYS_EPROGUNAVAIL EPROGUNAVAIL
#else
    #define TCM_SYS_EPROGUNAVAIL -TCM_EPROGUNAVAIL 
#endif
#ifdef EPROGMISMATCH
    #define TCM_SYS_EPROGMISMATCH EPROGMISMATCH
#else
    #define TCM_SYS_EPROGMISMATCH -TCM_EPROGMISMATCH 
#endif
#ifdef EPROCUNAVAIL
    #define TCM_SYS_EPROCUNAVAIL EPROCUNAVAIL
#else
    #define TCM_SYS_EPROCUNAVAIL -TCM_EPROCUNAVAIL 
#endif
#ifdef ENOLCK
    #define TCM_SYS_ENOLCK ENOLCK
#else
    #define TCM_SYS_ENOLCK -TCM_ENOLCK 
#endif
#ifdef ENOSYS
    #define TCM_SYS_ENOSYS ENOSYS
#else
    #define TCM_SYS_ENOSYS -TCM_ENOSYS 
#endif
#ifdef EFTYPE
    #define TCM_SYS_EFTYPE EFTYPE
#else
    #define TCM_SYS_EFTYPE -TCM_EFTYPE 
#endif
#ifdef EAUTH
    #define TCM_SYS_EAUTH EAUTH
#else
    #define TCM_SYS_EAUTH -TCM_EAUTH 
#endif
#ifdef ENEEDAUTH
    #define TCM_SYS_ENEEDAUTH ENEEDAUTH
#else
    #define TCM_SYS_ENEEDAUTH -TCM_ENEEDAUTH 
#endif
#ifdef EIDRM
    #define TCM_SYS_EIDRM EIDRM
#else
    #define TCM_SYS_EIDRM -TCM_EIDRM 
#endif
#ifdef ENOMSG
    #define TCM_SYS_ENOMSG ENOMSG
#else
    #define TCM_SYS_ENOMSG -TCM_ENOMSG 
#endif
#ifdef EOVERFLOW
    #define TCM_SYS_EOVERFLOW EOVERFLOW
#else
    #define TCM_SYS_EOVERFLOW -TCM_EOVERFLOW 
#endif
#ifdef ECANCELED
    #define TCM_SYS_ECANCELED ECANCELED
#else
    #define TCM_SYS_ECANCELED -TCM_ECANCELED 
#endif
#ifdef EILSEQ
    #define TCM_SYS_EILSEQ EILSEQ
#else
    #define TCM_SYS_EILSEQ -TCM_EILSEQ 
#endif
#ifdef ENOATTR
    #define TCM_SYS_ENOATTR ENOATTR
#else
    #define TCM_SYS_ENOATTR -TCM_ENOATTR 
#endif
#ifdef EDOOFUS
    #define TCM_SYS_EDOOFUS EDOOFUS
#else
    #define TCM_SYS_EDOOFUS -TCM_EDOOFUS 
#endif
#ifdef EBADMSG
    #define TCM_SYS_EBADMSG EBADMSG
#else
    #define TCM_SYS_EBADMSG -TCM_EBADMSG 
#endif
#ifdef EMULTIHOP
    #define TCM_SYS_EMULTIHOP EMULTIHOP
#else
    #define TCM_SYS_EMULTIHOP -TCM_EMULTIHOP 
#endif
#ifdef ENOLINK
    #define TCM_SYS_ENOLINK ENOLINK
#else
    #define TCM_SYS_ENOLINK -TCM_ENOLINK 
#endif
#ifdef EPROTO
    #define TCM_SYS_EPROTO EPROTO
#else
    #define TCM_SYS_EPROTO -TCM_EPROTO 
#endif
#ifdef ENOTCAPABLE
    #define TCM_SYS_ENOTCAPABLE ENOTCAPABLE
#else
    #define TCM_SYS_ENOTCAPABLE -TCM_ENOTCAPABLE 
#endif
#ifdef ECAPMODE
    #define TCM_SYS_ECAPMODE ECAPMODE
#else
    #define TCM_SYS_ECAPMODE -TCM_ECAPMODE 
#endif
#ifdef ENOTRECOVERABLE
    #define TCM_SYS_ENOTRECOVERABLE ENOTRECOVERABLE
#else
    #define TCM_SYS_ENOTRECOVERABLE -TCM_ENOTRECOVERABLE 
#endif
#ifdef EOWNERDEAD
    #define TCM_SYS_EOWNERDEAD EOWNERDEAD
#else
    #define TCM_SYS_EOWNERDEAD -TCM_EOWNERDEAD 
#endif
#ifdef EINTEGRITY
    #define TCM_SYS_EINTEGRITY EINTEGRITY
#else
    #define TCM_SYS_EINTEGRITY -TCM_EINTEGRITY 
#endif

#endif