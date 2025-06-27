/*
 *  Copyright 2005-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  autoinc.h
 *  Autotools-happy standard library include file
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.16
 *
 *  Copyright 2024 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM24-1063
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

/** @file
 *  Convenience include file for libyaf.
 */

#ifndef _YAF_AUTOINC_H_
#define _YAF_AUTOINC_H_

#ifdef _YAF_SOURCE_
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>

#if     HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if     HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#if     HAVE_STDINT_H
#  include <stdint.h>
#endif
#if     HAVE_ERRNO_H
#  include <errno.h>
#endif
#if     HAVE_FCNTL_H
#  include <fcntl.h>
#endif
#if     HAVE_GLOB_H
#  include <glob.h>
#endif
#if    HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif

#include <pcap.h>
#include <glib.h>


/* link layer header types */
#ifndef DLT_JUNIPER_ETHER
#define DLT_JUNIPER_ETHER  178
#endif

/** the following PRI* macros code was taken from
 * silk_config.h */
/** PRI* macros for printing */
#if !defined(PRIu32)
/* Assume we either get them all or get none of them. */
#  define PRId32 "d"
#  define PRIi32 "i"
#  define PRIo32 "o"
#  define PRIu32 "u"
#  define PRIx32 "x"
#  define PRIX32 "X"

#  define PRId16 PRId32
#  define PRIi16 PRIi32
#  define PRIo16 PRIo32
#  define PRIu16 PRIu32
#  define PRIx16 PRIx32
#  define PRIX16 PRIX32

#  define PRId8  PRId32
#  define PRIi8  PRIi32
#  define PRIo8  PRIo32
#  define PRIu8  PRIu32
#  define PRIx8  PRIx32
#  define PRIX8  PRIX32
#endif /* !defined(PRIU32) */
#if !defined(PRIu64)
#  if (SIZEOF_LONG >= 8)
#    define PRId64 "l" PRId32
#    define PRIi64 "l" PRIi32
#    define PRIo64 "l" PRIo32
#    define PRIu64 "l" PRIu32
#    define PRIx64 "l" PRIx32
#    define PRIX64 "l" PRIX32
#  else /* if (SIZEOF_LONG >= 8) */
#    define PRId64 "ll" PRId32
#    define PRIi64 "ll" PRIi32
#    define PRIo64 "ll" PRIo32
#    define PRIu64 "ll" PRIu32
#    define PRIx64 "ll" PRIx32
#    define PRIX64 "ll" PRIX32
#  endif /* if (SIZEOF_LONG >= 8) */
#endif /* !defined(PRIu64) */


#ifdef __CYGWIN__
const char *
yfGetCygwinConfDir(
    void);
#endif /* ifdef __CYGWIN__ */

#endif /* ifndef _YAF_AUTOINC_H_ */
