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

/**
 *  @file
 *  Convenience include file for libairframe.
 */

#ifndef _AIR_AUTOINC_H_
#define _AIR_AUTOINC_H_

#ifdef _AIRFRAME_SOURCE_
#ifdef  HAVE_CONFIG_H
#  include "config.h"
#endif
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
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
#if     HAVE_UNISTD_H
#  include <unistd.h>
#endif
#if     HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif

#if     HAVE_FCNTL_H
#  include <fcntl.h>
#endif
#if     HAVE_NETDB_H
#  include <netdb.h>
#endif
#if     HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#if     HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#if     HAVE_SYSLOG_H
#  include <syslog.h>
#endif
#if     HAVE_GLOB_H
#  include <glob.h>
#endif
#if     HAVE_DIRENT_H
#  include <dirent.h>
#endif
#if     HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif
#if     HAVE_PWD_H
#  include <pwd.h>
#endif
#if     HAVE_GRP_H
#  include <grp.h>
#endif
#if     WITH_DMALLOC
#  include <dmalloc.h>
#endif

#include <glib.h>
#include <pcap.h>

#endif /* ifndef _AIR_AUTOINC_H_ */
