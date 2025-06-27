/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_common_net.h
 *  Multiple I/O network source/sink common support and addrinfo glue
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

/* idem hack */
#ifndef _AIRFRAME_MIO_COMMON_NET_H_
#define _AIRFRAME_MIO_COMMON_NET_H_
#include <airframe/mio.h>

#ifndef HAVE_GETADDRINFO
struct addrinfo {
    int               ai_family;    /* protocol family for socket */
    int               ai_socktype;  /* socket type */
    int               ai_protocol;  /* protocol for socket */
    socklen_t         ai_addrlen;   /* length of socket-address */
    struct sockaddr  *ai_addr;      /* socket-address for socket */
    struct addrinfo  *ai_next;      /* pointer to next in list */
};
#endif /* ifndef HAVE_GETADDRINFO */

void
mio_freeaddrinfo(
    struct addrinfo  *ai);

struct addrinfo *
mio_init_ip_lookup(
    char      *hostaddr,
    char      *svcaddr,
    int        socktype,
    int        protocol,
    gboolean   passive,
    GError   **err);

void
mio_init_ip_splitspec(
    char      *spec,
    gboolean   passive,
    char      *default_port,
    char     **hostaddr,
    char     **svcaddr,
    char     **srcname);

gboolean
mio_sink_next_common_net(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err);

gboolean
mio_sink_close_common_net(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err);

void
mio_sink_free_common_net(
    MIOSink  *sink);

#endif /* ifndef _AIRFRAME_MIO_COMMON_NET_H_ */
