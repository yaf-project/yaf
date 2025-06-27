/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_source_udp.c
 *  Multiple I/O passive UDP datagram source
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
 * @file
 *
 * MIO passive UDP socket source initializer. Most applications should use the
 * interface in mio_config.h to access this initializer.
 */

/* idem hack */
#ifndef _AIRFRAME_MIO_SOURCE_UDP_H_
#define _AIRFRAME_MIO_SOURCE_UDP_H_
#include <airframe/mio.h>

/**
 * Initialize a source for reading datagrams from a passive UDP socket.
 *
 * @param source    pointer to MIOSource to initialize. This MIOSource will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSource with.
 *                  Must be a service specifier of the form "[host,]service"
 *                  where host is the IPv4 or IPv6 name or address of an
 *                  interface to bind to, or * to bind to all interfaces, and
 *                  service is a service name or UDP port number to bind to.
 *                  If omitted, host is assumed to be *. If spec is NULL,
 *                  host is assumed to be * and service is taken from the
 *                  cfg paramater.
 * @param vsp_type  requested source pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  Must be a pointer to a string with the default service
 *                  name or integer port number.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSource was successfully initialized.
 */
gboolean
mio_source_init_udp(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

#endif /* ifndef _AIRFRAME_MIO_SOURCE_UDP_H_ */
