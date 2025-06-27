/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_source_tcp.c
 *  Multiple I/O passive TCP stream source
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
 * MIO passive TCP socket source initializer. Most applications should use the
 * interface in mio_config.h to access this initializer.
 */

/* idem hack */
#ifndef _AIRFRAME_MIO_SOURCE_TCP_H_
#define _AIRFRAME_MIO_SOURCE_TCP_H_
#include <airframe/mio.h>

/**
 * TCP source configuration context. Pass as the cfg argument to
 * mio_source_init_tcp().
 */

typedef struct _MIOSourceTCPConfig {
    /** String containing default service name or integer TCP port number. */
    char            *default_port;
    /**
     * select(2) timeout used by next_source; next_source will wait no longer
     * than this before failing and setting MIO_F_CTL_POLL to allow
     * applications to do work or to detect termination while awaiting a
     * connection.
     */
    struct timeval   timeout;
} MIOSourceTCPConfig;

/**
 * Initialize a source for reading from a passive TCP socket.
 * This source supports single-threaded, sequential access only; clients
 * connecting to an application using this source may be refused connection
 * while the application is servicing a previously connected client.
 *
 * @param source    pointer to MIOSource to initialize. This MIOSource will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSource with.
 *                  Must be a service specifier of the form "[host,]service"
 *                  where host is the IPv4 or IPv6 name or address of an
 *                  interface to bind to, or * to bind to all interfaces, and
 *                  service is a service name or TCP port number to bind to.
 *                  If omitted, host is assumed to be *. If spec is NULL,
 *                  host is assumed to be * and service is taken from the
 *                  cfg paramater.
 * @param vsp_type  requested source pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  Must be a pointer to an MIOSourceTCPConfig structure.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSource was successfully initialized.
 */
gboolean
mio_source_init_tcp(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

#endif /* ifndef _AIRFRAME_MIO_SOURCE_TCP_H_ */
