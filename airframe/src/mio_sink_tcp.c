/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_sink_tcp.c
 *  Multiple I/O active TCP stream sink
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

#define _AIRFRAME_SOURCE_
#include <airframe/mio_sink_tcp.h>
#include "mio_common_net.h"

gboolean
mio_sink_init_tcp(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    char    *splitspec = NULL, *hostaddr = NULL, *svcaddr = NULL;
    gboolean ok = TRUE;

    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_SOCK_STREAM;}

    /* initialize UDP sink */
    sink->spec = g_strdup(spec);
    sink->name = NULL;
    sink->vsp_type = vsp_type;
    sink->vsp = NULL;
    sink->ctx = NULL;
    sink->cfg = cfg;
    sink->next_sink = mio_sink_next_common_net;
    sink->close_sink = mio_sink_close_common_net;
    sink->free_sink = mio_sink_free_common_net;
    sink->opened = FALSE;
    sink->active = FALSE;
    sink->iterative = FALSE;

    /* Ensure type is valid */
    if (vsp_type != MIO_T_SOCK_STREAM) {
        ok = FALSE;
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot create TCP sink: type mismatch");
        goto end;
    }

    /* Parse specifier */
    splitspec = spec ? g_strdup(spec) : NULL;
    mio_init_ip_splitspec(splitspec, FALSE, (char *)cfg,
                          &hostaddr, &svcaddr, &(sink->name));

    /* Check for no host */
    if (!hostaddr) {
        ok = FALSE;
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot create TCP sink: no output specifier");
        goto end;
    }

    /* Do lookup and create context */
    if (!(sink->ctx = mio_init_ip_lookup(hostaddr, svcaddr, SOCK_STREAM,
                                         IPPROTO_TCP, FALSE, err)))
    {
        ok = FALSE;
        goto end;
    }

  end:
    if (splitspec) {g_free(splitspec);}
    return ok;
}
