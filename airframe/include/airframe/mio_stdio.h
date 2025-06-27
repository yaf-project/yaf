/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_stdio.c
 *  Multiple I/O standard in source / standard out sink
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
 * MIO standard input/output initializers. Most applications should use the
 * interface in mio_config.h to access these initializers.
 */

/* idem hack */
#ifndef _AIRFRAME_MIO_STDIO_H_
#define _AIRFRAME_MIO_STDIO_H_
#include <airframe/mio.h>

/**
 * Initialize a standard input source.
 *
 * @param source    pointer to MIOSource to initialize. This MIOSource will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSource with.
 *                  Only "-" is acceptable for standard input sources.
 * @param vsp_type  requested source pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  This source uses no configuration context; pass NULL.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSource was successfully initialized.
 */
gboolean
mio_source_init_stdin(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

/**
 * Initialize a standard output sink.
 *
 * @param sink      pointer to MIOSink to initialize. This MIOSink will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSink with.
 *                  Only "-" is acceptable for standard output sinks.
 * @param vsp_type  requested sink pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  This source uses no configuration context; pass NULL.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSink was successfully initialized.
 */
gboolean
mio_sink_init_stdout(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

#endif /* ifndef _AIRFRAME_MIO_STDIO_H_ */
