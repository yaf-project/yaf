/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_sink_file.h
 *  Multiple I/O regular file sink, by pattern.
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
 * MIO file sink initializers. Most applications should use the
 * interface in mio_config.h to access these initializers.
 */

/* idem hack */
#ifndef _AIRFRAME_MIO_SINK_FILE_H_
#define _AIRFRAME_MIO_SINK_FILE_H_
#include <airframe/mio.h>

/**
 * File sink configuration context. Pass as the cfg argument to any file
 * sink initializer.
 */
typedef struct _MIOSinkFileConfig {
    /**
     * Next serial number to assign to %S or %X pattern variable.
     * Modified by sinks initialized by mio_sink_init_file_pattern().
     */
    uint32_t   next_serial;
} MIOSinkFileConfig;

/**
 * Initialize a file sink for writing to a single file. Fails over to
 * mio_sink_init_stdout() if specifier is the special string "-".
 *
 * @param sink      pointer to MIOSink to initialize. This MIOSink will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSink with.
 *                  Must be a filename.
 * @param vsp_type  requested sink pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  Must be a pointer to an MIOSinkFileConfig.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSink was successfully initialized.
 */
gboolean
mio_sink_init_file_single(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

/**
 * Initialize a file sink for writing to a multiple files based upon a
 * pattern. Fails over to mio_sink_file_single() if specifier does not have
 * any pattern variables.
 *
 * The following pattern variables are supported:
 *
 * - %T timestamp at sink open in YYYYMMDDHHMMSS format
 * - %S serial number (from cfg) in decimal
 * - %X serial number (from cfg) in hex
 * - %d dirname of source active at sink open
 * - %s basename of source active at sink open
 * - %e extension of source active at sink open
 *
 * @param sink      pointer to MIOSink to initialize. This MIOSink will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSink with.
 *                  Must be a filename.
 * @param vsp_type  requested sink pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  Must be a pointer to an MIOSinkFileConfig.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSink was successfully initialized.
 */
gboolean
mio_sink_init_file_pattern(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

#endif /* ifndef _AIRFRAME_MIO_SINK_FILE_H_ */
