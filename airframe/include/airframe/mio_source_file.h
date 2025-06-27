/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_source_file.h
 *  Multiple I/O regular file source, from single file, glob, or directory.
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
 * MIO file source initializers. Most applications should use the
 * interface in mio_config.h to access these initializers.
 */

/* idem hack */
#ifndef _AIRFRAME_MIO_SOURCE_FILE_H_
#define _AIRFRAME_MIO_SOURCE_FILE_H_
#include <airframe/mio.h>

/**
 * File source configuration context. Pass as the cfg argument to any file
 * source initializer.
 */
typedef struct _MIOSourceFileConfig {
    /** Next directory path. NULL to leave input where it is, "" to delete. */
    char  *nextdir;
    /** Fail directory path. NULL to leave input where it is, "" to delete. */
    char  *faildir;
} MIOSourceFileConfig;

/**
 * Initialize a file source for reading every file from a specified directory.
 *
 * @param source    pointer to MIOSource to initialize. This MIOSource will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSource with.
 *                  Must be the pathname of an accessible directory.
 * @param vsp_type  requested source pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  Must be a pointer to an MIOSourceFileConfig structure.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSource was successfully initialized.
 */
gboolean
mio_source_init_file_dir(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

/**
 * Initialize a file source for reading every file from a specified glob(3)
 * expression. Fails over to mio_source_init_file_single() if the specifier
 * contains no glob expression characters.
 *
 * @param source    pointer to MIOSource to initialize. This MIOSource will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSource with.
 *                  Must be a glob expression.
 * @param vsp_type  requested source pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  Must be a pointer to an MIOSourceFileConfig structure.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSource was successfully initialized.
 */
gboolean
mio_source_init_file_glob(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

/**
 * Initialize a file source for a single file. Fails over to
 * mio_source_init_stdin() if specifier is the special string "-".
 *
 * @param source    pointer to MIOSource to initialize. This MIOSource will
 *                  be overwritten.
 * @param spec      input specifier to initialize MIOSource with.
 *                  Must be a filename.
 * @param vsp_type  requested source pointer type, or MIO_T_ANY for default.
 * @param cfg       pointer to configuration context.
 *                  Must be a pointer to an MIOSourceFileConfig structure.
 * @param err       An error description pointer.
 * @return TRUE if the MIOSource was successfully initialized.
 */
gboolean
mio_source_init_file_single(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err);

#endif /* ifndef _AIRFRAME_MIO_SOURCE_FILE_H_ */
