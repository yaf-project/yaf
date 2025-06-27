/*
 *  Copyright 2005-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  airlock.c
 *  Airframe lockfile interface
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
 * Airframe lockfile interface. Used to acquire lockfiles compatible with
 * the Airframe filedaemon.
 */

/* idem hack */
#ifndef _AIR_AIRLOCK_H_
#define _AIR_AIRLOCK_H_

#include <airframe/autoinc.h>

/** GError domain for lock errors */
#define LOCK_ERROR_DOMAIN g_quark_from_string("airframeLockError")
/**
 * A lock could not be acquired.
 */
#define LOCK_ERROR_LOCK  1

/**
 * A lock structure. Must be maintained by a caller from lock acquisition
 * to release. Should be initialized by AIR_LOCK_INIT or memset(0) or bzero().
 */
typedef struct _AirLock {
    /** Path to .lock file */
    GString   *lpath;
    /** File descriptor of open .lock file */
    int        lfd;
    /** TRUE if this lock is held, and lpath and lfd are valid. */
    gboolean   held;
} AirLock;

/** Convenience initializer for AirLock structures */
#define AIR_LOCK_INIT { NULL, 0, FALSE }

/**
 * Acquire a lock. Creates a lockfile and returns TRUE if the lockfile was
 * created (and is now held).
 *
 * @param lock AirLock structure to store lockfile information in.
 * @param path path of file to lock (without .lock extension).
 * @param err an error descriptor
 * @return TRUE if lockfile created, FALSE if lock not available
 */
gboolean
air_lock_acquire(
    AirLock     *lock,
    const char  *path,
    GError     **err);

/**
 * Release an acquired lock.
 *
 * @param lock AirLock structure filled in by air_lock_acquire()
 */
void
air_lock_release(
    AirLock  *lock);

/**
 * Free storage used by an AirLock structure. Does not free the structure
 * itself.
 *
 * @param lock AirLock to free
 */
void
air_lock_cleanup(
    AirLock  *lock);

#endif /* ifndef _AIR_AIRLOCK_H_ */
