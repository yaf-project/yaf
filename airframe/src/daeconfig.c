/*
 *  Copyright 2005-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  daeconfig.c
 *  Generic daemon configuration support
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
#include <airframe/daeconfig.h>
#include <airframe/airopt.h>

static gboolean opt_daemon = FALSE;
static gboolean opt_fg = FALSE;

static gboolean did_fork = FALSE;

static gboolean daemon_quit = FALSE;

static AirOptionEntry  daec_optentries[] = {
    AF_OPTION( "daemon", 'd', 0, AF_OPT_TYPE_NONE, &opt_daemon,
               "Become daemon", NULL ),
    AF_OPTION( "foreground", (char)0, 0, AF_OPT_TYPE_NONE, &opt_fg,
               "Do not fork to background in daemon mode", NULL ),
    AF_OPTION_END
};

gboolean
daec_add_option_group(
    AirOptionCtx  *aoctx)
{
    g_assert(aoctx != NULL);

    air_option_context_add_group(aoctx, "daemon", "Daemon options:",
                                 "Show help for daemon options",
                                 daec_optentries);

    return TRUE;
}


gboolean
daec_is_daemon(
    void)
{
    return opt_daemon;
}


gboolean
daec_did_fork(
    void)
{
    return did_fork;
}


gboolean
daec_will_fork(
    void)
{
    return opt_daemon ? (opt_fg ? 0 : 1) : 0;
}


void
daec_quit(
    void)
{
    ++daemon_quit;
}

static void
sighandler_daec_quit(
    int   sig)
{
    (void)sig;
    daec_quit();
}

gboolean
daec_did_quit(
    void)
{
    return daemon_quit;
}


gboolean
daec_setup(
    GError **err)
{
    struct sigaction sa, osa;

    /* fork if necessary */
    if (daec_will_fork()) {
        /* fork */
        if (fork()) {exit(0);}

        /* dissociate from controlling terminal */
        if (setsid() < 0) {
            g_set_error(err, DAEC_ERROR_DOMAIN, DAEC_ERROR_SETUP,
                        "setsid() failed: %s", strerror(errno));
            return FALSE;
        }

        /* redirect stdio */
        if (NULL == freopen("/dev/null", "r", stdin)) {
            g_critical("freopen(stdin) failed: %s", strerror(errno));
            return FALSE;
        }
        if (NULL == freopen("/dev/null", "w", stdout)) {
            g_critical("freopen(stdout) failed: %s", strerror(errno));
            return FALSE;
        }
        if (NULL == freopen("/dev/null", "w", stderr)) {
            g_critical("freopen(stderr) failed: %s", strerror(errno));
            return FALSE;
        }

        /* we forked */
        did_fork = TRUE;
    }

    /* install quit flag handlers */
    sa.sa_handler = sighandler_daec_quit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, &osa)) {
        g_set_error(err, DAEC_ERROR_DOMAIN, DAEC_ERROR_SETUP,
                    "sigaction(SIGINT) failed: %s", strerror(errno));
        return FALSE;
    }

    sa.sa_handler = sighandler_daec_quit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, &osa)) {
        g_set_error(err, DAEC_ERROR_DOMAIN, DAEC_ERROR_SETUP,
                    "sigaction(SIGTERM) failed: %s", strerror(errno));
        return FALSE;
    }

    return TRUE;
}
