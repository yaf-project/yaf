/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_config.c
 *  Multiple I/O common command-line processing convenience module
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
#include <airframe/airopt.h>
#include <airframe/mio_config.h>
#include <airframe/mio_stdio.h>
#include <airframe/mio_source_file.h>
#include <airframe/mio_source_udp.h>
#include <airframe/mio_source_tcp.h>
#include <airframe/mio_source_pcap.h>
#include <airframe/mio_sink_file.h>
#include <airframe/mio_sink_udp.h>
#include <airframe/mio_sink_tcp.h>
#include <airframe/mio_sink_multi.h>
#include <airframe/daeconfig.h>

/* Convenience flags */
#define MIO_F_CLI_FILEROUTER    (MIO_F_CLI_PCAP_IN | MIO_F_CLI_FILE_IN)
#define MIO_F_CLI_PCAP          MIO_F_CLI_PCAP_IN

/* wrap this around string literals that are assigned to variables of type
 * "char *" to quiet compiler warnings */
#define C(String) (char *)String


char    *mio_ov_in      = NULL;
char    *mio_ov_out     = NULL;
char    *mio_ov_nextdir = NULL;
char    *mio_ov_faildir = NULL;
int      mio_ov_poll     = 60;
gboolean mio_ov_lock     = FALSE;
gboolean mio_ov_live     = FALSE;
char    *mio_ov_bpf     = NULL;

uint32_t mio_ov_pcaplen  = 0;
uint32_t mio_ov_pcapto   = 1000;
char    *mio_ov_port    = NULL;
MIOType  mio_ov_filetype = MIO_T_FP;

static MIOSourceFileConfig mio_icfg_f;
static MIOSinkFileConfig   mio_ocfg_f;
static GString            *mio_ocfg_pat = NULL;
static MIOSourceTCPConfig  mio_icfg_tcp;

#if HAVE_LIBPCAP
static MIOSourcePCapFileConfig mio_icfg_pf;
static MIOSourcePCapLiveConfig mio_icfg_pl;
#endif

#if 1
static AirOptionEntry mio_oe_in[] = {
    AF_OPTION( "in", 'i', 0, AF_OPT_TYPE_STRING, &mio_ov_in,
               "Input specifier", "inspec" ),
    AF_OPTION_END
};
static AirOptionEntry mio_oe_out[] = {
    AF_OPTION( "out", 'o', 0, AF_OPT_TYPE_STRING, &mio_ov_out,
               "Output specifier", "outspec" ),
    AF_OPTION_END
};

static AirOptionEntry mio_oe_fr[] = {
    AF_OPTION( "nextdir", 'n', 0, AF_OPT_TYPE_STRING, &mio_ov_nextdir,
               "Directory to move good input to (or 'delete')", "dir" ),
    AF_OPTION( "faildir", 'x', 0, AF_OPT_TYPE_STRING, &mio_ov_faildir,
               "Directory to move failed input to (or 'delete')", "dir" ),
    AF_OPTION( "poll", 'p', 0, AF_OPT_TYPE_INT, &mio_ov_poll,
               "Polling delay in seconds", "sec" ),
    AF_OPTION( "lock", 'k', 0, AF_OPT_TYPE_NONE, &mio_ov_lock,
               "Use exclusive .lock files for concurrency", NULL ),
    AF_OPTION_END
};

#if HAVE_LIBPCAP
static AirOptionEntry mio_oe_pcap[] = {
    AF_OPTION( "live", 'P', 0, AF_OPT_TYPE_NONE, &mio_ov_live,
               "Live packet capture from interface in -i", NULL ),
    AF_OPTION( "bpf", 'F', 0, AF_OPT_TYPE_STRING, &mio_ov_bpf,
               "BPF filter expression for packets to capture", "bpf-expr" ),
    AF_OPTION_END
};
#endif /* if HAVE_LIBPCAP */

#else /* if 1 */
GOptionEntry mio_oe_in[] = {
    { "in", 'i', 0, G_OPTION_ARG_STRING, &mio_ov_in,
      "Input specifier", "inspec" },
    { NULL }
};

GOptionEntry mio_oe_out[] = {
    { "out", 'o', 0, G_OPTION_ARG_STRING, &mio_ov_out,
      "Output specifier", "outspec" },
    { NULL }
};

GOptionEntry mio_oe_fr[] = {
    { "nextdir", 'n', 0, G_OPTION_ARG_STRING, &mio_ov_nextdir,
      "Directory to move good input to (or 'delete')", "dir" },
    { "faildir", 'x', 0, G_OPTION_ARG_STRING, &mio_ov_faildir,
      "Directory to move failed input to (or 'delete')", "dir" },
    { "poll", 'p', 0, G_OPTION_ARG_INT, &mio_ov_poll,
      "Polling delay in seconds", "sec" },
    { "lock", 'k', 0, G_OPTION_ARG_NONE, &mio_ov_lock,
      "Use exclusive .lock files for concurrency", NULL },
    { NULL }
};

#if HAVE_LIBPCAP
GOptionEntry mio_oe_pcap[] = {
    { "live", 'P', 0, G_OPTION_ARG_NONE, &mio_ov_live,
      "Live packet capture from interface in -i", NULL },
    { "bpf", 'F', 0, G_OPTION_ARG_STRING, &mio_ov_bpf,
      "BPF filter expression for packets to capture", "bpf-expr" },
    { NULL }
};
#endif /* if HAVE_LIBPCAP */
#endif /* if 1 */

gboolean
mio_add_option_group(
    AirOptionCtx  *aoctx,
    uint32_t       cli_flags)
{
    GArray *entries = NULL;
    int     i;
    g_assert(aoctx != NULL);

    entries = g_array_sized_new(TRUE, TRUE, sizeof(AirOptionEntry), 64);

    /* add entries as appropriate */
    if (cli_flags & MIO_F_CLI_INMASK) {
        for (i = 0; !AF_OPTION_EMPTY(mio_oe_in[i]); i++) {
            g_array_append_val(entries, mio_oe_in[i] );
        }
    }
    if (cli_flags & MIO_F_CLI_OUTMASK) {
        for (i = 0; !AF_OPTION_EMPTY(mio_oe_out[i]); i++) {
            g_array_append_val(entries, mio_oe_out[i] );
        }
    }
    if (cli_flags & MIO_F_CLI_FILEROUTER) {
        for (i = 0; !AF_OPTION_EMPTY(mio_oe_fr[i]); i++) {
            g_array_append_val(entries, mio_oe_fr[i] );
        }
    }
#if HAVE_LIBPCAP
    if (cli_flags & MIO_F_CLI_PCAP) {
        for (i = 0; !AF_OPTION_EMPTY(mio_oe_fr[i]); i++) {
            g_array_append_val(entries, mio_oe_pcap[i] );
        }
    }
#endif /* if HAVE_LIBPCAP */
    air_option_context_add_group(aoctx, "io", "I/O Configuration:",
                                 "Show help for I/O Configuration options",
                                 (AirOptionEntry *)entries->data);
    return TRUE;
}


static gboolean
mio_config_filerouter(
    MIOSourceFileConfig  *cfg,
    uint32_t              miod_flags,
    GError              **err)
{
    if (mio_ov_nextdir && !strcmp(mio_ov_nextdir, "delete")) {
        mio_ov_nextdir = C("");
    }
    cfg->nextdir = mio_ov_nextdir;

    if (mio_ov_faildir && !strcmp(mio_ov_faildir, "delete")) {
        mio_ov_faildir = C("");
    }
    cfg->faildir = mio_ov_faildir;

    if (miod_flags & MIO_F_OPT_DAEMON) {
        if (!cfg->nextdir || !cfg->faildir) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                        "--daemon with file input requires "
                        "--nextdir and --faildir");
            return FALSE;
        }
    }

    return TRUE;
}


#define MIO_CFG_TRYINIT(_expr_)                                              \
    {                                                                        \
        g_clear_error(err);                                                  \
        if (_expr_) {                                                        \
            return TRUE;                                                     \
        } else if (!g_error_matches(*err,                                    \
                                    MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT)) { \
            return FALSE;                                                    \
        }                                                                    \
    }

#define MIO_CFG_TRYINIT2(_expr_, _postcfg_)                                  \
    {                                                                        \
        g_clear_error(err);                                                  \
        if (_expr_) {                                                        \
            _postcfg_                                                        \
            return TRUE;                                                     \
        } else if (!g_error_matches(*err,                                    \
                                    MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT)) { \
            return FALSE;                                                    \
        }                                                                    \
    }

gboolean
mio_config_source(
    MIOSource  *source,
    uint32_t    cli_flags,
    uint32_t   *miod_flags,
    GError    **err)
{
    /* Set MIO options flags */
    if (mio_ov_lock) {*miod_flags |= MIO_F_OPT_LOCK;}
    if (daec_is_daemon()) {*miod_flags |= MIO_F_OPT_DAEMON;}

    /* Default input specifier */
    if (!mio_ov_in) {
        if (cli_flags & MIO_F_CLI_DEF_STDIN) {
            mio_ov_in = C("-");
        }
    }

#if HAVE_LIBPCAP
    /* Handle packet capture case */
    if (cli_flags & MIO_F_CLI_PCAP_IN) {
        if (mio_ov_live) {
            mio_icfg_pl.snaplen = mio_ov_pcaplen;
            mio_icfg_pl.timeout = mio_ov_pcapto;
            mio_icfg_pl.filter = mio_ov_bpf;
            MIO_CFG_TRYINIT(mio_source_init_pcap_live(
                                source, mio_ov_in, MIO_T_PCAP, &mio_icfg_pl,
                                err));
        } else {
            mio_icfg_pf.filter = mio_ov_bpf;
            if (cli_flags & MIO_F_CLI_DIR_IN) {
                MIO_CFG_TRYINIT2(mio_source_init_pcap_dir(
                                     source, mio_ov_in, MIO_T_PCAP,
                                     &mio_icfg_pf, err), {
                    if (!mio_config_filerouter(&(mio_icfg_pf.filecfg),
                                               *miod_flags, err))
                    {
                        return FALSE;
                    }
                });
            }
            MIO_CFG_TRYINIT2(mio_source_init_pcap_glob(
                                 source, mio_ov_in, MIO_T_PCAP, &mio_icfg_pf,
                                 err), {
                if ((*miod_flags & MIO_F_OPT_DAEMON) &&
                    !strcmp(source->spec, "-"))
                {
                    g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                                "Standard input not supported in --daemon mode");
                    return FALSE;
                }
                if (!mio_config_filerouter(&(mio_icfg_pf.filecfg),
                                           *miod_flags, err))
                {
                    return FALSE;
                }
            });
        }
    }
#endif /* if HAVE_LIBPCAP */

    /* Handle single-TCP passive open case */
    if (cli_flags & MIO_F_CLI_TCP_IN) {
        /* Swap poll into TCP configuration */
        mio_icfg_tcp.timeout.tv_sec = mio_ov_poll;
        mio_icfg_tcp.timeout.tv_usec = 0;
        mio_icfg_tcp.default_port = mio_ov_port;
        MIO_CFG_TRYINIT2(mio_source_init_tcp(
                             source, mio_ov_in, MIO_T_SOCK_STREAM,
                             &mio_icfg_tcp, err), {
            mio_ov_poll = 0;
        });
    }

    /* Handle UDP passive open case */
    if (cli_flags & MIO_F_CLI_UDP_IN) {
        MIO_CFG_TRYINIT(mio_source_init_udp(
                            source, mio_ov_in, MIO_T_SOCK_DGRAM, mio_ov_port,
                            err));
    }

    /* Handle file open case - this snags stdin - */
    if (cli_flags & MIO_F_CLI_FILE_IN) {
        /* check for directory if necessary */
        if (cli_flags & MIO_F_CLI_DIR_IN) {
            MIO_CFG_TRYINIT2(mio_source_init_file_dir(
                                 source, mio_ov_in, mio_ov_filetype,
                                 &mio_icfg_f, err), {
                if (!mio_config_filerouter(&mio_icfg_f, *miod_flags, err)) {
                    return FALSE;
                }
            });
        }
        /* treat inspec as glob */
        MIO_CFG_TRYINIT2(mio_source_init_file_glob(
                             source, mio_ov_in, mio_ov_filetype, &mio_icfg_f,
                             err), {
            if ((*miod_flags & MIO_F_OPT_DAEMON) &&
                !strcmp(source->spec, "-"))
            {
                g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                            "Standard input not supported in --daemon mode");
                return FALSE;
            }
            if (!mio_config_filerouter(&mio_icfg_f, *miod_flags, err)) {
                return FALSE;
            }
        });
    }

    /* Handle no source error */
    if (err && !*err) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "No sources available for --in (-i) input specifier %s",
                    mio_ov_in ? mio_ov_in : "[null]");
    }

    return FALSE;
}


gboolean
mio_config_sink(
    MIOSource  *source,
    MIOSink    *sink,
    char       *basepat,
    uint32_t    cli_flags,
    uint32_t   *miod_flags,
    GError    **err)
{
    /* Handle TCP active open case */
    if (cli_flags & MIO_F_CLI_TCP_OUT) {
        MIO_CFG_TRYINIT(mio_sink_init_tcp(
                            sink, mio_ov_out, MIO_T_SOCK_STREAM, mio_ov_port,
                            err));
    }

    /* Handle UDP active open case */
    if (cli_flags & MIO_F_CLI_UDP_OUT) {
        MIO_CFG_TRYINIT(mio_sink_init_udp(
                            sink, mio_ov_out, MIO_T_SOCK_DGRAM, mio_ov_port,
                            err));
    }

    /* Handle file open case - this snags stdout - */
    if (cli_flags & MIO_F_CLI_FILE_OUT) {
        mio_ocfg_pat = g_string_new(NULL);

        /* Handle no output spec cases */
        if (!mio_ov_out) {
            if (((source->vsp_type == MIO_T_PCAP) && mio_ov_live) ||
                source->vsp_type == MIO_T_SOCK_DGRAM ||
                source->vsp_type == MIO_T_SOCK_STREAM)
            {
                /* Network input: base pattern in current working directory */
                g_string_printf(mio_ocfg_pat, "./%s", basepat);
            } else if (cli_flags & MIO_F_CLI_DEF_STDOUT &&
                       (!source || !strcmp(source->spec, "-")))
            {
                /* Standard output default - override sinklink */
                *miod_flags &= ~MIO_F_OPT_SINKLINK;
                return mio_sink_init_stdout(
                    sink, "-", mio_ov_filetype, NULL, err);
            } else if (cli_flags & MIO_F_CLI_DIR_OUT) {
                /* Base pattern in source directory */
                g_string_printf(mio_ocfg_pat, "%%d/%s", basepat);
            } else {
                /* Can't continue. Need at least one default fallback. */
                g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                            "Missing required --out (-o) output specifier argument");
                return FALSE;
            }
        }

        /* Check for output specifier is dir */
        if (mio_ov_out && (cli_flags & MIO_F_CLI_DIR_OUT) &&
            g_file_test(mio_ov_out, G_FILE_TEST_IS_DIR))
        {
            /* Yep. Generate an output pattern from the directory. */
            g_string_printf(mio_ocfg_pat, "%s/%s", mio_ov_out, basepat);
        }

        /* Check for assumption of single file output */
        if (!mio_ocfg_pat->len) {
            /* single file - override sinklink */
            *miod_flags &= ~MIO_F_OPT_SINKLINK;
            g_string_printf(mio_ocfg_pat, "%s", mio_ov_out);
        }

        MIO_CFG_TRYINIT2(mio_sink_init_file_pattern(
                             sink, mio_ocfg_pat->str, mio_ov_filetype,
                             &mio_ocfg_f, err), {
            if ((*miod_flags & MIO_F_OPT_DAEMON) &&
                !strcmp(sink->spec, "-"))
            {
                g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                            "Standard output not supported in --daemon mode");
                return FALSE;
            }
        });
    }

    /* Handle no sink error */
    if (err && !*err) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "No sinks available for output specifier %s",
                    mio_ov_out ? mio_ov_out : "[null]");
    }

    return FALSE;
}


gboolean
mio_config_multisink_file(
    MIOSource  *source,
    MIOSink    *sink,
    char       *basepat,
    uint32_t    count,
    char      **labels,
    uint32_t    cli_flags,
    uint32_t   *miod_flags,
    GError    **err)
{
    gboolean isdir = FALSE;
    char    *basepat_mod = NULL;
    char    *basepat_ext = NULL;
    uint32_t mi = 0;

    /* create a multifile sink */
    if (!mio_sink_init_multi(sink, mio_ov_out, MIO_T_SINKARRAY,
                             GUINT_TO_POINTER(count), err))
    {
        return FALSE;
    }

    /* modify base pattern if necessary */
    mio_ocfg_pat = g_string_new(NULL);

    /* No output specifier? */
    if (!mio_ov_out) {
        if (cli_flags & MIO_F_CLI_DIR_OUT) {
            /* Base pattern in source directory */
            g_string_printf(mio_ocfg_pat, "%%d/%s", basepat);
            isdir = TRUE;
        } else {
            /* Can't continue. Need at least one default fallback. */
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                        "Missing required --out (-o) output specifier argument");
            return FALSE;
        }
    }

    /* Check for output specifier is dir */
    if (mio_ov_out && (cli_flags & MIO_F_CLI_DIR_OUT) &&
        g_file_test(mio_ov_out, G_FILE_TEST_IS_DIR))
    {
        /* Yep. Generate an output pattern from the directory. */
        g_string_printf(mio_ocfg_pat, "%s/%s", mio_ov_out, basepat);
        isdir = TRUE;
    }

    /* set up directory pattern */
    if (isdir) {
        basepat_mod = strdup(mio_ocfg_pat->str);
    } else {
        *miod_flags &= ~MIO_F_OPT_SINKLINK;
        basepat_mod = strdup(mio_ov_out);
    }

    /* strip extension from base pattern */
    if ((basepat_ext = strrchr(basepat_mod, '.'))) {
        *(basepat_ext++) = (char)0;
    }

    /* initialize each file sink in the multifile sink */
    for (mi = 0; mi < count; mi++) {
        /* generate a new file pattern */
        if (basepat_ext) {
            g_string_printf(mio_ocfg_pat, "%s-%s.%s",
                            basepat_mod, labels[mi], basepat_ext);
        } else {
            g_string_printf(mio_ocfg_pat, "%s-%s",
                            basepat_mod, labels[mi]);
        }

        if (!mio_sink_init_file_pattern(&mio_smn(sink, mi), mio_ocfg_pat->str,
                                        mio_ov_filetype, &mio_ocfg_f, err))
        {
            return FALSE;
        }
    }

    /* All done */
    return TRUE;
}
