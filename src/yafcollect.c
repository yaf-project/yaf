/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafcollect.c
 *  Yet Another Flow IPFIX collector
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

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <airframe/mio.h>
#include <airframe/mio_config.h>
#include <airframe/mio_sink_file.h>
#include <airframe/logconfig.h>
#include <airframe/daeconfig.h>
#include <airframe/airutil.h>
#include <airframe/privconfig.h>
#include <yaf/yafcore.h>
#include "yafctx.h"

/* wrap this around string literals that are assigned to variables of type
 * "char *" to quiet compiler warnings */
#define C(String) (char *)String


typedef struct ycContext_st {
    uint32_t   outtime;
    fBuf_t    *obuf;
    fBuf_t    *ibuf;
    gboolean   ibuf_ready;
    GString   *pstr;
    yfFlow_t   flow;
} ycContext_t;

/* stats */
static uint32_t     yac_files = 0;
static uint32_t     yac_flows = 0;

/* GOption managed options */
static int          yac_rotate = 300;
static char        *yac_transport = C("tcp");
static gboolean     yac_tls = FALSE;
static gboolean     yac_printall = FALSE;

static fbConnSpec_t yac_inspec = FB_CONNSPEC_INIT;

static yfConfig_t   yaf_config = YF_CONFIG_INIT;

/* MIO command-line configuration */
static uint32_t     yac_cliflags =  MIO_F_CLI_FILE_OUT |
    MIO_F_CLI_DIR_OUT;

static AirOptionEntry      yac_optentries[] = {
    AF_OPTION( "in", 'i', 0, AF_OPT_TYPE_STRING, &(yac_inspec.host),
               "Hostname or address to listen on", NULL ),
    AF_OPTION( "rotate-delay", 'I', 0, AF_OPT_TYPE_INT, &yac_rotate,
               "Output file rotation delay [300, 5m]", "sec" ),
    AF_OPTION( "transport", (char)0, 0, AF_OPT_TYPE_STRING, &yac_transport,
               "Set IPFIX transport (tcp, udp, sctp) [tcp]", "protocol" ),
    AF_OPTION( "port", (char)0, 0, AF_OPT_TYPE_STRING, &(yac_inspec.svc),
               "Select IPFIX listener port [4739, 4740]", "port" ),
    AF_OPTION( "tls", (char)0, 0, AF_OPT_TYPE_NONE, &yac_tls,
               "Use TLS/DTLS to secure IPFIX export", NULL ),
    AF_OPTION( "tls-ca", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yac_inspec.ssl_ca_file),
               "Specify TLS Certificate Authority file", "cafile" ),
    AF_OPTION( "tls-cert", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yac_inspec.ssl_cert_file),
               "Specify TLS Certificate file", "certfile" ),
    AF_OPTION( "tls-key", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yac_inspec.ssl_key_file),
               "Specify TLS Private Key file", "keyfile" ),
    AF_OPTION( "tls-pass", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yac_inspec.ssl_key_pass),
               "Specify TLS Private Key password", "password" ),
    AF_OPTION( "print-all", (char)0, 0, AF_OPT_TYPE_NONE, &yac_printall,
               "print all flows to stdout as received", NULL ),
    AF_OPTION_END
};

static void
ycParseOptions(
    int   *argc,
    char **argv[])
{
    AirOptionCtx *aoctx = NULL;

    aoctx = air_option_context_new("", argc, argv, yac_optentries);

    mio_add_option_group(aoctx, yac_cliflags);
    daec_add_option_group(aoctx);
    privc_add_option_group(aoctx);
    logc_add_option_group(aoctx, "yafcollect", VERSION);

    air_option_context_set_help_enabled(aoctx);
    air_option_context_parse(aoctx);

    air_option_context_free(aoctx);
}


/* the following is not 64-bit clean. */
#if 0
static gboolean
ycConnectDebug(
    fbListener_t     *listener,
    void            **ctx,
    int               fd,
    struct sockaddr  *speer,
    size_t            peerlen,
    GError          **err)
{
    char pabuf[256];
    union {
        struct sockaddr      *so;
        struct sockaddr_in   *ip4;
        struct sockaddr_in6  *ip6;
    }                           peer;

    peer.so = speer;
    if (peer.so->sa_family == AF_INET) {
        g_debug("New IPv4 connection from %s",
                inet_ntop(AF_INET, &(peer.ip4->sin_addr),
                          pabuf, sizeof(pabuf)));
    } else if (peer.so->sa_family == AF_INET6) {
        g_debug("New IPv6 connection from %s",
                inet_ntop(AF_INET6, &(peer.ip6->sin6_addr),
                          pabuf, sizeof(pabuf)));
    } else {
        g_debug("New connection from unknown AF %u", peer.so->sa_family);
    }

    return TRUE;
}
#endif /* 0 */


static gboolean
ycOpenListener(
    MIOSource  *source,
    void       *vctx,
    uint32_t   *flags,
    GError    **err)
{
    /* create listener */
    if (!(source->vsp = yfListenerForSpec(&yac_inspec, NULL,
                                          NULL, err)))
    {
        *flags |= (MIO_F_CTL_ERROR | MIO_F_CTL_TERMINATE);
        return FALSE;
    }

    return TRUE;
}


static gboolean
ycCloseListener(
    MIOSource  *source,
    void       *vctx,
    uint32_t   *flags,
    GError    **err)
{
    /* FIXME should shut the listener down perhaps? */

    return TRUE;
}


static gboolean
ycOpenFileSink(
    MIOSource  *source,
    MIOSink    *sink,
    void       *vctx,
    uint32_t   *flags,
    GError    **err)
{
    ycContext_t *yx = (ycContext_t *)vctx;
    yfConfig_t yfConfig = YF_CONFIG_INIT;

    yfConfig.time_elements = YF_TIME_IE__DEFAULT;

    /* start a new FixWriter */
    yx->obuf = yfWriterForFP(mio_fp(sink), &yaf_config, err);

    /* check for failure */
    if (yx->obuf) {
        /* Done. Get timestamp for file. */
        yx->outtime = time(NULL);
        ++yac_files;
        return TRUE;
    } else {
        *flags |= (MIO_F_CTL_SINKCLOSE | MIO_F_CTL_ERROR);
        return FALSE;
    }
}


static gboolean
ycCloseFileSink(
    MIOSource  *source,
    MIOSink    *sink,
    void       *vctx,
    uint32_t   *flags,
    GError    **err)
{
    ycContext_t *yx = (ycContext_t *)vctx;

    /* finish the message */
    if (yfWriterClose(yx->obuf, TRUE, err)) {
        yx->obuf = NULL;
        return TRUE;
    } else {
        *flags |= MIO_F_CTL_ERROR;
        return FALSE;
    }
}


static gboolean
ycProcess(
    MIOSource  *source,
    MIOSink    *sink,
    void       *vctx,
    uint32_t   *flags,
    GError    **err)
{
    ycContext_t  *yx = (ycContext_t *)vctx;
    fbListener_t *listener = (fbListener_t *)source->vsp;
    yfContext_t   ctx = YF_CTX_INIT;

    ctx.fbuf = yx->obuf;
    ctx.cfg = &yaf_config;

    /* Check for end of output file */
    if (yac_rotate && (time(NULL) > yx->outtime + yac_rotate)) {
        *flags |= MIO_F_CTL_SINKCLOSE;
    }

    /* Check for quit */
    if (daec_did_quit()) {
        *flags |= MIO_F_CTL_TERMINATE;
        return TRUE;
    }

    /* Check to see if we need to wait for a buffer */
    if (!yx->ibuf || !yx->ibuf_ready) {
        if (!(yx->ibuf = fbListenerWait(listener, err))) {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD) ||
                g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_CONN))
            {
                /* FIXME this quits on any interrupt */
                daec_quit();
                g_critical("Error on read: %s", (*err)->message);
                g_clear_error(err);
                *flags |= MIO_F_CTL_TERMINATE;
                return TRUE;
            } else {
                return FALSE;
            }
        }
    }

    /* presume our buffer is ready and process a flow */
    yx->ibuf_ready = TRUE;
    if (yfReadFlowExtended(yx->ibuf, &(yx->flow), err)) {
        /* Print it for debugging purposes */
        if (yx->pstr) {
            g_string_truncate(yx->pstr, 0);
        } else {
            yx->pstr = g_string_new(NULL);
        }
        yfPrintString(yx->pstr, &(yx->flow));
        if (yac_printall) {
            fprintf(stdout, "flow: %s", yx->pstr->str);
        }

        /* Got a flow. Write it. */
        if (yfWriteFlow(&ctx, &(yx->flow), err)) {
            /* Read and written. Done. */
            ++yac_flows;
            return TRUE;
        } else {
            /* Write error. Fatal. */
            *flags |= MIO_F_CTL_ERROR;
            return FALSE;
        }
    } else {
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
            /* End of message. Set ibuf not ready, keep going. */
            g_clear_error(err);
            yx->ibuf_ready = FALSE;
            return TRUE;
        } else if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD)) {
            /* just keep going if the error is "no packet" */
            g_clear_error(err);
            return TRUE;
        } else {
            /* Close the buffer */
            fBufFree(yx->ibuf);
            yx->ibuf_ready = FALSE;
            yx->ibuf = NULL;

            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
                /* EOF on a single collector not an issue. */
                g_clear_error(err);
                g_debug("Normal connection close");
                return TRUE;
            } else {
                /* bad message. no doughnut. chuck it but keep the socket. */
                sink->active = FALSE;
                *flags |= MIO_F_CTL_ERROR;
                return FALSE;
            }
        }
    }
}


int
main(
    int    argc,
    char  *argv[])
{
    GError      *err = NULL;
    ycContext_t  yx;
    MIOSource    source;
    MIOSink      sink;
    MIOAppDriver adrv;
    uint32_t     miodflags;
    int          rv          = 0;

    /* parse options */
    ycParseOptions(&argc, &argv);

    /* set up logging */
    if (!logc_setup(&err)) {
        air_opterr("%s", err->message);
    }

    /* fork if necessary */
    if (!daec_setup(&err)) {
        air_opterr("%s", err->message);
    }

    /* initialize MIO flags */
    miodflags = 0;

    /* default port */
    if (!yac_inspec.svc) {
        yac_inspec.svc = (yac_tls ? C("4740") : C("4739"));
    }

    if (strcmp(yac_transport, "tcp") == 0) {
        if (yac_tls) {
            yac_inspec.transport = FB_TLS_TCP;
        } else {
            yac_inspec.transport = FB_TCP;
        }
    } else if (strcmp(yac_transport, "udp") == 0) {
        if (yac_tls) {
            yac_inspec.transport = FB_DTLS_UDP;
        } else {
            yac_inspec.transport = FB_UDP;
        }
    } else if (strcmp(yac_transport, "sctp") == 0) {
        if (yac_tls) {
            yac_inspec.transport = FB_DTLS_SCTP;
        } else {
            yac_inspec.transport = FB_SCTP;
        }
    } else {
        air_opterr("Unsupported IPFIX transport protocol %s", yac_transport);
    }

    /* create a source around a listener */
    if (!mio_source_init_app(&source, mio_ov_in, MIO_T_APP, NULL, &err)) {
        air_opterr("Cannot set up MIO input: %s", err->message);
    }

    /* set up sink */
    if (!mio_config_sink(&source, &sink, C("ipfix-%T.yaf"), yac_cliflags,
                         &miodflags, &err))
    {
        air_opterr("Cannot set up output: %s", err->message);
    }

    /* initialize yafcollect context */
    yfFlowPrepare(&(yx.flow));
    yx.obuf = NULL;
    yx.ibuf = NULL;
    yx.ibuf_ready = FALSE;
    yx.pstr = NULL;
    yx.outtime = 0;

    /* set up an app driver */
    adrv.app_open_source = ycOpenListener;
    adrv.app_close_source = ycCloseListener;
    adrv.app_open_sink = ycOpenFileSink;
    adrv.app_close_sink = ycCloseFileSink;
    adrv.app_process = ycProcess;

    /* do dispatch here */
    if (!mio_dispatch_loop(&source, &sink, &adrv, &yx, miodflags, mio_ov_poll,
                           1, mio_ov_poll))
    {
        rv = 1;
    }

    g_message("yafcollect terminating");
    g_message("Processed %u flows into %u files", yac_flows, yac_files);

    return rv;
}
