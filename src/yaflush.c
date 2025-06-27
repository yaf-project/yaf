/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yaflush.c
 *  YAF unified flow/flush logic
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
#include "yaflush.h"
#include "yafout.h"
#include "yafstat.h"
#include <yaf/yafcore.h>

gboolean
yfProcessPBufRing(
    yfContext_t  *ctx,
    GError      **err)
{
    AirLock  *lock = NULL;
    yfPBuf_t *pbuf = NULL;
    gboolean  ok = TRUE;
    yfTime_t  cur_time;

    /* point to lock buffer if we need it */
    if (ctx->cfg->lockmode) {
        lock = &ctx->lockbuf;
    }

    /* Open output if we need to */
    if (!ctx->cfg->no_output) {
        if (!ctx->fbuf) {
            if (!(ctx->fbuf = yfOutputOpen(ctx->cfg, lock, err))) {
                ok = FALSE;
                goto end;
            }
        }
    }

    /* Dump statistics if requested */
    yfStatDumpLoop();

    /* process packets from the ring buffer */
    while ((pbuf = (yfPBuf_t *)rgaNextTail(ctx->pbufring))) {
        /* Skip time zero packets (these are marked invalid) */
        if (!yfTimeIsSet(pbuf->ptime)) {
            continue;
        }

        /* Add the packet to the flow table */
        yfFlowPBuf(ctx->flowtab, ctx->pbuflen, pbuf);
    }

    /* Flush the flow table */
    if (!yfFlowTabFlush(ctx, FALSE, err)) {
        ok = FALSE;
        goto end;
    }

    /* Close output file for rotation if necessary */
    if (yfDiffTimeIsSet(ctx->cfg->rotate_interval)) {
        yfFlowTabCurrentTime(ctx->flowtab, &cur_time);
        if (!yfTimeIsSet(ctx->last_rotate_time)) {
            ctx->last_rotate_time = cur_time;
        } else {
            if (yfTimeCheckElapsed(cur_time, ctx->last_rotate_time,
                                   ctx->cfg->rotate_interval))
            {
                yfOutputClose(ctx->fbuf, lock, TRUE);
                ctx->fbuf = NULL;
                ctx->last_rotate_time = cur_time;
                if (!(ctx->fbuf = yfOutputOpen(ctx->cfg, lock, err))) {
                    ok = FALSE;
                    goto end;
                }
            }
        }
    }

  end:
    return ok;
}


gboolean
yfTimeOutFlush(
    yfContext_t  *ctx,
    uint32_t      pcap_drop,
    uint32_t     *total_stats,
    GTimer       *timer,       /* yaf process timer */
    GTimer       *stats_timer,       /* yaf stats output timer */
    GError      **err)
{
    AirLock *lock = NULL;
    yfTime_t cur_time;

    /* point to lock buffer if we need it */
    if (ctx->cfg->lockmode) {
        lock = &ctx->lockbuf;
    }

    /* Open output if we need to */
    if (!ctx->cfg->no_output) {
        if (!ctx->fbuf) {
            if (!(ctx->fbuf = yfOutputOpen(ctx->cfg, lock, err))) {
                return FALSE;
            }
        }
    }

    /* Dump statistics if requested */
    yfStatDumpLoop();

    /* Flush the flow table */
    if (!yfFlowTabFlush(ctx, FALSE, err)) {
        return FALSE;
    }

    if (!ctx->cfg->nostats) {
        if (!stats_timer) {
            stats_timer = g_timer_new();
        }
        if (g_timer_elapsed(stats_timer, NULL) > ctx->cfg->stats_interval) {
            if (!yfWriteOptionsDataFlows(ctx, pcap_drop, timer, err)) {
                return FALSE;
            }
            g_timer_start(stats_timer);
            *total_stats += 1;
        }
    }

    if (!ctx->cfg->no_output) {
        if (!fBufEmit(ctx->fbuf, err)) {
            return FALSE;
        }
    }

    /* Close output file for rotation if necessary */
    if (yfDiffTimeIsSet(ctx->cfg->rotate_interval)) {
        yfFlowTabCurrentTime(ctx->flowtab, &cur_time);
        if (!yfTimeIsSet(ctx->last_rotate_time)) {
            ctx->last_rotate_time = cur_time;
        } else {
            if (yfTimeCheckElapsed(cur_time, ctx->last_rotate_time,
                                   ctx->cfg->rotate_interval))
            {
                yfOutputClose(ctx->fbuf, lock, TRUE);
                ctx->fbuf = NULL;
                ctx->last_rotate_time = cur_time;
            }
        }
    }

    return TRUE;
}


gboolean
yfFinalFlush(
    yfContext_t  *ctx,
    gboolean      ok,
    uint32_t      pcap_drop,
    GTimer       *timer,
    GError      **err)
{
    AirLock *lock = NULL;
    gboolean frv;
    gboolean srv = TRUE;

    /* point to lock buffer if we need it */
    if (ctx->cfg->lockmode) {
        lock = &ctx->lockbuf;
    }

    /* handle final flush and close */
    if (ctx->fbuf) {
        if (ok) {
            /* Flush flow buffer and close output file on successful exit */
            frv = yfFlowTabFlush(ctx, TRUE, err);
            if (!ctx->cfg->nostats) {
                srv = yfWriteOptionsDataFlows(ctx, pcap_drop, timer, err);
            }
            yfOutputClose(ctx->fbuf, lock, TRUE);
            if (!frv || !srv) {
                ok = FALSE;
            }
        } else {
            /* Just close output file on error */
            yfOutputClose(ctx->fbuf, lock, FALSE);
        }
    }

    return ok;
}
