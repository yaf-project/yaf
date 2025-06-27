/*
 *  Copyright 2007-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafctx.h
 *  YAF configuration
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

#ifndef _YAF_CTX_H_
#define _YAF_CTX_H_

#include <yaf/autoinc.h>
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>
#include <yaf/decode.h>
#include <yaf/ring.h>
#include <airframe/airlock.h>

#ifdef HAVE_SPREAD
/* Values for spreadGroupby */
#define YAF_SPREAD_GROUPBY_DESTPORT   1
#define YAF_SPREAD_GROUPBY_VLANID     2
#define YAF_SPREAD_GROUPBY_APPLABEL   3
#define YAF_SPREAD_GROUPBY_PROTOCOL   4
#define YAF_SPREAD_GROUPBY_IPVERSION  5
#endif  /* HAVE_SPREAD */

typedef struct yfConfig_st {
    char              *inspec;
    char              *livetype;
    char              *outspec;
    char              *bpf_expr;
    char              *pcapdir;

    gboolean           pcap_per_flow;
    gboolean           lockmode;
    gboolean           ipfixNetTrans;
    gboolean           noerror;
    gboolean           exportInterface;
    gboolean           macmode;
    gboolean           silkmode;
    /* TRUE to disable process statistics (and tombstone) option recs */
    gboolean           nostats;

    gboolean           flowstatsmode;
    gboolean           deltaMode;
    gboolean           no_output;
    gboolean           tmpl_metadata;
    gboolean           no_tombstone;
    gboolean           layer2IdExportMode;
    gboolean           force_ip6;

    /* A bitfield of all timestamps to appear in the record */
    uint8_t            time_elements;

    uint16_t           tombstone_configured_id;
    uint32_t           ingressInt;
    uint32_t           egressInt;

    /* How often to send stats and tombstone records, in seconds as measured
     * by a GTimer */
    double             stats_interval;

    yfDiffTime_t       rotate_interval;
    /* How often to send templates over UDP.  This is 1/3 the value given to
     * --udp-temp-timeout in accordance with RFC 5101.  Currently YAF does not
     * expire UDP templates */
    yfDiffTime_t       udp_tmpl_interval;
    uint64_t           max_pcap;
    uint64_t           pcap_timer;

    /* non-NULL when exporting payload for only selected appLabels;
     * `payload_applabels_size` is its lenth */
    uint16_t          *payload_applabels;
    /* number of applabels in `payload_applabels` */
    uint16_t           payload_applabels_size;

    /* amount of payload to export; 0 for none */
    uint16_t           export_payload;

    uint32_t           odid;
    fbConnSpec_t       connspec;
#ifdef HAVE_SPREAD
    gboolean           ipfixSpreadTrans;
    fbSpreadParams_t   spreadparams;
    uint16_t          *spreadGroupIndex;
    uint8_t            numSpreadGroups;
    uint8_t            spreadGroupby;
#endif /* ifdef HAVE_SPREAD */
} yfConfig_t;

/* Define yfConfig_t entries when Spread is enabled or disabled */
#ifdef HAVE_SPREAD
#define YAF_CONFIG_INIT_SPREAD                  \
    FALSE, FB_SPREADPARAMS_INIT, NULL, 0, 0
#else
#define YAF_CONFIG_INIT_SPREAD
#endif  /* HAVE_SPREAD */

#define YF_CONFIG_INIT                                       \
    {NULL, NULL, NULL, NULL, NULL,                           \
     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, \
     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,        \
     0, 0, 0, 0, 0.0,                                        \
     YF_DIFFTIME_INIT, YF_DIFFTIME_INIT, 5, 0,               \
     NULL, 0, 0, 0, FB_CONNSPEC_INIT,                        \
     YAF_CONFIG_INIT_SPREAD}

typedef struct yfContext_st {
    /** Configuration */
    yfConfig_t     *cfg;
    /** Packet source */
    void           *pktsrc;
    /** Packet ring buffer */
    size_t          pbuflen;
    rgaRing_t      *pbufring;
    /** Decoder */
    yfDecodeCtx_t  *dectx;
    /** Flow table */
    yfFlowTab_t    *flowtab;
    /** Fragment table */
    yfFragTab_t    *fragtab;
    /** Output rotation state */
    yfTime_t        last_rotate_time;
    /** Output lock buffer */
    AirLock         lockbuf;
    /** Output IPFIX buffer */
    fBuf_t         *fbuf;
    /** UDP last template send time */
    yfTime_t        udp_tmpl_sendtime;
    /** yaf start time */
    yfTime_t        yaf_start_time;
    /** Error description */
    GError         *err;
    /** Pcap File Ptr for Rolling Pcap*/
    pcap_dumper_t  *pcap;
    /** Pcap Offset into Rolling Pcap */
    uint64_t        pcap_offset;
    /** Pcap Lock Buffer */
    AirLock         pcap_lock;
} yfContext_t;

#define YF_CTX_INIT                                                     \
    {NULL, NULL, 0, NULL, NULL, NULL, NULL, YF_TIME_INIT, AIR_LOCK_INIT, \
     NULL, YF_TIME_INIT, YF_TIME_INIT, NULL, NULL, 0, AIR_LOCK_INIT}

/* global quit flag, defined in yaf.c */
extern int yaf_quit;

#endif /* ifndef _YAF_CTX_H_ */
