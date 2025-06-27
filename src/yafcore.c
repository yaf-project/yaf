/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafcore.c
 *  YAF core I/O routines
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell, Chris Inacio, Emily Ecoff
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
#include "yafctx.h"
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <airframe/airutil.h>
#include <yaf/yafrag.h>

#define INFOMODEL_EXCLUDE_yaf_dpi 1
#define INFOMODEL_EXCLUDE_yaf_dhcp 1
#include "infomodel.h"

#ifdef YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif


#define FBSTMLINIT(s, i, t) fbSubTemplateMultiListEntryInit(s, i, t, 1)
#define FBSTMLNEXT(p, s) fbSubTemplateMultiListGetNextEntry(p, s)

/* fixbuf 2.x uses char* as the type of the name of info elements in
 * fbInfoElementSpec_t; wrap this around string literals to quiet compiler
 * warnings */
#define C(String) (char *)String

/**
 *  Constant to tell fbTemplateAppendSpecArray() (via yfAddTemplate() and
 *  yfAddTemplateSpread()) to include all IEs
 */
#define YF_TMPL_SPEC_ALL_IE  UINT32_MAX

/**
 *  The value used to determine full- vs reduced-length encoding for octet and
 *  packet counters.  To use RLE, all counters must be less than this value.
 */
#define YAF_RLEMAX      (1L << 31)

/**  Delimiter used by yafscii and yafcollect */
#define YF_PRINT_DELIM  "|"

/**
 *  Names an environment variable that if defined (and if the first character
 *  is not '\0', '0', 'F', or 'f') causes the template alignment checks run by
 *  yaf and yafscii to be verbose.
 */
#define YAF_ALIGNMENT_CHECK  "YAF_ALIGNMENT_CHECK"


/*
 *  The template ID's and meta-data names for records other than flow records
 *  (yaf-stats, tombstone, metadata).
 */

#define YAF_PROCESS_STATS_TID     0xD003
#define YAF_TOMBSTONE_TID         0xD004
#define YAF_TOMBSTONE_ACCESS_TID  0xD005
#define YAF_TYPE_METADATA_TID     0xD006
#define YAF_TEMPLATE_METADATA_TID 0xD007

#define YAF_PROCESS_STATS_NAME      C("yaf_process_stats")
#define YAF_TOMBSTONE_NAME          C("tombstone_record")
#define YAF_TOMBSTONE_ACCESS_NAME   C("tombstone_access")

/*
 *  Template IDs and names for standard STML entries (TCP data, flow-stats,
 *  etc).
 */

#define YAF_APP_FLOW_TID       0xC001 /* not used */
#define YAF_ENTROPY_TID        0xC002
#define YAF_TCP_TID            0xC003
#define YAF_MAC_TID            0xC004
#define YAF_FLOWSTATS_TID      0xC005
#define YAF_P0F_TID            0xC006
#define YAF_FPEXPORT_TID       0xC007
#define YAF_PAYLOAD_TID        0xC008
#define YAF_MPTCP_TID          0xC009

/* Used to create reverse forms of the following names */
#define YF_REVNAME(name)            name "_rev"

#define YAF_APP_FLOW_NAME           "UNUSED" /* not used */
#define YAF_ENTROPY_NAME            "yaf_entropy"
#define YAF_TCP_NAME                "yaf_tcp"
#define YAF_MAC_NAME                "yaf_mac"
#define YAF_FLOWSTATS_NAME          "yaf_flow_stats"
#define YAF_P0F_NAME                "yaf_p0f"
#define YAF_FPEXPORT_NAME           "yaf_fpexport"
#define YAF_PAYLOAD_NAME            "yaf_payload"
#define YAF_MPTCP_NAME              "yaf_mptcp"

/*
 *  The template IDs for flow records YAF_FLOW_BASE_TID that may be modified
 *  when additional elements (MPLS) or alternate elements (IPv6 addresses
 *  instead of IPv4) are present.
 *
 *  The presence of these additional/alternate elements are sometimes called
 *  dimensions, and the YAF Template Flags (YTF) determine which sets of
 *  fields are exported in an IPFIX record.
 *
 *  Some YTF values affect the template ID and appear in the lower 16 bits.
 *  Others are the "default" state (IPv4, total-counters, etc) and appear in
 *  the upper 16 bits.
 */

/* Base flow-full TID with no general or special definitions */
#define YAF_FLOW_BASE_TID   0xB000

/* Base of the template metadata name for yaf_flow_full */
#define YAF_FLOW_FULL_NAME  "yaf_flow"

/* TID for the internal export template; the flags used to build it are
 * specified in YTF_ALL.  (YTF_PADDING is defined below) */
#define YAF_FLOW_FULL_TID   (YAF_FLOW_BASE_TID | YTF_PADDING)

/* The TID for the internal "extended" record used by yafscii and yafcollect
 * to read data */
#define YAF_FLOW_EXT_TID    0xB7FF

/* YTF_REV is used to mask the incoming TID when reading data from the STML */
#define YTF_REV             0xFF0F

/* The FLAG_GEN macro generates the dimensions based on the 4 digit hidden
 * flags and 4 digit visible flags */
#define FLAG_GEN(h, v) ((((h) & UINT32_C(0xFFFF)) << 16)        \
                        | ((v) & UINT32_C(0xFFFF)))

/* Millisecond, Microsecond, Nanosecond times.  The TID always reflects
 * Milliseconds when present.  If Milliseconds are not present, the TID
 * reflects whether Nanoseconds appear.  If neither Milliseconds nor
 * Nanoseconds are present, the TID reflects the presence of Microseconds.  */
#define YTF_MILLI       FLAG_GEN(0x0100, 0x0000)
#define YTF_MICRO       FLAG_GEN(0x0200, 0x0000)
#define YTF_MICRO_ONLY  FLAG_GEN(0x0000, 0x0100) /* YTF_LEGACY_RLE */
#define YTF_NANO        FLAG_GEN(0x0400, 0x0000)
#define YTF_NANO_NOMIL  FLAG_GEN(0x0000, 0x0001) /* YTF_LEGACY_TOTAL */

/* Total vs Delta counters for octets, packets */
#define YTF_TOTAL       FLAG_GEN(0x0002, 0x0000)
#define YTF_DELTA       FLAG_GEN(0x0000, 0x0002)

#define YTF_MPLS        FLAG_GEN(0x0000, 0x0004)
#define YTF_NDPI        FLAG_GEN(0x0000, 0x0008)

/* Bi flow */
#define YTF_BIF         FLAG_GEN(0x0000, 0x0010)

#define YTF_SILK        FLAG_GEN(0x0000, 0x0020)
#define YTF_DAGIF       FLAG_GEN(0x0000, 0x0040)

/* Reduced- vs Full-length encoding of octets, packets */
#define YTF_RLE         FLAG_GEN(0x0008, 0x0000)
#define YTF_FLE         FLAG_GEN(0x0000, 0x0080)

/* See YTF_NANO above for 0x0100 */
/* Unused               FLAG_GEN(0x0000, 0x0200) */

/* IPv4 vs IPv6 addresses */
#define YTF_IP4         FLAG_GEN(0x0004, 0x0000)
#define YTF_IP6         FLAG_GEN(0x0000, 0x0400)

/* Padding octets --- becomes part of TID for the internal template */
#define YTF_PADDING     FLAG_GEN(0x0000, 0x0800)

/* VNI */
#define YTF_VNI         FLAG_GEN(0x0001, 0x0000)

/* YTF_ALL is used to build the internal template (YAF_FLOW_FULL_TID).  It
 * contains everything _except_ RLE enabled */
#define YTF_ALL         (FLAG_GEN(0xFFFF, 0xFFFF) & ~(YTF_RLE))

/* Flags for total packet & octet counters vs delta counters */
#define YTF_LEGACY_TOTAL    0x0001
#define YTF_LEGACY_DELTA    YTF_DELTA

/* Flags for reduced-length-encoding of packet & octet counters vs full */
#define YTF_LEGACY_RLE      0x0100
#define YTF_LEGACY_FLE      YTF_FLE

/* Flags for IPv4 addresses vs IPv6 */
#define YTF_LEGACY_IP4      0x0200
#define YTF_LEGACY_IP6      YTF_IP6

/* Names used as part of template metadata */
#define YTF_NAME_BIF         "_bif"
#define YTF_NAME_TOTAL       "_total"
#define YTF_NAME_DELTA       "_delta"
#define YTF_NAME_MPLS        "_mpls"
#define YTF_NAME_SILK        "_silk"
#define YTF_NAME_DAGIF       "_dagif"
#define YTF_NAME_FLE         "_fle"
#define YTF_NAME_RLE         "_rle"
#define YTF_NAME_IP4         "_ip4"
#define YTF_NAME_IP6         "_ip6"
#define YTF_NAME_NDPI        "_ndpi"
#define YTF_NAME_MILLI       "_milli"
#define YTF_NAME_MICRO       "_micro"
#define YTF_NAME_NANO        "_nano"

/*
 *    IPFIX definition of the full YAF flow record, yaf_flow_full_t
 *
 *    Within this array, the stime,etime element pairs with milli,micro,nano
 *    units elements each appear twice: once at the start of the array and
 *    again just before the STML.  Likewise, reverseFlowDelta<UNITS>seconds
 *    elements appear twice: once near the middle then again before the STML.
 *
 *    For each time-unit, at most one and perhaps none are used depending on
 *    the --time-elements setting and whether YTF_<UNIT>_TOP or
 *    YTF_<UNIT>_BOTTOM are used within the `flags` argument to
 *    fbTemplateAppendSpecArray().
 *
 *    For each time-unit, the values within yaf_flow_full_t only appear once.
 */
static fbInfoElementSpec_t yaf_flow_full_spec[] = {
    /* Millisecond, Microsecond, Nanosecond times */
    {C("flowStartMilliseconds"),            8, YTF_MILLI },
    {C("flowEndMilliseconds"),              8, YTF_MILLI },

    {C("flowStartMicroseconds"),            8, YTF_MICRO },
    {C("flowEndMicroseconds"),              8, YTF_MICRO },

    {C("flowStartNanoseconds"),             8, YTF_NANO },
    {C("flowEndNanoseconds"),               8, YTF_NANO },

    /* Counters --- Only one of {YTF_FLE, YTF_RLE} x {YTF_TOTAL, YTF_DELTA}
     * appears on the exported record */
    {C("octetTotalCount"),                  8, YTF_FLE | YTF_TOTAL },
    {C("reverseOctetTotalCount"),           8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    {C("packetTotalCount"),                 8, YTF_FLE | YTF_TOTAL },
    {C("reversePacketTotalCount"),          8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    /* delta Counters */
    {C("octetDeltaCount"),                  8, YTF_FLE | YTF_DELTA },
    {C("reverseOctetDeltaCount"),           8, YTF_FLE | YTF_DELTA | YTF_BIF },
    {C("packetDeltaCount"),                 8, YTF_FLE | YTF_DELTA },
    {C("reversePacketDeltaCount"),          8, YTF_FLE | YTF_DELTA | YTF_BIF },

    /* Reduced-length counters */
    {C("octetTotalCount"),                  4, YTF_RLE | YTF_TOTAL },
    {C("reverseOctetTotalCount"),           4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    {C("packetTotalCount"),                 4, YTF_RLE | YTF_TOTAL },
    {C("reversePacketTotalCount"),          4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    /* Reduced-length delta counters */
    {C("octetDeltaCount"),                  4, YTF_RLE | YTF_DELTA },
    {C("reverseOctetDeltaCount"),           4, YTF_RLE | YTF_DELTA | YTF_BIF },
    {C("packetDeltaCount"),                 4, YTF_RLE | YTF_DELTA },
    {C("reversePacketDeltaCount"),          4, YTF_RLE | YTF_DELTA | YTF_BIF },

    /* 5-tuple and flow status */
    {C("sourceIPv6Address"),                16, YTF_IP6 },
    {C("destinationIPv6Address"),           16, YTF_IP6 },
    {C("sourceIPv4Address"),                4, YTF_IP4 },
    {C("destinationIPv4Address"),           4, YTF_IP4 },

    {C("sourceTransportPort"),              2, 0 },
    {C("destinationTransportPort"),         2, 0 },
    {C("flowAttributes"),                   2, 0 },
    {C("reverseFlowAttributes"),            2, YTF_BIF },
    {C("protocolIdentifier"),               1, 0 },
    {C("flowEndReason"),                    1, 0 },

#if defined(YAF_ENABLE_APPLABEL)
    {C("silkAppLabel"),                     2, 0 },
#else
    /* paddingApplabel in yaf_flow_full_t */
    {C("paddingOctets"),                    2, YTF_PADDING },
#endif
    /* Start of the reverse flow as an offset from forward flow */
    {C("reverseFlowDeltaMilliseconds"),     4, YTF_MILLI | YTF_BIF },
    {C("reverseFlowDeltaMicroseconds"),     8, YTF_MICRO | YTF_BIF },
    {C("reverseFlowDeltaNanoseconds"),      8, YTF_NANO |YTF_BIF },

    /* TCP Info would need to go here 4 SiLK & 4b padding*/
    {C("tcpSequenceNumber"),                4, YTF_SILK },
    {C("reverseTcpSequenceNumber"),         4, YTF_SILK | YTF_BIF },
    {C("initialTCPFlags"),                  1, YTF_SILK },
    {C("unionTCPFlags"),                    1, YTF_SILK },
    {C("reverseInitialTCPFlags"),           1, YTF_SILK | YTF_BIF },
    {C("reverseUnionTCPFlags"),             1, YTF_SILK | YTF_BIF },

    {C("vlanId"),                           2, 0 },
    {C("reverseVlanId"),                    2, YTF_BIF },
    {C("ingressInterface"),                 4, YTF_DAGIF },
    {C("egressInterface"),                  4, YTF_DAGIF },

    /* VNI */
    {C("yafLayer2SegmentId"),               4, YTF_VNI },
    /* paddingLayer2Segment in yaf_flow_full_t */
    {C("paddingOctets"),                    4, YTF_VNI | YTF_PADDING },

    {C("ipClassOfService"),                 1, 0 },
    {C("reverseIpClassOfService"),          1, YTF_BIF },
    {C("mplsTopLabelStackSection"),         3, YTF_MPLS },
    {C("mplsLabelStackSection2"),           3, YTF_MPLS },
    {C("mplsLabelStackSection3"),           3, YTF_MPLS },
#if defined(YAF_ENABLE_NDPI)
    /* paddingNpdi in yaf_flow_full_t */
    {C("paddingOctets"),                    1, YTF_PADDING },
    {C("nDPIL7Protocol"),                   2, 0 },
    {C("nDPIL7SubProtocol"),                2, 0 },
#else
    /* paddingNpdi in yaf_flow_full_t */
    {C("paddingOctets"),                    5, YTF_PADDING },
#endif /* if defined(YAF_ENABLE_NDPI) */

    {C("subTemplateMultiList"),             FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};


#ifdef YAF_ENABLE_ENTROPY
/* entropy fields */
static fbInfoElementSpec_t yaf_entropy_spec[] = {
    {C("payloadEntropy"),                   1, 0 },
    {C("reversePayloadEntropy"),            1, YTF_BIF },
    FB_IESPEC_NULL
};

typedef struct yaf_entropy_st {
    uint8_t   entropy;
    uint8_t   reverseEntropy;
} yaf_entropy_t;
#endif /* ifdef YAF_ENABLE_ENTROPY */

static fbInfoElementSpec_t yaf_tcp_spec[] = {
    /* TCP-specific information */
    {C("tcpSequenceNumber"),                4, 0 },
    {C("initialTCPFlags"),                  1, 0 },
    {C("unionTCPFlags"),                    1, 0 },
    {C("reverseInitialTCPFlags"),           1, YTF_BIF },
    {C("reverseUnionTCPFlags"),             1, YTF_BIF },
    {C("reverseTcpSequenceNumber"),         4, YTF_BIF },
    FB_IESPEC_NULL
};

typedef struct yaf_tcp_st {
    uint32_t   tcpSequenceNumber;
    uint8_t    initialTCPFlags;
    uint8_t    unionTCPFlags;
    uint8_t    reverseInitialTCPFlags;
    uint8_t    reverseUnionTCPFlags;
    uint32_t   reverseTcpSequenceNumber;
} yaf_tcp_t;


/* MAC-specific information */
static fbInfoElementSpec_t yaf_mac_spec[] = {
    {C("sourceMacAddress"),                 6, 0 },
    {C("destinationMacAddress"),            6, 0 },
    FB_IESPEC_NULL
};

typedef struct yaf_mac_st {
    uint8_t   sourceMacAddress[6];
    uint8_t   destinationMacAddress[6];
} yaf_mac_t;


static fbInfoElementSpec_t yaf_mptcp_spec[] = {
    {C("mptcpInitialDataSequenceNumber"),   8, 0 },
    {C("mptcpReceiverToken"),               4, 0 },
    {C("mptcpMaximumSegmentSize"),          2, 0 },
    {C("mptcpAddressID"),                   1, 0 },
    {C("mptcpFlags"),                       1, 0 },
    FB_IESPEC_NULL
};


#if YAF_ENABLE_P0F
static fbInfoElementSpec_t yaf_p0f_spec[] = {
    {C("osName"),                           FB_IE_VARLEN, 0 },
    {C("osVersion"),                        FB_IE_VARLEN, 0 },
    {C("osFingerPrint"),                    FB_IE_VARLEN, 0 },
    {C("reverseOsName"),                    FB_IE_VARLEN, YTF_BIF },
    {C("reverseOsVersion"),                 FB_IE_VARLEN, YTF_BIF },
    {C("reverseOsFingerPrint"),             FB_IE_VARLEN, YTF_BIF },
    FB_IESPEC_NULL
};

typedef struct yaf_p0f_st {
    fbVarfield_t   osName;
    fbVarfield_t   osVersion;
    fbVarfield_t   osFingerPrint;
    fbVarfield_t   reverseOsName;
    fbVarfield_t   reverseOsVersion;
    fbVarfield_t   reverseOsFingerPrint;
} yaf_p0f_t;
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
static fbInfoElementSpec_t yaf_fpexport_spec[] = {
    {C("firstPacketBanner"),                FB_IE_VARLEN, 0 },
    {C("secondPacketBanner"),               FB_IE_VARLEN, 0 },
    {C("reverseFirstPacketBanner"),         FB_IE_VARLEN, YTF_BIF },
    FB_IESPEC_NULL
};

typedef struct yaf_fpexport_st {
    fbVarfield_t   firstPacketBanner;
    fbVarfield_t   secondPacketBanner;
    fbVarfield_t   reverseFirstPacketBanner;
} yaf_fpexport_t;
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
/* Variable-length payload fields */
static fbInfoElementSpec_t yaf_payload_spec[] = {
    {C("payload"),                          FB_IE_VARLEN, 0 },
    {C("reversePayload"),                   FB_IE_VARLEN, YTF_BIF },
    FB_IESPEC_NULL
};

typedef struct yaf_payload_st {
    fbVarfield_t   payload;
    fbVarfield_t   reversePayload;
} yaf_payload_t;
#endif /* if YAF_ENABLE_PAYLOAD */


/* IPFIX definition of the Extended YAF Flow record (yfIpfixExtFlow_t) used by
 * yafscii and yafcollect for reading data.  It contains elements which get
 * added to the internal record to support alternate time representations. */
static fbInfoElementSpec_t yaf_ext_flow_spec[] = {
    /* Second start, end, and duration (extended time) */
    {C("flowStartSeconds"),                 4, 0 },
    {C("flowEndSeconds"),                   4, 0 },
    /* Flow durations (extended time) */
    {C("flowDurationMicroseconds"),         4, 0 },
    {C("flowDurationMilliseconds"),         4, 0 },
    /* Microsecond delta start and end (extended time) */
    {C("flowStartDeltaMicroseconds"),       4, 0 },
    {C("flowEndDeltaMicroseconds"),         4, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_process_stats_spec[] = {
    {C("observationDomainId"),              4, 0 },
    {C("exportingProcessId"),               4, 0 },
    {C("exporterIPv4Address"),              4, 0 },
    {C("observationTimeSeconds"),           4, 0 },
    {C("systemInitTimeMilliseconds"),       8, 0 },
    {C("exportedFlowRecordTotalCount"),     8, 0 },
    {C("packetTotalCount"),                 8, 0 },
    {C("droppedPacketTotalCount"),          8, 0 },
    {C("ignoredPacketTotalCount"),          8, 0 },
    {C("notSentPacketTotalCount"),          8, 0 },
    {C("expiredFragmentCount"),             4, 0 },
    {C("assembledFragmentCount"),           4, 0 },
    {C("flowTableFlushEventCount"),         4, 0 },
    {C("flowTablePeakCount"),               4, 0 },
    {C("meanFlowRate"),                     4, 0 },
    {C("meanPacketRate"),                   4, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_tombstone_spec[] = {
    {C("observationDomainId"),              4, 0 },
    {C("exportingProcessId"),               4, 0 },
    {C("exporterConfiguredId"),             2, 0 },
    {C("paddingOctets"),                    6, 0 },
    {C("tombstoneId"),                      4, 0 },
    {C("observationTimeSeconds"),           4, 0 },
    {C("tombstoneAccessList"),              FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_tombstone_access_spec[] = {
    {C("certToolId"),                       4, 0 },
    {C("observationTimeSeconds"),           4, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t yaf_flowstats_spec[] = {
    {C("dataByteCount"),                            8, 0 },
    {C("averageInterarrivalTime"),                  8, 0 },
    {C("standardDeviationInterarrivalTime"),        8, 0 },
    {C("tcpUrgTotalCount"),                         4, 0 },
    {C("smallPacketCount"),                         4, 0 },
    {C("nonEmptyPacketCount"),                      4, 0 },
    {C("largePacketCount"),                         4, 0 },
    {C("firstNonEmptyPacketSize"),                  2, 0 },
    {C("maxPacketSize"),                            2, 0 },
    {C("standardDeviationPayloadLength"),           2, 0 },
    {C("firstEightNonEmptyPacketDirections"),       1, 0 },
    /* paddingFirst8 in yaf_flowstats_t */
    {C("paddingOctets"),                            1, 1 },
    {C("reverseDataByteCount"),                     8, YTF_BIF },
    {C("reverseAverageInterarrivalTime"),           8, YTF_BIF },
    {C("reverseStandardDeviationInterarrivalTime"), 8, YTF_BIF },
    {C("reverseTcpUrgTotalCount"),                  4, YTF_BIF },
    {C("reverseSmallPacketCount"),                  4, YTF_BIF },
    {C("reverseNonEmptyPacketCount"),               4, YTF_BIF },
    {C("reverseLargePacketCount"),                  4, YTF_BIF },
    {C("reverseFirstNonEmptyPacketSize"),           2, YTF_BIF },
    {C("reverseMaxPacketSize"),                     2, YTF_BIF },
    {C("reverseStandardDeviationPayloadLength"),    2, YTF_BIF },
    /* paddingRevStdDev in yaf_flowstats_t */
    {C("paddingOctets"),                            2, 1 },
    FB_IESPEC_NULL
};

typedef struct yaf_flowstats_st {
    uint64_t   dataByteCount;
    uint64_t   averageInterarrivalTime;
    uint64_t   standardDeviationInterarrivalTime;
    uint32_t   tcpUrgTotalCount;
    uint32_t   smallPacketCount;
    uint32_t   nonEmptyPacketCount;
    uint32_t   largePacketCount;
    uint16_t   firstNonEmptyPacketSize;
    uint16_t   maxPacketSize;
    uint16_t   standardDeviationPayloadLength;
    uint8_t    firstEightNonEmptyPacketDirections;
    uint8_t    paddingFirst8[1];
    /* reverse Fields */
    uint64_t   reverseDataByteCount;
    uint64_t   reverseAverageInterarrivalTime;
    uint64_t   reverseStandardDeviationInterarrivalTime;
    uint32_t   reverseTcpUrgTotalCount;
    uint32_t   reverseSmallPacketCount;
    uint32_t   reverseNonEmptyPacketCount;
    uint32_t   reverseLargePacketCount;
    uint16_t   reverseFirstNonEmptyPacketSize;
    uint16_t   reverseMaxPacketSize;
    uint16_t   reverseStandardDeviationPayloadLength;
    uint8_t    paddingRevStdDev[2];
} yaf_flowstats_t;

typedef struct yfTemplates_st {
    fbTemplate_t  *yaf_process_stats_tmpl;
    fbTemplate_t  *yaf_tombstone_tmpl;
    fbTemplate_t  *yaf_tombstone_access_tmpl;
    fbTemplate_t  *yaf_flowstats_tmpl;
    fbTemplate_t  *yaf_flowstats_tmpl_rev;
#if YAF_ENABLE_ENTROPY
    fbTemplate_t  *yaf_entropy_tmpl;
    fbTemplate_t  *yaf_entropy_tmpl_rev;
#endif
    fbTemplate_t  *yaf_tcp_tmpl;
    fbTemplate_t  *yaf_tcp_tmpl_rev;
    fbTemplate_t  *yaf_mac_tmpl;
    fbTemplate_t  *yaf_mptcp_tmpl;
#if YAF_ENABLE_P0F
    fbTemplate_t  *yaf_p0f_tmpl;
    fbTemplate_t  *yaf_p0f_tmpl_rev;
#endif
#if YAF_ENABLE_FPEXPORT
    fbTemplate_t  *yaf_fpexport_tmpl;
    fbTemplate_t  *yaf_fpexport_tmpl_rev;
#endif
#if YAF_ENABLE_PAYLOAD
    fbTemplate_t  *yaf_payload_tmpl;
    fbTemplate_t  *yaf_payload_tmpl_rev;
#endif
} yfTemplates_t;

static yfTemplates_t yaf_tmpl;

/* IPv6-mapped IPv4 address prefix */
static uint8_t       yaf_ip6map_pfx[12] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };

/* Full YAF flow record. */
typedef struct yaf_flow_full_st {
    uint64_t                   flowStartMilliseconds;
    uint64_t                   flowEndMilliseconds;
    uint64_t                   flowStartMicroseconds;
    uint64_t                   flowEndMicroseconds;
    uint64_t                   flowStartNanoseconds;
    uint64_t                   flowEndNanoseconds;

    uint64_t                   octetTotalCount;
    uint64_t                   reverseOctetTotalCount;
    uint64_t                   packetTotalCount;
    uint64_t                   reversePacketTotalCount;

    uint64_t                   octetDeltaCount;
    uint64_t                   reverseOctetDeltaCount;
    uint64_t                   packetDeltaCount;
    uint64_t                   reversePacketDeltaCount;

    uint8_t                    sourceIPv6Address[16];
    uint8_t                    destinationIPv6Address[16];
    uint32_t                   sourceIPv4Address;
    uint32_t                   destinationIPv4Address;

    uint16_t                   sourceTransportPort;
    uint16_t                   destinationTransportPort;
    uint16_t                   flowAttributes;
    uint16_t                   reverseFlowAttributes;
    uint8_t                    protocolIdentifier;
    uint8_t                    flowEndReason;
#if YAF_ENABLE_APPLABEL
    uint16_t                   silkAppLabel;
#else
    uint8_t                    paddingApplabel[2];
#endif
    uint32_t                   reverseFlowDeltaMilliseconds;
    uint64_t                   reverseFlowDeltaMicroseconds;
    uint64_t                   reverseFlowDeltaNanoseconds;

    /* TCP stuff for SiLK */
    uint32_t                   tcpSequenceNumber;
    uint32_t                   reverseTcpSequenceNumber;
    uint8_t                    initialTCPFlags;
    uint8_t                    unionTCPFlags;
    uint8_t                    reverseInitialTCPFlags;
    uint8_t                    reverseUnionTCPFlags;

    /* MAC Specific Info */
    uint16_t                   vlanId;
    uint16_t                   reverseVlanId;
    uint32_t                   ingressInterface;
    uint32_t                   egressInterface;

    /* VNI */
    uint32_t                   yafLayer2SegmentId;
    uint8_t                    paddingLayer2Segment[4];

    /* MPLS! */
    uint8_t                    ipClassOfService;
    uint8_t                    reverseIpClassOfService;
    uint8_t                    mpls_label1[3];
    uint8_t                    mpls_label2[3];
    uint8_t                    mpls_label3[3];
#if YAF_ENABLE_NDPI
    uint8_t                    paddingNpdi[1];
    uint16_t                   ndpi_master;
    uint16_t                   ndpi_sub;
#else
    uint8_t                    paddingNpdi[5];
#endif /* if YAF_ENABLE_NDPI */

    fbSubTemplateMultiList_t   subTemplateMultiList;
} yaf_flow_full_t;


/* "Extended" Flow record used by yafscii and yafcollect to read data.
 * The additional elements are defined in yaf_ext_flow_spec. */
typedef struct yfIpfixExtFlow_st {
    yaf_flow_full_t f;
    uint32_t        flowStartSeconds;
    uint32_t        flowEndSeconds;
    uint32_t        flowDurationMicroseconds;
    uint32_t        flowDurationMilliseconds;
    uint32_t        flowStartDeltaMicroseconds;
    uint32_t        flowEndDeltaMicroseconds;
} yfIpfixExtFlow_t;

typedef struct yaf_process_stats_st {
    uint32_t   observationDomainId;
    uint32_t   exportingProcessId;
    uint32_t   exporterIPv4Address;
    uint32_t   observationTimeSeconds;
    uint64_t   systemInitTimeMilliseconds;
    uint64_t   exportedFlowTotalCount;
    uint64_t   packetTotalCount;
    uint64_t   droppedPacketTotalCount;
    uint64_t   ignoredPacketTotalCount;
    uint64_t   notSentPacketTotalCount;
    uint32_t   expiredFragmentCount;
    uint32_t   assembledFragmentCount;
    uint32_t   flowTableFlushEvents;
    uint32_t   flowTablePeakCount;
    uint32_t   meanFlowRate;
    uint32_t   meanPacketRate;
} yaf_process_stats_t;

typedef struct yaf_tombstone_st {
    uint32_t              observationDomainId;
    uint32_t              exportingProcessId;
    uint16_t              exporterConfiguredId;
    uint8_t               paddingOctets[6];
    uint32_t              tombstoneId;
    uint32_t              observationTimeSeconds;
    fbSubTemplateList_t   accessList;
} yaf_tombstone_t;

typedef struct yaf_tombstone_access_st {
    uint32_t   certToolId;
    uint32_t   observationTimeSeconds;
} yaf_tombstone_access_t;


/**
 *  Checks the alignment of the record structs and aborts via g_error() if the
 *  elements are not aligned or there are gaps in the struct.
 *
 *  Ideally, all this magic would happen at compile time, but it doesn't
 *  currently, (can't really do it in C,) so we do it at run time.
 */
void
yfAlignmentCheck(
    void)
{
    size_t      prevOffset = 0;
    size_t      prevSize = 0;
    gboolean    verbose = FALSE;
    const char *env;

    env = getenv(YAF_ALIGNMENT_CHECK);
    if (env) {
        switch (*env) {
          case '\0':
          case '0':
          case 'F':
          case 'f':
            break;
          default:
            verbose = TRUE;
            break;
        }
    }

    /* required aligned of an fbVarfield_t */
#define ALIGNED_VARFIELD    DO_SIZE(fbVarfield_t, buf)

    /* required aligned of an fbBasicList_t */
#define ALIGNED_BASICLIST   DO_SIZE(fbBasicList_t, dataPtr)

    /* required aligned of an fbSubTemplateList_t */
#define ALIGNED_STL         DO_SIZE(fbSubTemplateList_t, dataPtr)

    /* required aligned of an fbSubTemplateMultiList_t */
#define ALIGNED_STML        DO_SIZE(fbSubTemplateMultiList_t, firstEntry)

    /* compute sizeof member `F_` in struct `S_` */
#define DO_SIZE(S_, F_) (SIZE_T_CAST)sizeof(((S_ *)(0))->F_)

    /* exit with an error that member `F_` is not aligned on an
     * `L_`-byte-boundary in struct `S_` */
#define ABORT_ALIGNMENT(S_, F_, L_)                                     \
    g_error(("alignment error in struct " #S_ " for member " #F_        \
             ", offset %#" SIZE_T_FORMATX ", size %" SIZE_T_FORMAT      \
             ", required alignment %" SIZE_T_FORMAT                     \
             ", overhang %" SIZE_T_FORMAT),                             \
            (SIZE_T_CAST)offsetof(S_, F_), DO_SIZE(S_, F_),             \
            L_, (SIZE_T_CAST)(offsetof(S_, F_) % L_))

    /* exit with an error that struct `S_` contains a gap before member `F_`
     * (which requires `L_` alignment) and that previous member ended at
     * offset `P_` */
#define ABORT_GAP(S_, F_, L_, P_)                                       \
    g_error(("gap error in struct " #S_ " for member " #F_              \
             ", offset %#" SIZE_T_FORMATX ", size %" SIZE_T_FORMAT      \
             ", required alignement %" SIZE_T_FORMAT                    \
             ", end previous member %#" SIZE_T_FORMATX                  \
             ", gap %" SIZE_T_FORMAT),                                  \
            (SIZE_T_CAST)offsetof(S_, F_), DO_SIZE(S_, F_),             \
            L_, (SIZE_T_CAST)(P_),                                      \
            (SIZE_T_CAST)(offsetof(S_, F_) - P_))

    /* check that member `F_` in struct `S_` is properly aligned and does not
     * contain a gap between the previous member and `F_`.  If `A_` is 0, the
     * offset of `F_` must be a multiple of its size.  If `A_` is any other
     * value, `F_` must be aligned on that size; specifically, octetArrays
     * should use an `A_` of 1 and structs should use DOSIZE() of their
     * largest member. */
#define RUN_CHECKS(S_, F_, A_)                                          \
    {                                                                   \
        SIZE_T_CAST align = ((0 != (A_)) ? (A_) : DO_SIZE(S_, F_));     \
        if (((offsetof(S_, F_) % align) != 0)) {                        \
            ABORT_ALIGNMENT(S_, F_, align);                             \
        }                                                               \
        if (offsetof(S_, F_) != (prevOffset + prevSize)) {              \
            ABORT_GAP(S_, F_, align, (prevOffset + prevSize));          \
        }                                                               \
        prevOffset = offsetof(S_, F_);                                  \
        prevSize = DO_SIZE(S_, F_);                                     \
        if (verbose) {                                                  \
            fprintf(stderr,                                             \
                    "%19s %40s %#6lx %4" PRId64 " %#6" PRIx64 "\n",     \
                    #S_, #F_,                                           \
                    offsetof(S_,F_), DO_SIZE(S_,F_),                    \
                    offsetof(S_,F_)+DO_SIZE(S_,F_));                    \
        }                                                               \
    }


    /*  yaf_flow_full_t  *****************************************  */

    RUN_CHECKS(yaf_flow_full_t, flowStartMilliseconds, 0);
    RUN_CHECKS(yaf_flow_full_t, flowEndMilliseconds, 0);
    RUN_CHECKS(yaf_flow_full_t, flowStartMicroseconds, 0);
    RUN_CHECKS(yaf_flow_full_t, flowEndMicroseconds, 0);
    RUN_CHECKS(yaf_flow_full_t, flowStartNanoseconds, 0);
    RUN_CHECKS(yaf_flow_full_t, flowEndNanoseconds, 0);

    RUN_CHECKS(yaf_flow_full_t, octetTotalCount, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseOctetTotalCount, 0);
    RUN_CHECKS(yaf_flow_full_t, packetTotalCount, 0);
    RUN_CHECKS(yaf_flow_full_t, reversePacketTotalCount, 0);

    RUN_CHECKS(yaf_flow_full_t, octetDeltaCount, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseOctetDeltaCount, 0);
    RUN_CHECKS(yaf_flow_full_t, packetDeltaCount, 0);
    RUN_CHECKS(yaf_flow_full_t, reversePacketDeltaCount, 0);

    RUN_CHECKS(yaf_flow_full_t, sourceIPv6Address, 1);
    RUN_CHECKS(yaf_flow_full_t, destinationIPv6Address, 1);
    RUN_CHECKS(yaf_flow_full_t, sourceIPv4Address, 0);
    RUN_CHECKS(yaf_flow_full_t, destinationIPv4Address, 0);

    RUN_CHECKS(yaf_flow_full_t, sourceTransportPort, 0);
    RUN_CHECKS(yaf_flow_full_t, destinationTransportPort, 0);
    RUN_CHECKS(yaf_flow_full_t, flowAttributes, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseFlowAttributes, 0);
    RUN_CHECKS(yaf_flow_full_t, protocolIdentifier, 0);
    RUN_CHECKS(yaf_flow_full_t, flowEndReason, 0);
#if YAF_ENABLE_APPLABEL
    RUN_CHECKS(yaf_flow_full_t, silkAppLabel, 0);
#else
    RUN_CHECKS(yaf_flow_full_t, paddingApplabel, 1);
#endif
    RUN_CHECKS(yaf_flow_full_t, reverseFlowDeltaMilliseconds, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseFlowDeltaMicroseconds, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseFlowDeltaNanoseconds, 0);

    /* TCP stuff for SiLK only! */
    RUN_CHECKS(yaf_flow_full_t, tcpSequenceNumber, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseTcpSequenceNumber, 0);
    RUN_CHECKS(yaf_flow_full_t, initialTCPFlags, 0);
    RUN_CHECKS(yaf_flow_full_t, unionTCPFlags, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseInitialTCPFlags, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseUnionTCPFlags, 0);

    RUN_CHECKS(yaf_flow_full_t, vlanId, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseVlanId, 0);
    RUN_CHECKS(yaf_flow_full_t, ingressInterface, 0);
    RUN_CHECKS(yaf_flow_full_t, egressInterface, 0);

    /* VNI */
    RUN_CHECKS(yaf_flow_full_t, yafLayer2SegmentId, 0);
    RUN_CHECKS(yaf_flow_full_t, paddingLayer2Segment, 1);

    RUN_CHECKS(yaf_flow_full_t, ipClassOfService, 0);
    RUN_CHECKS(yaf_flow_full_t, reverseIpClassOfService, 0);
    RUN_CHECKS(yaf_flow_full_t, mpls_label1, 1);
    RUN_CHECKS(yaf_flow_full_t, mpls_label2, 1);
    RUN_CHECKS(yaf_flow_full_t, mpls_label3, 1);

#if YAF_ENABLE_NDPI
    RUN_CHECKS(yaf_flow_full_t, paddingNpdi, 1);
    RUN_CHECKS(yaf_flow_full_t, ndpi_master, 0);
    RUN_CHECKS(yaf_flow_full_t, ndpi_sub, 0);
#else
    RUN_CHECKS(yaf_flow_full_t, paddingNpdi, 1);
#endif /* if YAF_ENABLE_NDPI */

    RUN_CHECKS(yaf_flow_full_t, subTemplateMultiList, ALIGNED_STML);


    /*  yfIpfixExtFlow_t  ****************************************  */

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfIpfixExtFlow_t, f, DO_SIZE(yaf_flow_full_t, octetTotalCount));
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartSeconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndSeconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowDurationMicroseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowDurationMilliseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartDeltaMicroseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndDeltaMicroseconds, 0);


    /*  yaf_process_stats_t  *************************************  */

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yaf_process_stats_t, observationDomainId, 0);
    RUN_CHECKS(yaf_process_stats_t, exportingProcessId, 0);
    RUN_CHECKS(yaf_process_stats_t, exporterIPv4Address, 0);
    RUN_CHECKS(yaf_process_stats_t, observationTimeSeconds, 0);
    RUN_CHECKS(yaf_process_stats_t, systemInitTimeMilliseconds, 0);
    RUN_CHECKS(yaf_process_stats_t, exportedFlowTotalCount, 0);
    RUN_CHECKS(yaf_process_stats_t, packetTotalCount, 0);
    RUN_CHECKS(yaf_process_stats_t, droppedPacketTotalCount, 0);
    RUN_CHECKS(yaf_process_stats_t, ignoredPacketTotalCount, 0);
    RUN_CHECKS(yaf_process_stats_t, notSentPacketTotalCount, 0);
    RUN_CHECKS(yaf_process_stats_t, expiredFragmentCount, 0);
    RUN_CHECKS(yaf_process_stats_t, assembledFragmentCount, 0);
    RUN_CHECKS(yaf_process_stats_t, flowTableFlushEvents, 0);
    RUN_CHECKS(yaf_process_stats_t, flowTablePeakCount, 0);
    RUN_CHECKS(yaf_process_stats_t, meanFlowRate, 0);
    RUN_CHECKS(yaf_process_stats_t, meanPacketRate, 0);


    /*  yaf_tombstone_t  *****************************************  */

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yaf_tombstone_t, observationDomainId, 0);
    RUN_CHECKS(yaf_tombstone_t, exportingProcessId, 0);
    RUN_CHECKS(yaf_tombstone_t, exporterConfiguredId, 0);
    RUN_CHECKS(yaf_tombstone_t, paddingOctets, 1);
    RUN_CHECKS(yaf_tombstone_t, tombstoneId, 0);
    RUN_CHECKS(yaf_tombstone_t, observationTimeSeconds, 0);
    RUN_CHECKS(yaf_tombstone_t, accessList, ALIGNED_STL);


    /*  yaf_tombstone_access_t  **********************************  */

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yaf_tombstone_access_t, certToolId, 0);
    RUN_CHECKS(yaf_tombstone_access_t, observationTimeSeconds, 0);


    /*  yaf_flowstats_t_t  ***************************************  */

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yaf_flowstats_t, dataByteCount, 0);
    RUN_CHECKS(yaf_flowstats_t, averageInterarrivalTime, 0);
    RUN_CHECKS(yaf_flowstats_t, standardDeviationInterarrivalTime, 0);
    RUN_CHECKS(yaf_flowstats_t, tcpUrgTotalCount, 0);
    RUN_CHECKS(yaf_flowstats_t, smallPacketCount, 0);
    RUN_CHECKS(yaf_flowstats_t, nonEmptyPacketCount, 0);
    RUN_CHECKS(yaf_flowstats_t, largePacketCount, 0);
    RUN_CHECKS(yaf_flowstats_t, firstNonEmptyPacketSize, 0);
    RUN_CHECKS(yaf_flowstats_t, maxPacketSize, 0);
    RUN_CHECKS(yaf_flowstats_t, standardDeviationPayloadLength, 0);
    RUN_CHECKS(yaf_flowstats_t, firstEightNonEmptyPacketDirections, 0);
    RUN_CHECKS(yaf_flowstats_t, paddingFirst8, 1);
    RUN_CHECKS(yaf_flowstats_t, reverseDataByteCount, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseAverageInterarrivalTime, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseStandardDeviationInterarrivalTime, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseTcpUrgTotalCount, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseSmallPacketCount, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseNonEmptyPacketCount, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseLargePacketCount, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseFirstNonEmptyPacketSize, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseMaxPacketSize, 0);
    RUN_CHECKS(yaf_flowstats_t, reverseStandardDeviationPayloadLength, 0);
    RUN_CHECKS(yaf_flowstats_t, paddingRevStdDev, 1);


#undef ABORT_ALIGNMENT
#undef ABORT_GAP
#undef ALIGNED_BASICLIST
#undef ALIGNED_STL
#undef ALIGNED_STML
#undef ALIGNED_VARFIELD
#undef DO_SIZE
#undef RUN_CHECKS
}


#if YAF_ENABLE_APPLABEL
static gboolean
findInApplabelArray(
    const yfContext_t  *ctx,
    uint16_t            applabel)
{
    size_t i;
    for (i = 0; i < ctx->cfg->payload_applabels_size; ++i) {
        if (ctx->cfg->payload_applabels[i] == applabel) {
            return TRUE;
        }
    }
    return FALSE;
}
#endif  /* YAF_ENABLE_APPLABEL */


/**
 * yfFlowPrepare
 *
 * initialize the state of a flow to be "clean" so that they
 * can be reused
 *
 */
void
yfFlowPrepare(
    yfFlow_t  *flow)
{
#if YAF_ENABLE_HOOKS
    unsigned int loop;
#endif

#if YAF_ENABLE_PAYLOAD
    flow->val.paylen = 0;
    flow->val.payload = NULL;
    flow->rval.paylen = 0;
    flow->rval.payload = NULL;
#endif /* if YAF_ENABLE_PAYLOAD */

#ifdef YAF_ENABLE_HOOKS
    for (loop = 0; loop < YAF_MAX_HOOKS; loop++) {
        flow->hfctx[loop] = 0x0;
    }
#endif

    memset(flow->sourceMacAddr, 0, ETHERNET_MAC_ADDR_LENGTH);
    memset(flow->destinationMacAddr, 0, ETHERNET_MAC_ADDR_LENGTH);
}


/**
 * yfFlowCleanup
 *
 * cleans up after a flow is no longer needed by deallocating
 * the dynamic memory allocated to the flow (think payload)
 *
 */
void
yfFlowCleanup(
    yfFlow_t  *flow)
{
#if YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        g_free(flow->val.payload);
        flow->val.payload = NULL;
    }

    if (flow->rval.payload) {
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfPayloadCopyIn
 *
 *
 *
 *
 */
static void
yfPayloadCopyIn(
    fbVarfield_t  *payvar,
    yfFlowVal_t   *val)
{
#if YAF_ENABLE_PAYLOAD
    if (payvar->len) {
        if (!val->payload) {
            val->payload = g_malloc0(payvar->len);
        } else {
            val->payload = g_realloc(val->payload, payvar->len);
        }
        val->paylen = payvar->len;
        memcpy(val->payload, payvar->buf, payvar->len);
    } else {
        if (val->payload) {g_free(val->payload);}
        val->payload = NULL;
        val->paylen = 0;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfInfoModel
 *
 *
 */
static fbInfoModel_t *
yfInfoModel(
    void)
{
    static fbInfoModel_t *yaf_model = NULL;
#if YAF_ENABLE_HOOKS
    fbInfoElement_t      *yaf_hook_elements = NULL;
#endif
    if (!yaf_model) {
        yaf_model = fbInfoModelAlloc();

        infomodelAddGlobalElements(yaf_model);

#if YAF_ENABLE_HOOKS
        yaf_hook_elements = yfHookGetInfoModel();
        if (yaf_hook_elements) {
            fbInfoModelAddElementArray(yaf_model, yaf_hook_elements);
        }
#endif /* if YAF_ENABLE_HOOKS */
    }

    return yaf_model;
}


/**
 * yfAddTemplate
 *
 *    Creates and returns a new template and adds it to the export session.
 *
 *    Allocates a new template.  If `reverse` is true, adds all elements from
 *    `spec` to the template and adds the `YAF_BIF` bit to `tid`; otherwise
 *    only adds the elements from `spec` whose flag value is 0.  Sets the
 *    scope of the template to `scope` if non-zero.  Adds the template as an
 *    export template to `session` with tid `tid` (or `tid | YAF_BIF` when
 *    `reverse` is TRUE), setting the name and description if metadata is
 *    enabled.  Returns the new template.  Sets `err` and returns NULL on
 *    error.
 */
static fbTemplate_t *
yfAddTemplate(
    fbSession_t          *session,
    fbInfoElementSpec_t  *spec,
    uint16_t              tid,
    uint16_t              scope,
    const gchar          *name,
    const gchar          *description,
    gboolean              reverse,
    GError              **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = fbTemplateAlloc(model);
    uint32_t       flags = 0;
    uint16_t       rtid = tid;

    if (reverse) {
        flags = YF_TMPL_SPEC_ALL_IE;
        rtid = tid | YTF_BIF;
    }

    /* g_debug("yaf: %x (%s), %d (%x)", tid, name, reverse, */
    /*         tid | (reverse ? YTF_BIF : 0)); */

    if (!fbTemplateAppendSpecArray(tmpl, spec, flags, err)) {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
    if (scope) {
        fbTemplateSetOptionsScope(tmpl, scope);
    }

#if YAF_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplateWithMetadata(session, FALSE, rtid,
                                          tmpl, name, description, err))
    {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#else /* if YAF_ENABLE_METADATA_EXPORT */
    (void)name;
    (void)description;
    if (!fbSessionAddTemplate(session, FALSE, rtid, tmpl, err)) {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#endif /* if YAF_ENABLE_METADATA_EXPORT */

    return tmpl;
}


/**
 * yfInitExporterSession
 *
 *
 */
static fbSession_t *
yfInitExporterSession(
    const yfConfig_t  *cfg,
    GError           **err)
{
    fbInfoModel_t    *model = yfInfoModel();
    fbTemplate_t     *tmpl = NULL;
    fbSession_t      *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* set observation domain */
    fbSessionSetDomain(session, cfg->odid);

    /* Create the full record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_full_spec, YTF_ALL, err)) {
        return NULL;
    }

    if (cfg->tmpl_metadata) {
#if YAF_ENABLE_METADATA_EXPORT
        if (!fbSessionSetMetadataExportElements(
                session, TRUE, YAF_TYPE_METADATA_TID, err))
        {
            return NULL;
        }
        if (!fbSessionSetMetadataExportTemplates(
                session, TRUE, YAF_TEMPLATE_METADATA_TID, err))
        {
            return NULL;
        }
#endif /* if YAF_ENABLE_METADATA_EXPORT */
    }

    /* Add the full record template to the internal session only */
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, err)) {
        return NULL;
    }

    /* Process Stats Options Template. Scope fields are exporterIPv4Address,
     * observationDomainId, and exportingProcessID */
    tmpl = yfAddTemplate(session, yaf_process_stats_spec,
                         YAF_PROCESS_STATS_TID, 3,
                         YAF_PROCESS_STATS_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    if (!fbSessionAddTemplate(
            session, TRUE, YAF_PROCESS_STATS_TID, tmpl, err))
    {
        return NULL;
    }
    yaf_tmpl.yaf_process_stats_tmpl = tmpl;

    /* Tombstone Record Template. Scope fields are exportingProcessID,
     * observationDomainId, and exporterConfiguredId */
    tmpl = yfAddTemplate(session, yaf_tombstone_spec, YAF_TOMBSTONE_TID, 3,
                         YAF_TOMBSTONE_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    if (!fbSessionAddTemplate(
            session, TRUE, YAF_TOMBSTONE_TID, tmpl, err))
    {
        return NULL;
    }
    yaf_tmpl.yaf_tombstone_tmpl = tmpl;

    /* Tombstone Access SubTemplate */
    tmpl = yfAddTemplate(session, yaf_tombstone_access_spec,
                         YAF_TOMBSTONE_ACCESS_TID, 0,
                         YAF_TOMBSTONE_ACCESS_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    if (!fbSessionAddTemplate(
            session, TRUE, YAF_TOMBSTONE_ACCESS_TID, tmpl, err))
    {
        return NULL;
    }
    yaf_tmpl.yaf_tombstone_access_tmpl = tmpl;

    /* Flow Stats Template */
    tmpl = yfAddTemplate(session, yaf_flowstats_spec, YAF_FLOWSTATS_TID, 0,
                         YAF_FLOWSTATS_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_flowstats_tmpl = tmpl;

    /* Reverse Flow Stats Template */
    tmpl = yfAddTemplate(session, yaf_flowstats_spec, YAF_FLOWSTATS_TID, 0,
                         YF_REVNAME(YAF_FLOWSTATS_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_flowstats_tmpl_rev = tmpl;

#if YAF_ENABLE_ENTROPY
    /* Entropy */
    tmpl = yfAddTemplate(session, yaf_entropy_spec, YAF_ENTROPY_TID, 0,
                         YAF_ENTROPY_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_entropy_tmpl = tmpl;

    /* Reverse Entropy */
    tmpl = yfAddTemplate(session, yaf_entropy_spec, YAF_ENTROPY_TID, 0,
                         YF_REVNAME(YAF_ENTROPY_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_entropy_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_ENTROPY */

    /* TCP */
    tmpl = yfAddTemplate(session, yaf_tcp_spec, YAF_TCP_TID, 0,
                         YAF_TCP_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_tcp_tmpl = tmpl;

    /* Reverse TCP */
    tmpl = yfAddTemplate(session, yaf_tcp_spec, YAF_TCP_TID, 0,
                         YF_REVNAME(YAF_TCP_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_tcp_tmpl_rev = tmpl;

    /* MAC */
    tmpl = yfAddTemplate(session, yaf_mac_spec, YAF_MAC_TID, 0,
                         YAF_MAC_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_mac_tmpl = tmpl;

    /* MPTCP */
    tmpl = yfAddTemplate(session, yaf_mptcp_spec, YAF_MPTCP_TID, 0,
                         YAF_MPTCP_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_mptcp_tmpl = tmpl;

#if YAF_ENABLE_P0F
    /* P0F */
    tmpl = yfAddTemplate(session, yaf_p0f_spec, YAF_P0F_TID, 0,
                         YAF_P0F_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_p0f_tmpl = tmpl;

    /* Reverse P0F */
    tmpl = yfAddTemplate(session, yaf_p0f_spec, YAF_P0F_TID, 0,
                         YF_REVNAME(YAF_P0F_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_p0f_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    /* Fingerprint Export */
    tmpl = yfAddTemplate(session, yaf_fpexport_spec, YAF_FPEXPORT_TID, 0,
                         YAF_FPEXPORT_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_fpexport_tmpl = tmpl;

    /* Reverse Fingerprint Export */
    tmpl = yfAddTemplate(session, yaf_fpexport_spec, YAF_FPEXPORT_TID, 0,
                         YF_REVNAME(YAF_FPEXPORT_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_fpexport_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
    /* Payload */
    tmpl = yfAddTemplate(session, yaf_payload_spec, YAF_PAYLOAD_TID, 0,
                         YAF_PAYLOAD_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_payload_tmpl = tmpl;

    /* Reverse Payload */
    tmpl = yfAddTemplate(session, yaf_payload_spec, YAF_PAYLOAD_TID, 0,
                         YF_REVNAME(YAF_PAYLOAD_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_payload_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_PAYLOAD */

#if YAF_ENABLE_HOOKS
    /*  Add the hook template fields if available  */
    if (!yfHookGetTemplate(session)) {
        g_debug("Hook Templates could not be added to the session");
    }
#endif /* if YAF_ENABLE_HOOKS */

    /* Done. Return the session. */
    return session;
}


#ifdef HAVE_SPREAD
/**
 * yfAddTemplateSpread
 *
 *
 */
static fbTemplate_t *
yfAddTemplateSpread(
    fbSession_t          *session,
    fbInfoElementSpec_t  *spec,
    char                **groups,
    uint16_t              tid,
    uint16_t              scope,
    const gchar          *name,
    const gchar          *description,
    gboolean              reverse,
    GError              **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = fbTemplateAlloc(model);
    uint32_t       flags = 0;
    uint16_t       rtid = tid;

    if (reverse) {
        flags = YF_TMPL_SPEC_ALL_IE;
        rtid = tid | YTF_BIF;
    }

    g_debug("yaf spread: %x (%s), %d (%x)", tid, name, reverse,
            tid | (reverse ? YTF_BIF : 0));
    if (!fbTemplateAppendSpecArray(tmpl, spec, flags, err)) {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
    if (scope) {
        fbTemplateSetOptionsScope(tmpl, scope);
    }

#if YAF_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplatesMulticastWithMetadata(
            session, groups, FALSE, rtid, tmpl,
            (char *)name, (char *)description, err))
    {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#else /* if YAF_ENABLE_METADATA_EXPORT */
    (void)name;
    (void)description;
    if (!fbSessionAddTemplatesMulticast(session, groups, FALSE,
                                        rtid, tmpl, err))
    {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#endif /* if YAF_ENABLE_METADATA_EXPORT */

    if (reverse) {
        if (!fbSessionAddTemplate(session, TRUE, tid, tmpl, err)) {
            return NULL;
        }
    }

    return tmpl;
}


/**
 * yfInitExporterSpreadSession
 *
 *
 */
static fbSession_t *
yfInitExporterSpreadSession(
    const yfConfig_t  *cfg,
    fBuf_t            *fbuf,
    fbSession_t       *session,
    fbSpreadParams_t  *spread,
    uint16_t          *spreadIndex,
    GError           **err)
{
    fbInfoModel_t    *model = yfInfoModel();
    fbTemplate_t     *tmpl = NULL;
#if YAF_ENABLE_HOOKS
    int               n;
#endif

    if (cfg->tmpl_metadata) {
#if YAF_ENABLE_METADATA_EXPORT
        if (!fbSessionSpreadSetMetadataExportElements(
                session, spread->groups, TRUE, YAF_TYPE_METADATA_TID, err))
        {
            return NULL;
        }
        if (!fbSessionSpreadSetMetadataExportTemplates(
                session, spread->groups, TRUE, YAF_TEMPLATE_METADATA_TID, err))
        {
            return NULL;
        }
#endif /* if YAF_ENABLE_METADATA_EXPORT */
    }

    /* Full record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_full_spec, YTF_ALL, err)) {
        return NULL;
    }

    /* Add the full record template to the internal session only */
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, err)) {
        return NULL;
    }

    /* Process Stats Options Template. Scope fields are exporterIPv4Address,
     * observationDomainId, and exportingProcessID */
    tmpl = yfAddTemplateSpread(session, yaf_process_stats_spec,
                               spread->groups, YAF_PROCESS_STATS_TID, 3,
                               YAF_PROCESS_STATS_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    if (!fbSessionAddTemplate(
            session, TRUE, YAF_PROCESS_STATS_TID, tmpl, err))
    {
        return NULL;
    }
    yaf_tmpl.yaf_process_stats_tmpl = tmpl;

    /* Tombstone Record Template. Scope fields are exportingProcessID,
     * observationDomainId, and exporterConfiguredId */
    tmpl = yfAddTemplateSpread(session, yaf_tombstone_spec, spread->groups,
                               YAF_TOMBSTONE_TID, 3,
                               YAF_TOMBSTONE_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    if (!fbSessionAddTemplate(
            session, TRUE, YAF_TOMBSTONE_TID, tmpl, err))
    {
        return NULL;
    }
    yaf_tmpl.yaf_tombstone_tmpl = tmpl;

    /* Tombstone Access SubTemplate */
    tmpl = yfAddTemplateSpread(session, yaf_tombstone_access_spec,
                               spread->groups, YAF_TOMBSTONE_ACCESS_TID, 0,
                               YAF_TOMBSTONE_ACCESS_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    if (!fbSessionAddTemplate(
            session, TRUE, YAF_TOMBSTONE_ACCESS_TID, tmpl, err))
    {
        return NULL;
    }
    yaf_tmpl.yaf_tombstone_access_tmpl = tmpl;

    /* Flow Stats Template */
    tmpl = yfAddTemplateSpread(session, yaf_flowstats_spec, spread->groups,
                               YAF_FLOWSTATS_TID, 0,
                               YAF_FLOWSTATS_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_flowstats_tmpl = tmpl;

    /* Reverse Flow Stats Template */
    tmpl = yfAddTemplateSpread(session, yaf_flowstats_spec, spread->groups,
                               YAF_FLOWSTATS_TID, 0,
                               YF_REVNAME(YAF_FLOWSTATS_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_flowstats_tmpl_rev = tmpl;

#if YAF_ENABLE_ENTROPY
    /* Entropy */
    tmpl = yfAddTemplateSpread(session, yaf_entropy_spec, spread->groups,
                               YAF_ENTROPY_TID, 0,
                               YAF_ENTROPY_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_entropy_tmpl = tmpl;

    /* Reverse Entropy */
    tmpl = yfAddTemplateSpread(session, yaf_entropy_spec, spread->groups,
                               YAF_ENTROPY_TID, 0,
                               YF_REVNAME(YAF_ENTROPY_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_entropy_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_ENTROPY */

    /* TCP */
    tmpl = yfAddTemplateSpread(session, yaf_tcp_spec, spread->groups,
                               YAF_TCP_TID, 0,
                               YAF_TCP_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_tcp_tmpl = tmpl;

    /* Reverse TCP */
    tmpl = yfAddTemplateSpread(session, yaf_tcp_spec, spread->groups,
                               YAF_TCP_TID, 0,
                               YF_REVNAME(YAF_TCP_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_tcp_tmpl_rev = tmpl;

    /* MAC */
    tmpl = yfAddTemplateSpread(session, yaf_mac_spec, spread->groups,
                               YAF_MAC_TID, 0, YAF_MAC_NAME,
                               NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_mac_tmpl = tmpl;

    /* MPTCP */
    tmpl = yfAddTemplateSpread(session, yaf_mptcp_spec, spread->groups,
                               YAF_MPTCP_TID, 0,
                               YAF_MPTCP_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_mptcp_tmpl = tmpl;

#if YAF_ENABLE_P0F
    /* P0F */
    tmpl = yfAddTemplateSpread(session, yaf_p0f_spec, spread->groups,
                               YAF_P0F_TID, 0,
                               YAF_P0F_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_p0f_tmpl = tmpl;

    /* Reverse P0F */
    tmpl = yfAddTemplateSpread(session, yaf_p0f_spec, spread->groups,
                               YAF_P0F_TID, 0,
                               YF_REVNAME(YAF_P0F_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_p0f_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    /* Fingerprint Export */
    tmpl = yfAddTemplateSpread(session, yaf_fpexport_spec, spread->groups,
                               YAF_FPEXPORT_TID, 0,
                               YAF_FPEXPORT_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_fpexport_tmpl = tmpl;

    /* Reverse Fingerprint Export */
    tmpl = yfAddTemplateSpread(session, yaf_fpexport_spec, spread->groups,
                               YAF_FPEXPORT_TID, 0,
                               YF_REVNAME(YAF_FPEXPORT_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_fpexport_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_FPEXPORT */

#if YAF_ENABLE_PAYLOAD
    /* Payload */
    tmpl = yfAddTemplateSpread(session, yaf_payload_spec, spread->groups,
                               YAF_PAYLOAD_TID, 0,
                               YAF_PAYLOAD_NAME, NULL, FALSE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_payload_tmpl = tmpl;

    /* Reverse Payload */
    tmpl = yfAddTemplateSpread(session, yaf_payload_spec, spread->groups,
                               YAF_PAYLOAD_TID, 0,
                               YF_REVNAME(YAF_PAYLOAD_NAME), NULL, TRUE, err);
    if (!tmpl) {
        return NULL;
    }
    yaf_tmpl.yaf_payload_tmpl_rev = tmpl;
#endif /* if YAF_ENABLE_PAYLOAD */

#if YAF_ENABLE_HOOKS
    /* Add the hook template fields if available  */
    for (n = 0; spread->groups[n]; ++n) {
        fBufSetSpreadExportGroup(fbuf, &(spread->groups[n]), 1, err);
        if (!yfHookGetTemplate(session)) {
            g_warning("Hook Templates could not be added to the session");
            return NULL;
        }
    }
#endif /* if YAF_ENABLE_HOOKS */

    /* Done. Return the session. */
    return session;
}


/**
 * yfWriterForSpread
 *
 *
 *
 */
fBuf_t *
yfWriterForSpread(
    fbSpreadParams_t  *spread,
    uint16_t          *spreadGroupIndex,
    const yfConfig_t  *yfConfig,
    GError           **err)
{
    fBuf_t           *fbuf = NULL;
    fbSession_t      *session;
    fbExporter_t     *exporter;
    fbInfoModel_t    *model = yfInfoModel();

    session = fbSessionAlloc(model);

    spread->session = session;

    fbSessionSetDomain(session, yfConfig->odid);

    exporter = fbExporterAllocSpread(spread);

    fbuf = fBufAllocForExport(session, exporter);

    /* If we are using spread group by - we need to multicast templates */
    if (spreadGroupIndex) {
        session = yfInitExporterSpreadSession(
            yfConfig, fbuf, session, spread, spreadGroupIndex, err);
    } else {
        /* initialize session and exporter */
        session = yfInitExporterSession(yfConfig, err);
    }
    if (!session) {
        goto err;
    }

    /* set observation domain */
    fbSessionSetDomain(session, yfConfig->odid);

    /* write YAF flow templates */

    if (!fbSessionExportTemplates(session, err)) { goto err;}
    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        goto err;
    }

    /* all done */
    return fbuf;

  err:
    if (fbuf) { fBufFree(fbuf);}

    return NULL;
}


/**
 * yfSetSpreadExportTemplate
 *
 *    The Spread version of yfSetExportTemplate().
 *
 *
 */
static gboolean
yfSetSpreadExportTemplate(
    fBuf_t            *fbuf,
    fbSpreadParams_t  *spread,
    uint32_t           flags,
    char             **groups,
    int                num_groups,
    GError           **err)
{
    fbSession_t  *session = NULL;
    fbTemplate_t *tmpl = NULL;
    uint16_t      tid = UINT16_MAX & flags;

    /* Try to set export template */

    if (fBufSetExportTemplate(fbuf, tid, err)) {
        return TRUE;
    }

    /* Check for error other than missing template */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    /* Okay. We have a missing template. Clear the error and try to load it. */
    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(yfInfoModel());

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_full_spec,
                                   (flags & (~YAF_FLOW_BASE_TID)), err))
    {
        return FALSE;
    }
    /* Multicast templates to all groups */
    if (!(fbSessionAddTemplatesMulticast(session, spread->groups, FALSE,
                                         tid, tmpl, err)))
    {
        return FALSE;
    }

    /* Now reset groups on the buffer */
    fBufSetSpreadExportGroup(fbuf, groups, num_groups, err);
    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}
#endif /* HAVE SPREAD */



/**
 * yfSetExportTemplate
 *
 *    Sets the export template to that whose ID is in the lower 16-bits of
 *    `flags`.  If the template does not exist, a new template for flow record
 *    export is created using the yaf_flow_full_spec[].
 *
 *    @param the TID to export or flags is used to select IEs from
 *    yaf_flow_full_spec[], may include elements whose presence is not
 *    reflected in the template ID.
 *
 *
 */
static gboolean
yfSetExportTemplate(
    fBuf_t    *fbuf,
    uint32_t   flags,
    GError   **err)
{
    fbSession_t  *session = NULL;
    fbTemplate_t *tmpl = NULL;
    uint16_t      tid = UINT16_MAX & flags;

#define TEMPLATE_NAME_INIT_LEN 32

    /* Try to set export template */
    if (fBufSetExportTemplate(fbuf, tid, err)) {
        return TRUE;
    }

    /* Check for error other than missing template */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    /* Okay. We have a missing template. Clear the error and try to load it. */
    g_clear_error(err);

    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(yfInfoModel());
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_full_spec,
                                   (flags & (~YAF_FLOW_BASE_TID)), err))
    {
        return FALSE;
    }

#if !YAF_ENABLE_METADATA_EXPORT

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        return FALSE;
    }

#else  /* #if !YAF_ENABLE_METADATA_EXPORT */

    if ((tid & YAF_FLOW_BASE_TID) != YAF_FLOW_BASE_TID) {
        /* No names to match; export without metadata */
        if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
            return FALSE;
        }
    } else {
        GString *template_name = g_string_sized_new(TEMPLATE_NAME_INIT_LEN);

        g_string_append(template_name, YAF_FLOW_FULL_NAME);

        if (tid & YTF_DELTA) {
            g_string_append(template_name, YTF_NAME_DELTA);
        } else {
            g_string_append(template_name, YTF_NAME_TOTAL);
        }

        if (tid & YTF_BIF) {
            g_string_append(template_name, YTF_NAME_BIF);
        }

        if (tid & YTF_SILK) {
            g_string_append(template_name, YTF_NAME_SILK);
        }

        if (tid & YTF_MPLS) {
            g_string_append(template_name, YTF_NAME_MPLS);
        }

        if (tid & YTF_FLE) {
            g_string_append(template_name, YTF_NAME_FLE);
        } else {
            g_string_append(template_name, YTF_NAME_RLE);
        }

        if (tid & YTF_IP6) {
            g_string_append(template_name, YTF_NAME_IP6);
        } else {
            g_string_append(template_name, YTF_NAME_IP4);
        }

        if (tid & YTF_DAGIF) {
            g_string_append(template_name, YTF_NAME_DAGIF);
        }
        if (tid & YTF_NDPI) {
            g_string_append(template_name, YTF_NAME_NDPI);
        }

        if (0 != (flags & (YTF_MICRO | YTF_NANO))) {
            if (flags & YTF_MILLI) {
                g_string_append(template_name, YTF_NAME_MILLI);
            }
            if (flags & YTF_MICRO) {
                g_string_append(template_name, YTF_NAME_MICRO);
            }
            if (flags & YTF_NANO) {
                g_string_append(template_name, YTF_NAME_NANO);
            }
        }

        /* printf("yfSetExportTemplate: %x, %s\n", tid, template_name->str); */

        if (!fbSessionAddTemplateWithMetadata(session, FALSE, tid, tmpl,
                                              template_name->str, NULL, err))
        {
            g_string_free(template_name, TRUE);
            return FALSE;
        }
        g_string_free(template_name, TRUE);
    }

#endif /* #else of #if !YAF_ENABLE_METADATA_EXPORT */

    /*g_debug("adding new template %02x", tid);*/

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}


/**
 * yfWriterForFile
 *
 *
 */
fBuf_t *
yfWriterForFile(
    const char        *path,
    const yfConfig_t  *yfConfig,
    GError           **err)
{
    fBuf_t       *fbuf = NULL;
    fbExporter_t *exporter;
    fbSession_t  *session;

    /* Allocate an exporter for the file */
    exporter = fbExporterAllocFile(path);

    /* Create a new buffer */
    session = yfInitExporterSession(yfConfig, err);
    if (!session) {
        goto err;
    }

    fbuf = fBufAllocForExport(session, exporter);

    /* write YAF flow templates */
    if (!fbSessionExportTemplates(session, err)) {goto err;}

    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {goto err;}

    /* all done */
    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfWriterForFP
 *
 *
 *
 */
fBuf_t *
yfWriterForFP(
    FILE              *fp,
    const yfConfig_t  *yfConfig,
    GError           **err)
{
    fBuf_t       *fbuf = NULL;
    fbExporter_t *exporter;
    fbSession_t  *session;

    /* Allocate an exporter for the file */
    exporter = fbExporterAllocFP(fp);

    /* Create a new buffer */
    session = yfInitExporterSession(yfConfig, err);
    if (!session) {
        goto err;
    }
    fbuf = fBufAllocForExport(session, exporter);

    /* write YAF flow templates */

    if (!fbSessionExportTemplates(session, err)) {goto err;}

    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {goto err;}

    /* all done */
    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfWriterForSpec
 *
 *
 *
 */
fBuf_t *
yfWriterForSpec(
    fbConnSpec_t      *spec,
    const yfConfig_t  *yfConfig,
    GError           **err)
{
    fBuf_t           *fbuf = NULL;
    fbSession_t      *session;
    fbExporter_t     *exporter;

    /* initialize session and exporter */
    session = yfInitExporterSession(yfConfig, err);
    if (!session) {
        goto err;
    }

    exporter = fbExporterAllocNet(spec);
    fbuf = fBufAllocForExport(session, exporter);

    /* set observation domain */
    fbSessionSetDomain(session, yfConfig->odid);

    /* write YAF flow templates */
    if (!fbSessionExportTemplates(session, err)) {goto err;}

    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {goto err;}

    /* all done */
    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfWriteOptionsDataFlows
 *
 *
 */
gboolean
yfWriteOptionsDataFlows(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err)
{
    yfContext_t *ctx = (yfContext_t *)yfContext;

    /* Call yfWriteStatsFlow() in no-output mode so the stats can be written
     * to the log file */
    if (!yfWriteStatsFlow(yfContext, pcap_drop, timer, err)) {
        return FALSE;
    }

    if (!ctx->cfg->no_output) {
        if (!ctx->cfg->no_tombstone
            && !yfWriteTombstoneFlow(yfContext, err))
        {
            return FALSE;
        }
        if (ctx->fbuf
            && !fBufEmit(ctx->fbuf, err))
        {
            return FALSE;
        }
    }
    return TRUE;
}


/**
 * yfWriteStatsFlow
 *
 *
 */
gboolean
yfWriteStatsFlow(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err)
{
    yaf_process_stats_t  rec;
    yfContext_t    *ctx = (yfContext_t *)yfContext;
    fBuf_t         *fbuf = ctx->fbuf;
    uint32_t        mask = 0x000000FF;
    char            buf[200];
    uint32_t        total_frags = 0;
    static struct hostent *host;
    static uint32_t host_ip = 0;

    yfGetFlowTabStats(ctx->flowtab, &(rec.packetTotalCount),
                      &(rec.exportedFlowTotalCount),
                      &(rec.notSentPacketTotalCount),
                      &(rec.flowTablePeakCount), &(rec.flowTableFlushEvents));
    if (ctx->fragtab) {
        yfGetFragTabStats(ctx->fragtab, &(rec.expiredFragmentCount),
                          &(rec.assembledFragmentCount), &total_frags);
    } else {
        rec.expiredFragmentCount = 0;
        rec.assembledFragmentCount = 0;
    }

    /* Get IP of sensor for scope */
    if (!host) {
        gethostname(buf, sizeof(buf));
        host = (struct hostent *)gethostbyname(buf);
        if (host) {
            host_ip = (host->h_addr[0] & mask) << 24;
            host_ip |= (host->h_addr[1] & mask) << 16;
            host_ip |= (host->h_addr[2] & mask) << 8;
            host_ip |= (host->h_addr[3] & mask);
        }
    }

    /* Rejected/Ignored Packet Total Count from decode.c */
    rec.ignoredPacketTotalCount = yfGetDecodeStats(ctx->dectx);

    /* Dropped packets - from yafcap.c & libpcap */
    rec.droppedPacketTotalCount = pcap_drop;
    rec.exporterIPv4Address = host_ip;

    rec.observationDomainId = ctx->cfg->odid;
    rec.exportingProcessId = getpid();
    rec.observationTimeSeconds = (int)time(NULL);

    rec.meanFlowRate =
        rec.exportedFlowTotalCount / g_timer_elapsed(timer, NULL);
    rec.meanPacketRate = rec.packetTotalCount / g_timer_elapsed(timer, NULL);

    rec.systemInitTimeMilliseconds = yfTimeToMilli(ctx->yaf_start_time);

    g_debug("YAF statistics: Flows: %" PRIu64 " Packets: %" PRIu64
            " Dropped: %" PRIu64 " Ignored: %" PRIu64
            " Out of Sequence: %" PRIu64
            " Expired Frags: %u Assembled Frags: %u",
            rec.exportedFlowTotalCount, rec.packetTotalCount,
            rec.droppedPacketTotalCount, rec.ignoredPacketTotalCount,
            rec.notSentPacketTotalCount, rec.expiredFragmentCount,
            rec.assembledFragmentCount);

    if (!fbuf) {
        if (ctx->cfg->no_output) {
            return TRUE;
        }
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Writing Stats Message: No fbuf [output] Available");
        return FALSE;
    }

    /* Set Internal Template for Buffer to Options TID */
    if (!fBufSetInternalTemplate(fbuf, YAF_PROCESS_STATS_TID, err)) {
        return FALSE;
    }

#if HAVE_SPREAD
    if (ctx->cfg->spreadGroupIndex) {
        fBufSetSpreadExportGroup(fbuf, ctx->cfg->spreadparams.groups,
                                 ctx->cfg->numSpreadGroups, err);
    }
#endif /* if HAVE_SPREAD */

    /* Set Export Template for Buffer to Options TMPL */
    if (!yfSetExportTemplate(fbuf, YAF_PROCESS_STATS_TID, err)) {
        return FALSE;
    }

    /* Append Record */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

    /* emit buffer */
    if (!fBufEmit(fbuf, err)) {
        return FALSE;
    }

    /* Set Internal TID Back to Flow Record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * yfWriteTombstoneFlow
 *
 *
 */
gboolean
yfWriteTombstoneFlow(
    void    *yfContext,
    GError **err)
{
    yaf_tombstone_t         rec;
    yfContext_t            *ctx = (yfContext_t *)yfContext;
    fBuf_t                 *fbuf = ctx->fbuf;
    static uint32_t         tombstoneId = 0;
    uint32_t                currentTime;
    yaf_tombstone_access_t *accessListPtr;

    if (!fbuf) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Writing Stats Message: No fbuf [output] Available");
        return FALSE;
    }

    /* Set Internal Template for Buffer to Options TID */
    if (!fBufSetInternalTemplate(fbuf, YAF_TOMBSTONE_TID, err)) {
        return FALSE;
    }

#if HAVE_SPREAD
    if (ctx->cfg->spreadGroupIndex) {
        fBufSetSpreadExportGroup(fbuf, ctx->cfg->spreadparams.groups,
                                 ctx->cfg->numSpreadGroups, err);
    }
#endif /* if HAVE_SPREAD */

    /* Set Export Template for Buffer to Options TMPL */
    if (!yfSetExportTemplate(fbuf, YAF_TOMBSTONE_TID, err)) {
        return FALSE;
    }

    memset(rec.paddingOctets, 0, sizeof(rec.paddingOctets));
    currentTime = (uint32_t)time(NULL);
    rec.tombstoneId = tombstoneId++;
    rec.exporterConfiguredId = ctx->cfg->tombstone_configured_id;
    rec.exportingProcessId = getpid();
    rec.observationTimeSeconds = currentTime;
    rec.observationDomainId = ctx->cfg->odid;
    accessListPtr = (yaf_tombstone_access_t *)fbSubTemplateListInit(
        &(rec.accessList), 0,
        YAF_TOMBSTONE_ACCESS_TID,
        yaf_tmpl.yaf_tombstone_access_tmpl, 1);

    accessListPtr->certToolId = 1;
    accessListPtr->observationTimeSeconds = currentTime;

    /* Append Record */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

    /* emit buffer */
    if (!fBufEmit(fbuf, err)) {
        return FALSE;
    }

    g_message("Sent Tombstone record: observationDomain:%d, "
              "exporterId:%d:%d, tombstoneId: %d",
              rec.observationDomainId, rec.exporterConfiguredId,
              rec.exportingProcessId, rec.tombstoneId);

    fbSubTemplateListClear(&(rec.accessList));

    /* Set Internal TID Back to Flow Record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * yfWriteFlow
 *
 *
 *
 */
gboolean
yfWriteFlow(
    void      *yfContext,
    yfFlow_t  *flow,
    GError   **err)
{
    yaf_flow_full_t rec;
    uint32_t        wtid;
    /* etid is the bi-flow indicator for STML templates */
    uint16_t        etid = 0;
    fbSubTemplateMultiListEntry_t *stml = NULL;
    /* number of STML entries */
    int             tmplcount = 0;
    gboolean        ok;
    gboolean        stats = FALSE;
    int             loop, count;
    yfContext_t      *ctx = (yfContext_t *)yfContext;
    fBuf_t           *fbuf = ctx->fbuf;
    yaf_flowstats_t  *statsflow = NULL;

    if (ctx->cfg->no_output) {
        return TRUE;
    }

    /* Fill the record and set the appropriate flags on the basic template */
    wtid = YAF_FLOW_BASE_TID;

    /*
     *  Handle the timestamps:
     *
     *  If millisec is present, the TID does not reflect whether additional
     *  timestamps are present; this is for maximum compatibility with older
     *  downstream readers.
     *
     *  Otherwise, the TID reflects nanoseconds if present (regardless of
     *  microsec setting); else it specifies that only microseconds are
     *  available.
     */
    if (yfRecordTimeIEBitCheck(ctx->cfg->time_elements, YF_TIME_IE_MILLI)) {
        rec.flowStartMilliseconds = yfTimeToMilli(flow->stime);
        rec.flowEndMilliseconds = yfTimeToMilli(flow->etime);
        rec.reverseFlowDeltaMilliseconds = yfDiffTimeToMilli(flow->rdtime);
        wtid |= YTF_MILLI;
    }
    if (yfRecordTimeIEBitCheck(ctx->cfg->time_elements, YF_TIME_IE_MICRO)) {
        yfTimeToNTP(&rec.flowStartMicroseconds, flow->stime);
        yfTimeToNTP(&rec.flowEndMicroseconds, flow->etime);
        rec.flowStartMicroseconds &= YF_TIME_NTP_USEC_MASK;
        rec.flowEndMicroseconds &= YF_TIME_NTP_USEC_MASK;
        rec.reverseFlowDeltaMicroseconds = yfDiffTimeToMicro(flow->rdtime);
        wtid |= YTF_MICRO;
        if (yfRecordTimeIEBitSet(YF_TIME_IE_MICRO) == ctx->cfg->time_elements) {
            /* only microseconds are present; reflect this in the TID */
            wtid |= YTF_MICRO_ONLY;
        }
    }
    if (yfRecordTimeIEBitCheck(ctx->cfg->time_elements, YF_TIME_IE_NANO)) {
        yfTimeToNTP(&rec.flowStartNanoseconds, flow->stime);
        yfTimeToNTP(&rec.flowEndNanoseconds, flow->etime);
        rec.reverseFlowDeltaNanoseconds = yfDiffTimeToNano(flow->rdtime);
        wtid |= YTF_NANO;
        if (!yfRecordTimeIEBitCheck(ctx->cfg->time_elements, YF_TIME_IE_MILLI))
        {
            /* Milliseconds are not present; let the TID reflect the presence
             * of Nanoseconds */
            wtid |= YTF_NANO_NOMIL;
        }
    }

    /* copy addresses */
    if (ctx->cfg->force_ip6 && (flow->key.version == 4)) {
        memcpy(rec.sourceIPv6Address, yaf_ip6map_pfx,
               sizeof(yaf_ip6map_pfx));
        *(uint32_t *)(&(rec.sourceIPv6Address[sizeof(yaf_ip6map_pfx)])) =
            g_htonl(flow->key.addr.v4.sip);
        memcpy(rec.destinationIPv6Address, yaf_ip6map_pfx,
               sizeof(yaf_ip6map_pfx));
        *(uint32_t *)(&(rec.destinationIPv6Address[sizeof(yaf_ip6map_pfx)])) =
            g_htonl(flow->key.addr.v4.dip);
        wtid |= YTF_IP6;
    } else if (flow->key.version == 4) {
        rec.sourceIPv4Address = flow->key.addr.v4.sip;
        rec.destinationIPv4Address = flow->key.addr.v4.dip;
        wtid |= YTF_IP4;
    } else if (flow->key.version == 6) {
        memcpy(rec.sourceIPv6Address, flow->key.addr.v6.sip,
               sizeof(rec.sourceIPv6Address));
        memcpy(rec.destinationIPv6Address, flow->key.addr.v6.dip,
               sizeof(rec.destinationIPv6Address));
        wtid |= YTF_IP6;
    } else {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "Illegal IP version %u", flow->key.version);
    }

    rec.vlanId = flow->val.vlan;
    rec.reverseVlanId = flow->rval.vlan;

    /* Copy key and attributes */
    rec.sourceTransportPort = flow->key.sp;
    rec.destinationTransportPort = flow->key.dp;
    rec.flowAttributes = flow->val.attributes;
    rec.reverseFlowAttributes = flow->rval.attributes;
    rec.protocolIdentifier = flow->key.proto;
    rec.flowEndReason = flow->reason;

    /* Copy counters, choosing Delta or Total counters and whether to use
     * reduced-length encoding */
    if (ctx->cfg->deltaMode) {
        rec.octetDeltaCount = flow->val.oct;
        rec.reverseOctetDeltaCount = flow->rval.oct;
        rec.packetDeltaCount = flow->val.pkt;
        rec.reversePacketDeltaCount = flow->rval.pkt;
        wtid |= YTF_DELTA;
    } else {
        rec.octetTotalCount = flow->val.oct;
        rec.reverseOctetTotalCount = flow->rval.oct;
        rec.packetTotalCount = flow->val.pkt;
        rec.reversePacketTotalCount = flow->rval.pkt;
        wtid |= YTF_TOTAL;
    }
    if (flow->val.oct < YAF_RLEMAX && flow->rval.oct < YAF_RLEMAX &&
        flow->val.pkt < YAF_RLEMAX && flow->rval.pkt < YAF_RLEMAX)
    {
        wtid |= YTF_RLE;
    } else {
        wtid |= YTF_FLE;
    }

    /* Enable Bi-Flow if reverse packets */
    if (flow->rval.pkt) {
        wtid |= YTF_BIF;
        etid = YTF_BIF;
    }

    /* VNI */
    if (ctx->cfg->layer2IdExportMode) {
        rec.yafLayer2SegmentId = flow->key.layer2Id;
        wtid |= YTF_VNI;
    }

    /* Type Of Service */
    rec.ipClassOfService = flow->key.tos;
    rec.reverseIpClassOfService = flow->rtos;

    /*  Interfaces: If SEPARATE_INTERFACES is TRUE, use the interfaces from
     *  flow->val; else if DAG_SEPARATE_INTERFACES is TRUE, use the interfaces
     *  from flow->key; otherwise use those from the command line.
     *
     *  Export the interfaces if they are non-zero or if exportInterface is
     *  set (which requires BIVIO or the --export-interfaces option which is
     *  only available when an INTERFACES #define is active)
     */
#if YAF_ENABLE_SEPARATE_INTERFACES
    rec.ingressInterface = flow->val.netIf;
    if (flow->rval.pkt) {
        rec.egressInterface = flow->rval.netIf;
    } else {
        rec.egressInterface = flow->val.netIf | 0x100;
    }
#elif YAF_ENABLE_DAG_SEPARATE_INTERFACES
    rec.ingressInterface = flow->key.netIf;
    rec.egressInterface  = flow->key.netIf | 0x100;
#else
    rec.ingressInterface = ctx->cfg->ingressInt;
    rec.egressInterface = ctx->cfg->egressInt;
#endif  /* #else of #if YAF_ENABLE_SEPARATE_INTERFACES */

    if (rec.ingressInterface || rec.egressInterface
        || ctx->cfg->exportInterface)
    {
        wtid |= YTF_DAGIF;
    }

#if YAF_ENABLE_APPLABEL
    rec.silkAppLabel = flow->appLabel;
#endif

#if YAF_ENABLE_NDPI
    rec.ndpi_master = flow->ndpi_master;
    rec.ndpi_sub = flow->ndpi_sub;
    wtid |= YTF_NDPI;
#endif

#if YAF_MPLS
    /* since the mpls label isn't defined as an integer in fixbuf, it's
     * not endian-converted on transcode, so we fix that here */
    /*    temp = htonl(flow->mpls->mpls_label[0]) >> 8;*/
    memcpy(rec.mpls_label1, &(flow->mpls->mpls_label[0]), 3);
    /*temp = htonl(flow->mpls->mpls_label[1]) >> 8;*/
    memcpy(rec.mpls_label2, &(flow->mpls->mpls_label[1]), 3);
    /*temp = htonl(flow->mpls->mpls_label[2]) >> 8;*/
    memcpy(rec.mpls_label3, &(flow->mpls->mpls_label[2]), 3);
    wtid |= YTF_MPLS;
#endif /* if YAF_MPLS */

    if (rec.protocolIdentifier == YF_PROTO_TCP) {
        if (ctx->cfg->silkmode) {
            rec.tcpSequenceNumber = flow->val.isn;
            rec.reverseTcpSequenceNumber = flow->rval.isn;
            rec.initialTCPFlags = flow->val.iflags;
            rec.reverseInitialTCPFlags = flow->rval.iflags;
            rec.unionTCPFlags = flow->val.uflags;
            rec.reverseUnionTCPFlags = flow->rval.uflags;
            wtid |= YTF_SILK;
        } else {
            tmplcount++;
        }
    }

#if HAVE_SPREAD
#define  YF_SPREAD_NUM_GROUPS  25
    char     *spgroups[YF_SPREAD_NUM_GROUPS];
    uint16_t  spGroupBy;
    int       numGroups;
    int       i;

    /* Get the value to group-by */
    switch (ctx->cfg->spreadGroupby) {
#if YAF_ENABLE_APPLABEL
      case YAF_SPREAD_GROUPBY_APPLABEL:
        spGroupBy = rec.silkAppLabel;
        break;
#endif  /* YAF_ENABLE_APPLABEL */
      case YAF_SPREAD_GROUPBY_DESTPORT:
        spGroupBy = rec.destinationTransportPort;
        break;
      case YAF_SPREAD_GROUPBY_VLANID:
        spGroupBy = rec.vlanId;
        break;
      case YAF_SPREAD_GROUPBY_PROTOCOL:
        spGroupBy = (uint16_t)rec.protocolIdentifier;
        break;
      case YAF_SPREAD_GROUPBY_IPVERSION:
        spGroupBy = (uint16_t)flow->key.version;
        break;
      default:
        spGroupBy = 0;
        break;
    }

    /* Find out which groups we need to send this flow to */
    numGroups = 0;
    for (i = 0; i < ctx->cfg->numSpreadGroups; i++) {
        if (ctx->cfg->spreadGroupIndex[i] == spGroupBy ||
            ctx->cfg->spreadGroupIndex[i] == 0)
        {
            spgroups[numGroups] = ctx->cfg->spreadparams.groups[i];
            ++numGroups;
            if (YF_SPREAD_NUM_GROUPS == numGroups) {
                break;
            }
        }
    }

    /* If we are selectively setting groups to send this to - set groups
     * on the export buffer */
    if (ctx->cfg->spreadGroupIndex) {
        if (0 == numGroups) {
            return TRUE;
        }
        fBufSetSpreadExportGroup(fbuf, spgroups, numGroups, err);
        /* Now make sure the groups have those templates */
        if (!yfSetSpreadExportTemplate(fbuf, &ctx->cfg->spreadparams,
                                       wtid, spgroups, numGroups, err))
        {
            return FALSE;
        }
    } else
#endif /* if HAVE_SPREAD */
    {
        /* Either there is no Spread support or Spread is sending to all
         * groups */
        if (!yfSetExportTemplate(fbuf, wtid, err)) {
            return FALSE;
        }
    }

    if (ctx->cfg->macmode) {
        tmplcount++;
    }

    if (ctx->cfg->flowstatsmode && flow->val.stats) {
        if (flow->val.stats->payoct || flow->rval.stats) {
            tmplcount++;
            stats = TRUE;
        }
    }

    if ((flow->mptcp.token)) {
        tmplcount++;
    }

#if YAF_ENABLE_PAYLOAD
    /* point to payload */
    if ((0 < ctx->cfg->export_payload)
        && (flow->val.paylen || flow->rval.paylen)
#if YAF_ENABLE_APPLABEL
        && (NULL == ctx->cfg->payload_applabels
            || findInApplabelArray(ctx, flow->appLabel))
#endif
       )
    {
        tmplcount++;
    }
    /* copy payload-derived information */

#if YAF_ENABLE_HOOKS
    tmplcount += yfHookGetTemplateCount(flow);
#endif

#if YAF_ENABLE_ENTROPY
    if (flow->val.entropy || flow->rval.entropy) {
        tmplcount++;
    }
#endif

#if YAF_ENABLE_P0F
    if (flow->val.osname || flow->val.osver ||
        flow->rval.osname || flow->rval.osver ||
        flow->val.osFingerPrint || flow->rval.osFingerPrint)
    {
        tmplcount++;
    }
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    if (flow->val.firstPacket || flow->rval.firstPacket ||
        flow->val.secondPacket)
    {
        tmplcount++;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

#endif /* if YAF_ENABLE_PAYLOAD */

    /* Initialize SubTemplateMultiList with number of templates we are to add*/
    fbSubTemplateMultiListInit(&(rec.subTemplateMultiList), 3, tmplcount);

    /* Add TCP Template - IF TCP Flow and SiLK Mode is OFF */
    if (flow->key.proto == YF_PROTO_TCP && !ctx->cfg->silkmode) {
        yaf_tcp_t      *tcprec;
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            tcprec = (yaf_tcp_t *)FBSTMLINIT(stml,
                                             (YAF_TCP_TID | etid),
                                             yaf_tmpl.yaf_tcp_tmpl_rev);
            tcprec->reverseTcpSequenceNumber = flow->rval.isn;
            tcprec->reverseInitialTCPFlags = flow->rval.iflags;
            tcprec->reverseUnionTCPFlags = flow->rval.uflags;
        } else {
            tcprec = (yaf_tcp_t *)FBSTMLINIT(stml, YAF_TCP_TID,
                                             yaf_tmpl.yaf_tcp_tmpl);
        }
        tcprec->tcpSequenceNumber = flow->val.isn;
        tcprec->initialTCPFlags = flow->val.iflags;
        tcprec->unionTCPFlags = flow->val.uflags;
        tmplcount--;
    }

    /* Add MAC Addresses */
    if (ctx->cfg->macmode) {
        yaf_mac_t      *macrec;
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        macrec = (yaf_mac_t *)FBSTMLINIT(stml, YAF_MAC_TID,
                                         yaf_tmpl.yaf_mac_tmpl);
        memcpy(macrec->sourceMacAddress, flow->sourceMacAddr,
               ETHERNET_MAC_ADDR_LENGTH);
        memcpy(macrec->destinationMacAddress, flow->destinationMacAddr,
               ETHERNET_MAC_ADDR_LENGTH);
        tmplcount--;
    }

    if (flow->mptcp.token) {
        yaf_mptcp_t    *mptcprec;
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        mptcprec = (yaf_mptcp_t *)FBSTMLINIT(stml, YAF_MPTCP_TID,
                                             yaf_tmpl.yaf_mptcp_tmpl);
        memcpy(mptcprec, &(flow->mptcp), sizeof(yaf_mptcp_t));
        tmplcount--;
    }

#if YAF_ENABLE_PAYLOAD
    /* Add Payload Template */
    if ((0 < ctx->cfg->export_payload)
        && (flow->val.paylen || flow->rval.paylen)
#if YAF_ENABLE_APPLABEL
        && (NULL == ctx->cfg->payload_applabels
            || findInApplabelArray(ctx, flow->appLabel))
#endif
       )
    {
        yaf_payload_t    *payrec;
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            payrec = (yaf_payload_t *)FBSTMLINIT(stml,
                                                 YAF_PAYLOAD_TID | etid,
                                                 yaf_tmpl.yaf_payload_tmpl_rev);
            payrec->reversePayload.len = MIN(flow->rval.paylen,
                                             ctx->cfg->export_payload);
            payrec->reversePayload.buf = flow->rval.payload;
        } else {
            payrec = (yaf_payload_t *)FBSTMLINIT(stml,
                                                 YAF_PAYLOAD_TID,
                                                 yaf_tmpl.yaf_payload_tmpl);
        }
        payrec->payload.len = MIN(flow->val.paylen, ctx->cfg->export_payload);
        payrec->payload.buf = flow->val.payload;
        tmplcount--;
    }
#endif /* if YAF_ENABLE_PAYLOAD */

#if YAF_ENABLE_ENTROPY
    /* Add Entropy Template */
    if (flow->val.entropy || flow->rval.entropy) {
        yaf_entropy_t    *entropyrec;
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            entropyrec = (yaf_entropy_t *)FBSTMLINIT(
                stml, YAF_ENTROPY_TID | etid, yaf_tmpl.
                yaf_entropy_tmpl_rev);
            entropyrec->reverseEntropy = flow->rval.entropy;
        } else {
            entropyrec = (yaf_entropy_t *)FBSTMLINIT(
                stml, YAF_ENTROPY_TID, yaf_tmpl.yaf_entropy_tmpl);
        }
        entropyrec->entropy = flow->val.entropy;
        tmplcount--;
    }
#endif /* if YAF_ENABLE_ENTROPY */

#if YAF_ENABLE_P0F
    /* Add P0F Template */
    if (flow->val.osname || flow->val.osver || flow->rval.osname ||
        flow->rval.osver || flow->val.osFingerPrint || flow->rval.osFingerPrint)
    {
        yaf_p0f_t        *p0frec;
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            p0frec = (yaf_p0f_t *)FBSTMLINIT(stml,
                                             YAF_P0F_TID | etid,
                                             yaf_tmpl.yaf_p0f_tmpl_rev);
            if (NULL != flow->rval.osname) {
                p0frec->reverseOsName.buf = (uint8_t *)flow->rval.osname;
                p0frec->reverseOsName.len = strlen(flow->rval.osname);
            } else {
                p0frec->reverseOsName.len = 0;
            }
            if (NULL != flow->rval.osver) {
                p0frec->reverseOsVersion.buf = (uint8_t *)flow->rval.osver;
                p0frec->reverseOsVersion.len = strlen(flow->rval.osver);
            } else {
                p0frec->reverseOsVersion.len = 0;
            }
            if (NULL != flow->rval.osFingerPrint) {
                p0frec->reverseOsFingerPrint.buf = (uint8_t *)
                    flow->rval.osFingerPrint;
                p0frec->reverseOsFingerPrint.len =
                    strlen(flow->rval.osFingerPrint);
            } else {
                p0frec->reverseOsFingerPrint.len = 0;
            }
        } else {
            p0frec = (yaf_p0f_t *)FBSTMLINIT(stml, YAF_P0F_TID,
                                             yaf_tmpl.yaf_p0f_tmpl);
        }
        if (NULL != flow->val.osname) {
            p0frec->osName.buf  = (uint8_t *)flow->val.osname;
            p0frec->osName.len  = strlen(flow->val.osname);
        } else {
            p0frec->osName.len = 0;
        }

        if (NULL != flow->val.osver) {
            p0frec->osVersion.buf = (uint8_t *)flow->val.osver;
            p0frec->osVersion.len = strlen(flow->val.osver);
        } else {
            p0frec->osVersion.len = 0;
        }

        if (NULL != flow->val.osFingerPrint) {
            p0frec->osFingerPrint.buf = (uint8_t *)flow->val.osFingerPrint;
            p0frec->osFingerPrint.len = strlen(flow->val.osFingerPrint);
        } else {
            p0frec->osFingerPrint.len = 0;
        }
        tmplcount--;
    }
#endif /* if YAF_ENABLE_P0F */

#if YAF_ENABLE_FPEXPORT
    /* Add FingerPrint Template */
    if (flow->val.firstPacket || flow->rval.firstPacket ||
        flow->val.secondPacket)
    {
        yaf_fpexport_t   *fpexportrec;
        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);

        if (etid) {
            fpexportrec = (yaf_fpexport_t *)FBSTMLINIT(
                stml, (YAF_FPEXPORT_TID | etid), yaf_tmpl.
                yaf_fpexport_tmpl_rev);
            fpexportrec->reverseFirstPacketBanner.buf = flow->rval.firstPacket;
            fpexportrec->reverseFirstPacketBanner.len =
                flow->rval.firstPacketLen;
        } else {
            fpexportrec = (yaf_fpexport_t *)FBSTMLINIT(
                stml, YAF_FPEXPORT_TID, yaf_tmpl.yaf_fpexport_tmpl);
        }
        fpexportrec->firstPacketBanner.buf = flow->val.firstPacket;
        fpexportrec->firstPacketBanner.len = flow->val.firstPacketLen;
        fpexportrec->secondPacketBanner.buf = flow->val.secondPacket;
        fpexportrec->secondPacketBanner.len = flow->val.secondPacketLen;
        tmplcount--;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

    if (stats) {
        yfFlowStats_t *fwd_stats = flow->val.stats;
        yfFlowStats_t *rev_stats = flow->rval.stats;
        uint32_t pktavg = 0;

        stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml);
        if (etid) {
            statsflow = (yaf_flowstats_t *)
                FBSTMLINIT(stml, (YAF_FLOWSTATS_TID | etid),
                           yaf_tmpl.yaf_flowstats_tmpl_rev);
            statsflow->reverseTcpUrgTotalCount = rev_stats->tcpurgct;
            statsflow->reverseSmallPacketCount = rev_stats->smallpktct;
            statsflow->reverseFirstNonEmptyPacketSize =
                (uint16_t)rev_stats->firstpktsize;
            statsflow->reverseNonEmptyPacketCount = rev_stats->nonemptypktct;
            statsflow->reverseDataByteCount = rev_stats->payoct;
            statsflow->reverseMaxPacketSize = (uint16_t)rev_stats->maxpktsize;
            statsflow->reverseLargePacketCount = rev_stats->largepktct;
            if (rev_stats->nonemptypktct) {
                int32_t temp = 0;
                int32_t diff;
                count = MIN(rev_stats->nonemptypktct, 10);
                pktavg = rev_stats->payoct / rev_stats->nonemptypktct;
                for (loop = 0; loop < count; loop++) {
                    diff = (int32_t)rev_stats->pktsize[loop] - (int32_t)pktavg;
                    temp += diff * diff;
                }
                statsflow->reverseStandardDeviationPayloadLength =
                    sqrt(temp / count);
            }
            if (flow->rval.pkt > 1) {
                uint64_t time_temp = 0;
                int64_t diff;
                statsflow->reverseAverageInterarrivalTime =
                    rev_stats->aitime / (flow->rval.pkt - 1);
                count = MIN(flow->rval.pkt, 11) - 1;
                for (loop = 0; loop < count; loop++) {
                    diff = ((int64_t)rev_stats->iaarray[loop] -
                            (int64_t)statsflow->reverseAverageInterarrivalTime);
                    time_temp += diff * diff;
                }
                statsflow->reverseStandardDeviationInterarrivalTime =
                    sqrt(time_temp / count);
            }
        } else {
            statsflow = (yaf_flowstats_t *)
                FBSTMLINIT(stml, YAF_FLOWSTATS_TID,
                           yaf_tmpl.yaf_flowstats_tmpl);
        }
        pktavg = 0;
        statsflow->firstEightNonEmptyPacketDirections = flow->pktdir;
        statsflow->tcpUrgTotalCount = fwd_stats->tcpurgct;
        statsflow->smallPacketCount = fwd_stats->smallpktct;
        statsflow->firstNonEmptyPacketSize = (uint16_t)fwd_stats->firstpktsize;
        statsflow->nonEmptyPacketCount = fwd_stats->nonemptypktct;
        statsflow->dataByteCount = fwd_stats->payoct;
        statsflow->maxPacketSize = (uint16_t)fwd_stats->maxpktsize;
        statsflow->largePacketCount = fwd_stats->largepktct;
        if (fwd_stats->nonemptypktct) {
            int32_t temp = 0;
            int32_t diff;
            count = MIN(fwd_stats->nonemptypktct, 10);
            pktavg = fwd_stats->payoct / fwd_stats->nonemptypktct;
            temp = 0;
            for (loop = 0; loop < count; loop++) {
                diff = (int32_t)fwd_stats->pktsize[loop] - (int32_t)pktavg;
                temp += diff * diff;
            }
            statsflow->standardDeviationPayloadLength = sqrt(temp / count);
        }
        if (flow->val.pkt > 1) {
            uint64_t time_temp = 0;
            int64_t diff;
            statsflow->averageInterarrivalTime =
                fwd_stats->aitime / (flow->val.pkt - 1);
            count = MIN(flow->val.pkt, 11) - 1;
            for (loop = 0; loop < count; loop++) {
                diff = ((int64_t)fwd_stats->iaarray[loop] -
                        (int64_t)statsflow->averageInterarrivalTime);
                time_temp += diff * diff;
            }
            statsflow->standardDeviationInterarrivalTime =
                sqrt(time_temp / count);
        }
        tmplcount--;
    }

#if YAF_ENABLE_HOOKS
    /* write hook record - only add if there are some available in list*/
    if (!yfHookFlowWrite(&(rec.subTemplateMultiList), stml, flow, err)) {
        return FALSE;
    }
#endif /* if YAF_ENABLE_HOOKS */

    /* IF UDP - Check to see if we need to re-export templates */
    /* We do not advise in using UDP (nicer than saying you're stupid) */
    if ((ctx->cfg->connspec.transport == FB_UDP) ||
        (ctx->cfg->connspec.transport == FB_DTLS_UDP))
    {
        if (yfTimeCheckElapsed(flow->etime, ctx->udp_tmpl_sendtime,
                               ctx->cfg->udp_tmpl_interval))
        {
            /* resend templates */
            ok = fbSessionExportTemplates(fBufGetSession(ctx->fbuf), err);
            ctx->udp_tmpl_sendtime = flow->etime;
            if (!ok) {
                g_warning("Failed to renew UDP Templates: %s",
                          (*err)->message);
                g_clear_error(err);
            }
        }
        if (!(ctx->cfg->livetype)) {
            /* slow down UDP export if reading from a file */
            usleep(2);
        }
    }

    /* Now append the record to the buffer */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

#if YAF_ENABLE_HOOKS
    /* clear basic lists */
    yfHookFreeLists(flow);
#endif
    /* Clear MultiList */
    fbSubTemplateMultiListClear(&(rec.subTemplateMultiList));

    return TRUE;
}


/**
 * yfWriterClose
 *
 *
 *
 */
gboolean
yfWriterClose(
    fBuf_t    *fbuf,
    gboolean   flush,
    GError   **err)
{
    gboolean ok = TRUE;

    if (flush) {
        ok = fBufEmit(fbuf, err);
    }

    fBufFree(fbuf);

    return ok;
}


/**
 * yfTemplateCallback
 *
 *
 */
static void
yfTemplateCallback(
    fbSession_t           *session,
    uint16_t               tid,
    fbTemplate_t          *tmpl,
    void                  *app_ctx,
    void                 **tmpl_ctx,
    fbTemplateCtxFree_fn  *fn)
{
    uint16_t ntid;

    ntid = tid & YTF_REV;

    if (YAF_FLOW_BASE_TID == (tid & 0xF000)) {
        fbSessionAddTemplatePair(session, tid, tid);
    }

    if (ntid == YAF_ENTROPY_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (ntid == YAF_TCP_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (ntid == YAF_MAC_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else if (ntid == YAF_PAYLOAD_TID) {
        fbSessionAddTemplatePair(session, tid, tid);
    } else {
        /* Dont decode templates yafscii doesn't care about */
        fbSessionAddTemplatePair(session, tid, 0);
    }
}


/**
 * yfInitCollectorSession
 *
 *
 *
 */
static fbSession_t *
yfInitCollectorSession(
    GError **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = NULL;
    fbSession_t   *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* Add the full record template */
    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_full_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, err)) {
        return NULL;
    }

    /* Entropy */
#if YAF_ENABLE_ENTROPY
    yaf_tmpl.yaf_entropy_tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.yaf_entropy_tmpl, yaf_entropy_spec,
                                   YF_TMPL_SPEC_ALL_IE, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_ENTROPY_TID,
                              yaf_tmpl.yaf_entropy_tmpl, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_ENTROPY */

    /* TCP Flags and Sequence Numbers */
    yaf_tmpl.yaf_tcp_tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.yaf_tcp_tmpl, yaf_tcp_spec,
                                   YF_TMPL_SPEC_ALL_IE, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_TCP_TID,
                              yaf_tmpl.yaf_tcp_tmpl, err))
    {
        return NULL;
    }

    /* MAC Addresses */
    yaf_tmpl.yaf_mac_tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.yaf_mac_tmpl, yaf_mac_spec,
                                   YF_TMPL_SPEC_ALL_IE, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_MAC_TID,
                              yaf_tmpl.yaf_mac_tmpl, err))
    {
        return NULL;
    }

    /* P0F Fingerprints */
#if YAF_ENABLE_P0F
    yaf_tmpl.yaf_p0f_tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.yaf_p0f_tmpl, yaf_p0f_spec,
                                   YF_TMPL_SPEC_ALL_IE, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_P0F_TID,
                              yaf_tmpl.yaf_p0f_tmpl, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_P0F */

    /* Additional Fingerprinting data (fpexport) */
#if YAF_ENABLE_FPEXPORT
    yaf_tmpl.yaf_fpexport_tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.yaf_fpexport_tmpl,
                                   yaf_fpexport_spec, YF_TMPL_SPEC_ALL_IE, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FPEXPORT_TID,
                              yaf_tmpl.yaf_fpexport_tmpl, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_FPEXPORT */

    /* Payload */
#if YAF_ENABLE_PAYLOAD
    yaf_tmpl.yaf_payload_tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(yaf_tmpl.yaf_payload_tmpl, yaf_payload_spec,
                                   YF_TMPL_SPEC_ALL_IE, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_PAYLOAD_TID,
                              yaf_tmpl.yaf_payload_tmpl, err))
    {
        return NULL;
    }
#endif /* if YAF_ENABLE_PAYLOAD */

    /* Add the extended record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_full_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbTemplateAppendSpecArray(tmpl, yaf_ext_flow_spec,
                                   YF_TMPL_SPEC_ALL_IE, err))
    {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_EXT_TID, tmpl, err)) {
        return NULL;
    }

    /* Done. Return the session. */

    /** Add the template callback so we don't try to decode DPI */
    fbSessionAddNewTemplateCallback(session, yfTemplateCallback, NULL);

    return session;
}


/**
 * yfReaderForFP
 *
 *
 *
 */
fBuf_t *
yfReaderForFP(
    fBuf_t  *fbuf,
    FILE    *fp,
    GError **err)
{
    fbSession_t   *session;
    fbCollector_t *collector;

    /* Allocate a collector for the file */
    collector = fbCollectorAllocFP(NULL, fp);

    /* Allocate a buffer, or reset the collector */
    if (fbuf) {
        fBufSetCollector(fbuf, collector);
    } else {
        if (!(session = yfInitCollectorSession(err))) {goto err;}
        fbuf = fBufAllocForCollection(session, collector);
    }

    /* FIXME do a preread? */

    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfListenerForSpec
 *
 *
 *
 */
fbListener_t *
yfListenerForSpec(
    fbConnSpec_t          *spec,
    fbListenerAppInit_fn   appinit,
    fbListenerAppFree_fn   appfree,
    GError               **err)
{
    fbSession_t *session;

    if (!(session = yfInitCollectorSession(err))) {return NULL;}

    return fbListenerAlloc(spec, session, appinit, appfree, err);
}


/**
 * yfReadFlow
 *
 * read an IPFIX record in, with respect to fields YAF cares about
 *
 */
gboolean
yfReadFlow(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err)
{
    yaf_flow_full_t  rec;
    size_t           len;
    fbSubTemplateMultiListEntry_t *stml = NULL;
    yaf_tcp_t       *tcprec = NULL;
    fbTemplate_t    *next_tmpl = NULL;
    yaf_mac_t       *macrec = NULL;
#if YAF_ENABLE_ENTROPY
    yaf_entropy_t   *entropyrec = NULL;
#endif
#if YAF_ENABLE_PAYLOAD
    yaf_payload_t   *payrec = NULL;
#endif

    len = sizeof(yaf_flow_full_t);

    /* Check if Options Template - if so - ignore */
    next_tmpl = fBufNextCollectionTemplate(fbuf, NULL, err);
    if (next_tmpl) {
        if (fbTemplateGetOptionsScope(next_tmpl)) {
            /* Stats Msg - Don't actually Decode */
            if (!fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
                return FALSE;
            }
            return TRUE;
        }
    } else {
        return FALSE;
    }

    /* read next YAF record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }
    if (!fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
        return FALSE;
    }

    /* copy time */
    yfTimeFromMilli(&flow->stime, rec.flowStartMilliseconds);
    yfTimeFromMilli(&flow->etime, rec.flowEndMilliseconds);
    yfDiffTimeFromMilli(&flow->rdtime, rec.reverseFlowDeltaMilliseconds);

    /* copy addresses */
    if (rec.sourceIPv4Address || rec.destinationIPv4Address) {
        flow->key.version = 4;
        flow->key.addr.v4.sip = rec.sourceIPv4Address;
        flow->key.addr.v4.dip = rec.destinationIPv4Address;
    } else {
        flow->key.version = 6;
        memcpy(flow->key.addr.v6.sip, rec.sourceIPv6Address,
               sizeof(flow->key.addr.v6.sip));
        memcpy(flow->key.addr.v6.dip, rec.destinationIPv6Address,
               sizeof(flow->key.addr.v6.dip));
    }

    /* copy key and counters */
    flow->key.sp = rec.sourceTransportPort;
    flow->key.dp = rec.destinationTransportPort;
    flow->key.proto = rec.protocolIdentifier;
    flow->val.oct = rec.octetTotalCount;
    flow->val.pkt = rec.packetTotalCount;
    if (flow->val.oct == 0 && flow->val.pkt == 0) {
        flow->val.oct = rec.octetDeltaCount;
        flow->val.pkt = rec.packetDeltaCount;
    }
    flow->key.vlanId = rec.vlanId;
    flow->val.vlan = rec.vlanId;
    flow->rval.vlan = rec.reverseVlanId;
    flow->rval.oct = rec.reverseOctetTotalCount;
    flow->rval.pkt = rec.reversePacketTotalCount;
    flow->reason = rec.flowEndReason;

#if YAF_ENABLE_APPLABEL
    flow->appLabel = rec.silkAppLabel;
#endif
#if YAF_ENABLE_ENTROPY
    flow->val.entropy = 0;
    flow->rval.entropy = 0;
#endif
    flow->val.isn = rec.tcpSequenceNumber;
    flow->val.iflags = rec.initialTCPFlags;
    flow->val.uflags = rec.unionTCPFlags;
    flow->rval.isn = rec.reverseTcpSequenceNumber;
    flow->rval.iflags = rec.reverseInitialTCPFlags;
    flow->rval.uflags = rec.reverseUnionTCPFlags;
    flow->key.layer2Id = rec.yafLayer2SegmentId;

    /* Get subTemplateMultiList Entry */
    while ((stml = FBSTMLNEXT(&(rec.subTemplateMultiList), stml))) {
        switch ((stml->tmplID & YTF_REV)) {
#if YAF_ENABLE_ENTROPY
          case YAF_ENTROPY_TID:
            entropyrec =
                (yaf_entropy_t *)fbSubTemplateMultiListEntryNextDataPtr(
                    stml, entropyrec);
            flow->val.entropy = entropyrec->entropy;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.entropy = entropyrec->reverseEntropy;
            }
            break;
#endif /* if YAF_ENABLE_ENTROPY */
          case YAF_TCP_TID:
            tcprec = (yaf_tcp_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, tcprec);
            flow->val.isn = tcprec->tcpSequenceNumber;
            flow->val.iflags = tcprec->initialTCPFlags;
            flow->val.uflags = tcprec->unionTCPFlags;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.isn = tcprec->reverseTcpSequenceNumber;
                flow->rval.iflags = tcprec->reverseInitialTCPFlags;
                flow->rval.uflags = tcprec->reverseUnionTCPFlags;
            }
            break;
          case YAF_MAC_TID:
            macrec = (yaf_mac_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, macrec);
            memcpy(flow->sourceMacAddr, macrec->sourceMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            memcpy(flow->destinationMacAddr, macrec->destinationMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            break;
#if YAF_ENABLE_PAYLOAD
          case YAF_PAYLOAD_TID:
            /* copy payload */
            payrec = (yaf_payload_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, payrec);
            yfPayloadCopyIn(&payrec->payload, &flow->val);
            if ((stml->tmplID & YTF_BIF)) {
                yfPayloadCopyIn(&payrec->reversePayload, &flow->rval);
            }
            break;
#endif /* if YAF_ENABLE_PAYLOAD */
          default:
            /* don't know about this template */
            break;
        }
    }

    fbSubTemplateMultiListClear(&(rec.subTemplateMultiList));

    return TRUE;
}


/**
 * yfReadFlowExtended
 *
 * read an IPFIX flow record in (with respect to fields YAF cares about)
 * using YAF's extended precision time recording
 *
 */
gboolean
yfReadFlowExtended(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err)
{
    yfIpfixExtFlow_t rec;
    fbTemplate_t    *next_tmpl = NULL;
    size_t           len;
    fbSubTemplateMultiListEntry_t *stml = NULL;
    yaf_tcp_t       *tcprec = NULL;
    yaf_mac_t       *macrec = NULL;
#if YAF_ENABLE_ENTROPY
    yaf_entropy_t   *entropyrec = NULL;
#endif
#if YAF_ENABLE_PAYLOAD
    yaf_payload_t   *payrec = NULL;
#endif

    /* read next YAF record; retrying on missing template or EOF. */
    len = sizeof(yfIpfixExtFlow_t);
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_EXT_TID, err)) {
        return FALSE;
    }

    for (;;) {
        /* Check if Options Template - if so - ignore */
        next_tmpl = fBufNextCollectionTemplate(fbuf, NULL, err);
        if (next_tmpl) {
            if (fbTemplateGetOptionsScope(next_tmpl)) {
                if (!(fBufNext(fbuf, (uint8_t *)&rec, &len, err))) {
                    return FALSE;
                }
                continue;
            }
        } else {
            return FALSE;
        }
        if (fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
            break;
        } else {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                /* try again on missing template */
                g_debug("skipping IPFIX data set: %s", (*err)->message);
                g_clear_error(err);
                continue;
            } else {
                /* real, actual error */
                return FALSE;
            }
        }
    }

    /* Run the Gauntlet of Time. */
    if (rec.f.flowStartMilliseconds) {
        yfTimeFromMilli(&flow->stime, rec.f.flowStartMilliseconds);
        if (rec.f.flowEndMilliseconds >= rec.f.flowStartMilliseconds) {
            yfTimeFromMilli(&flow->etime, rec.f.flowEndMilliseconds);
        } else {
            yfDiffTime_t dur;
            yfDiffTimeFromMilli(&dur, rec.flowDurationMilliseconds);
            yfTimeAdd(&flow->etime, flow->stime, dur);
        }
    } else if (rec.f.flowStartMicroseconds) {
        /* Decode NTP-format microseconds */
        yfTimeFromNTP(&flow->stime, rec.f.flowStartMicroseconds, TRUE);
        /* This test is false for valid times that bridge the NTP Eras */
        if (rec.f.flowEndMicroseconds >= rec.f.flowStartMicroseconds) {
            yfTimeFromNTP(&flow->etime, rec.f.flowEndMicroseconds, TRUE);
        } else {
            yfDiffTime_t dur;
            yfDiffTimeFromMicro(&dur, rec.flowDurationMicroseconds);
            yfTimeAdd(&flow->etime, flow->stime, dur);
        }
    } else if (rec.f.flowStartNanoseconds) {
        /* Decode NTP-format nanoseconds */
        yfTimeFromNTP(&flow->stime, rec.f.flowStartNanoseconds, FALSE);
        yfTimeFromNTP(&flow->etime, rec.f.flowEndNanoseconds, FALSE);
    } else if (rec.flowStartSeconds) {
        /* Seconds? Well. Okay... */
        yfTimeFromSeconds(&flow->stime, rec.flowStartSeconds);
        yfTimeFromSeconds(&flow->etime, rec.flowEndSeconds);
    } else if (rec.flowStartDeltaMicroseconds) {
        /* Handle delta microseconds. */
        uint64_t usec;
        usec = (fBufGetExportTime(fbuf) * 10000000 -
                rec.flowStartDeltaMicroseconds);
        yfTimeFromMicro(&flow->stime, usec);
        if (rec.flowEndDeltaMicroseconds &&
            rec.flowEndDeltaMicroseconds <= rec.flowStartDeltaMicroseconds)
        {
            usec = (fBufGetExportTime(fbuf) * 10000000 -
                    rec.flowEndDeltaMicroseconds);
            yfTimeFromMicro(&flow->etime, usec);
        } else {
            /* usec still holds the start time */
            usec += rec.flowDurationMicroseconds;
            yfTimeFromMicro(&flow->etime, usec);
        }
    } else {
        /* Out of time. Use current timestamp, zero duration */
        yfTimeNow(&flow->stime);
        flow->etime = flow->stime;
    }

    /* copy private time field - reverse delta */
    yfDiffTimeFromMilli(&flow->rdtime, rec.f.reverseFlowDeltaMilliseconds);

    /* copy addresses */
    if (rec.f.sourceIPv4Address || rec.f.destinationIPv4Address) {
        flow->key.version = 4;
        flow->key.addr.v4.sip = rec.f.sourceIPv4Address;
        flow->key.addr.v4.dip = rec.f.destinationIPv4Address;
    } else {
        flow->key.version = 6;
        memcpy(flow->key.addr.v6.sip, rec.f.sourceIPv6Address,
               sizeof(flow->key.addr.v6.sip));
        memcpy(flow->key.addr.v6.dip, rec.f.destinationIPv6Address,
               sizeof(flow->key.addr.v6.dip));
    }

    /* copy key and counters */
    flow->key.sp = rec.f.sourceTransportPort;
    flow->key.dp = rec.f.destinationTransportPort;
    flow->key.proto = rec.f.protocolIdentifier;
    flow->val.oct = rec.f.octetTotalCount;
    flow->val.pkt = rec.f.packetTotalCount;
    flow->rval.oct = rec.f.reverseOctetTotalCount;
    flow->rval.pkt = rec.f.reversePacketTotalCount;
    flow->key.vlanId = rec.f.vlanId;
    flow->val.vlan = rec.f.vlanId;
    flow->rval.vlan = rec.f.reverseVlanId;
    flow->reason = rec.f.flowEndReason;
    /* Handle delta counters */
    if (!(flow->val.oct)) {
        flow->val.oct = rec.f.octetDeltaCount;
        flow->rval.oct = rec.f.reverseOctetDeltaCount;
    }
    if (!(flow->val.pkt)) {
        flow->val.pkt = rec.f.packetDeltaCount;
        flow->rval.pkt = rec.f.reversePacketDeltaCount;
    }

#if YAF_ENABLE_APPLABEL
    flow->appLabel = rec.f.silkAppLabel;
#endif
#if YAF_ENABLE_NDPI
    flow->ndpi_master = rec.f.ndpi_master;
    flow->ndpi_sub = rec.f.ndpi_sub;
#endif

#if YAF_ENABLE_ENTROPY
    flow->val.entropy = 0;
    flow->rval.entropy = 0;
#endif
    flow->val.isn = rec.f.tcpSequenceNumber;
    flow->val.iflags = rec.f.initialTCPFlags;
    flow->val.uflags = rec.f.unionTCPFlags;
    flow->rval.isn = rec.f.reverseTcpSequenceNumber;
    flow->rval.iflags = rec.f.reverseInitialTCPFlags;
    flow->rval.uflags = rec.f.reverseUnionTCPFlags;

    while ((stml = FBSTMLNEXT(&(rec.f.subTemplateMultiList), stml))) {
        switch ((stml->tmplID & YTF_REV)) {
#if YAF_ENABLE_ENTROPY
          case YAF_ENTROPY_TID:
            entropyrec =
                (yaf_entropy_t *)fbSubTemplateMultiListEntryNextDataPtr(
                    stml, entropyrec);
            flow->val.entropy = entropyrec->entropy;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.entropy = entropyrec->reverseEntropy;
            }
            break;
#endif /* if YAF_ENABLE_ENTROPY */
          case YAF_TCP_TID:
            tcprec = (yaf_tcp_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, tcprec);
            flow->val.isn = tcprec->tcpSequenceNumber;
            flow->val.iflags = tcprec->initialTCPFlags;
            flow->val.uflags = tcprec->unionTCPFlags;
            if ((stml->tmplID & YTF_BIF)) {
                flow->rval.isn = tcprec->reverseTcpSequenceNumber;
                flow->rval.iflags = tcprec->reverseInitialTCPFlags;
                flow->rval.uflags = tcprec->reverseUnionTCPFlags;
            }
            break;
          case YAF_MAC_TID:
            macrec = (yaf_mac_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, macrec);
            memcpy(flow->sourceMacAddr, macrec->sourceMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            memcpy(flow->destinationMacAddr, macrec->destinationMacAddress,
                   ETHERNET_MAC_ADDR_LENGTH);
            break;
#if YAF_ENABLE_PAYLOAD
          case YAF_PAYLOAD_TID:
            /* copy payload */
            payrec = (yaf_payload_t *)fbSubTemplateMultiListEntryNextDataPtr(
                stml, payrec);
            yfPayloadCopyIn(&payrec->payload, &flow->val);
            if ((stml->tmplID & YTF_BIF)) {
                yfPayloadCopyIn(&payrec->reversePayload, &flow->rval);
            }
            break;
#endif /* if YAF_ENABLE_PAYLOAD */
          default:
            fbSubTemplateMultiListEntryNextDataPtr(stml, NULL);
            break;
        }
    }

    fbSubTemplateMultiListClear(&(rec.f.subTemplateMultiList));

    return TRUE;
}


/**
 * yfPrintFlags
 *
 *
 *
 */
static void
yfPrintFlags(
    GString  *str,
    uint8_t   flags)
{
    if (flags & YF_TF_ECE) {g_string_append_c(str, 'E');}
    if (flags & YF_TF_CWR) {g_string_append_c(str, 'C');}
    if (flags & YF_TF_URG) {g_string_append_c(str, 'U');}
    if (flags & YF_TF_ACK) {g_string_append_c(str, 'A');}
    if (flags & YF_TF_PSH) {g_string_append_c(str, 'P');}
    if (flags & YF_TF_RST) {g_string_append_c(str, 'R');}
    if (flags & YF_TF_SYN) {g_string_append_c(str, 'S');}
    if (flags & YF_TF_FIN) {g_string_append_c(str, 'F');}
    if (!flags) {g_string_append_c(str, '0');}
}


/**
 * yfPrintString
 *
 *
 *
 */
void
yfPrintString(
    GString   *rstr,
    yfFlow_t  *flow)
{
    char sabuf[AIR_IP6ADDR_BUF_MINSZ],
         dabuf[AIR_IP6ADDR_BUF_MINSZ];
    uint64_t s_msec;
    uint64_t e_msec;
    uint32_t dur_msec;

    /* FIXME: Chanage libairframe functions to take a yfTime_t */

    if (NULL == rstr) {
        return;
    }

    s_msec = yfTimeToMilli(flow->stime);
    e_msec = yfTimeToMilli(flow->etime);
    dur_msec = yfDiffTimeToMilli(flow->rdtime);

    /* print start as date and time */
    air_mstime_g_string_append(rstr, s_msec, AIR_TIME_ISO8601);

    /* print end as time and duration if not zero-duration */
    if (yfTimeCmpOp(flow->stime, flow->etime, !=)) {
        g_string_append_printf(rstr, " - ");
        air_mstime_g_string_append(rstr, e_msec, AIR_TIME_ISO8601_HMS);
        g_string_append_printf(rstr, " (%.3f sec)",
                               (e_msec - s_msec) / 1000.0);
    }

    /* print protocol and addresses */
    if (flow->key.version == 4) {
        air_ipaddr_buf_print(sabuf, flow->key.addr.v4.sip);
        air_ipaddr_buf_print(dabuf, flow->key.addr.v4.dip);
    } else if (flow->key.version == 6) {
        air_ip6addr_buf_print(sabuf, flow->key.addr.v6.sip);
        air_ip6addr_buf_print(dabuf, flow->key.addr.v6.dip);
    } else {
        sabuf[0] = (char)0;
        dabuf[0] = (char)0;
    }

    switch (flow->key.proto) {
      case YF_PROTO_TCP:
        if (flow->rval.oct) {
            g_string_append_printf(rstr, " tcp %s:%u => %s:%u %08x:%08x ",
                                   sabuf, flow->key.sp, dabuf, flow->key.dp,
                                   flow->val.isn, flow->rval.isn);
        } else {
            g_string_append_printf(rstr, " tcp %s:%u => %s:%u %08x ",
                                   sabuf, flow->key.sp, dabuf, flow->key.dp,
                                   flow->val.isn);
        }

        yfPrintFlags(rstr, flow->val.iflags);
        g_string_append_c(rstr, '/');
        yfPrintFlags(rstr, flow->val.uflags);
        if (flow->rval.oct) {
            g_string_append_c(rstr, ':');
            yfPrintFlags(rstr, flow->rval.iflags);
            g_string_append_c(rstr, '/');
            yfPrintFlags(rstr, flow->rval.uflags);
        }
        break;
      case YF_PROTO_UDP:
        g_string_append_printf(rstr, " udp %s:%u => %s:%u",
                               sabuf, flow->key.sp, dabuf, flow->key.dp);
        break;
      case YF_PROTO_ICMP:
        g_string_append_printf(rstr, " icmp [%u:%u] %s => %s",
                               (flow->key.dp >> 8), (flow->key.dp & 0xFF),
                               sabuf, dabuf);
        break;
      case YF_PROTO_ICMP6:
        g_string_append_printf(rstr, " icmp6 [%u:%u] %s => %s",
                               (flow->key.dp >> 8), (flow->key.dp & 0xFF),
                               sabuf, dabuf);
        break;
      default:
        g_string_append_printf(rstr, " ip %u %s => %s",
                               flow->key.proto, sabuf, dabuf);
        break;
    }

    /* print vlan tags */
    if (flow->key.vlanId) {
        if (flow->rval.oct) {
            g_string_append_printf(rstr, " vlan %03hx:%03hx",
                                   flow->val.vlan, flow->rval.vlan);
        } else {
            g_string_append_printf(rstr, " vlan %03hx",
                                   flow->val.vlan);
        }
    }

    /* print flow counters and round-trip time */
    if (flow->rval.pkt) {
        g_string_append_printf(
            rstr,
            " (%" PRIu64 "/%" PRIu64 " <-> %" PRIu64 "/%" PRIu64 ") rtt %d ms",
            flow->val.pkt, flow->val.oct, flow->rval.pkt, flow->rval.oct,
            dur_msec);
    } else {
        g_string_append_printf(rstr, " (%" PRIu64 "/%" PRIu64 " ->)",
                               flow->val.pkt, flow->val.oct);
    }

    /* end reason flags */
    if ((flow->reason & YAF_END_MASK) == YAF_END_IDLE) {
        g_string_append(rstr, " idle");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_ACTIVE) {
        g_string_append(rstr, " active");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_FORCED) {
        g_string_append(rstr, " eof");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_RESOURCE) {
        g_string_append(rstr, " rsrc");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_UDPFORCE) {
        g_string_append(rstr, " force");
    }

    /* if app label is enabled, print the label */
#ifdef YAF_ENABLE_APPLABEL
    if (0 != flow->appLabel) {
        g_string_append_printf(rstr, " applabel: %u", flow->appLabel);
    }
#endif
#ifdef YAF_ENABLE_NDPI
    if (0 != flow->ndpi_master) {
        if (flow->ndpi_sub) {
            g_string_append_printf(rstr, " ndpi: %u[%u]", flow->ndpi_master,
                                   flow->ndpi_sub);
        } else {
            g_string_append_printf(rstr, " ndpi: %u", flow->ndpi_master);
        }
    }
#endif /* ifdef YAF_ENABLE_NDPI */

    /* if entropy is enabled, print the entropy values */
#ifdef YAF_ENABLE_ENTROPY
    if (0 != flow->val.entropy || 0 != flow->rval.entropy) {
        g_string_append_printf(rstr, " entropy: %u rev entropy: %u",
                               flow->val.entropy, flow->rval.entropy);
    }
#endif /* ifdef YAF_ENABLE_ENTROPY */

    /* finish line */
    g_string_append(rstr, "\n");

    /* print payload if necessary */
#if YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        air_hexdump_g_string_append(rstr, "  -> ",
                                    flow->val.payload, flow->val.paylen);
        g_free(flow->val.payload);
        flow->val.payload = NULL;
        flow->val.paylen = 0;
    }
    if (flow->rval.payload) {
        air_hexdump_g_string_append(rstr, " <-  ",
                                    flow->rval.payload, flow->rval.paylen);
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
        flow->rval.paylen = 0;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfPrintDelimitedString
 *
 *
 *
 */
void
yfPrintDelimitedString(
    GString   *rstr,
    yfFlow_t  *flow,
    gboolean   yaft_mac)
{
    char           sabuf[AIR_IP6ADDR_BUF_MINSZ],
                   dabuf[AIR_IP6ADDR_BUF_MINSZ];
    GString       *fstr = NULL;
    int            loop = 0;
    unsigned short rvlan = 0;
    uint64_t       s_msec;
    uint64_t       e_msec;
    double         dur;

    if (NULL == rstr) {
        return;
    }

    s_msec = yfTimeToMilli(flow->stime);
    e_msec = yfTimeToMilli(flow->etime);
    dur = (double)yfDiffTimeToMilli(flow->rdtime) / 1000.0;

    /* print time and duration */
    air_mstime_g_string_append(rstr, s_msec, AIR_TIME_ISO8601);
    g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
    air_mstime_g_string_append(rstr, e_msec, AIR_TIME_ISO8601);
    g_string_append_printf(rstr, "%s%8.3f%s",
                           YF_PRINT_DELIM, (e_msec - s_msec) / 1000.0,
                           YF_PRINT_DELIM);

    /* print initial RTT */
    g_string_append_printf(rstr, "%8.3f%s", dur, YF_PRINT_DELIM);

    /* print five tuple */
    if (flow->key.version == 4) {
        air_ipaddr_buf_print(sabuf, flow->key.addr.v4.sip);
        air_ipaddr_buf_print(dabuf, flow->key.addr.v4.dip);
    } else if (flow->key.version == 6) {
        air_ip6addr_buf_print(sabuf, flow->key.addr.v6.sip);
        air_ip6addr_buf_print(dabuf, flow->key.addr.v6.dip);
    } else {
        sabuf[0] = (char)0;
        dabuf[0] = (char)0;
    }
    g_string_append_printf(rstr, "%3u%s%40s%s%5u%s%40s%s%5u%s",
                           flow->key.proto, YF_PRINT_DELIM,
                           sabuf, YF_PRINT_DELIM, flow->key.sp, YF_PRINT_DELIM,
                           dabuf, YF_PRINT_DELIM, flow->key.dp, YF_PRINT_DELIM);

    if (yaft_mac) {
        for (loop = 0; loop < 6; loop++) {
            g_string_append_printf(rstr, "%02x", flow->sourceMacAddr[loop]);
            if (loop < 5) {
                g_string_append_printf(rstr, ":");
            }
            /* clear out mac addr for next flow */
            flow->sourceMacAddr[loop] = 0;
        }
        g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
        for (loop = 0; loop < 6; loop++) {
            g_string_append_printf(rstr, "%02x",
                                   flow->destinationMacAddr[loop]);
            if (loop < 5) {
                g_string_append_printf(rstr, ":");
            }
            /* clear out mac addr for next flow */
            flow->destinationMacAddr[loop] = 0;
        }
        g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
    }

    /* print tcp flags */
    fstr = g_string_new(NULL);
    yfPrintFlags(fstr, flow->val.iflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->val.uflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->rval.iflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->rval.uflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_free(fstr, TRUE);

    /* print tcp sequence numbers */
    g_string_append_printf(rstr, "%08x%s%08x%s", flow->val.isn, YF_PRINT_DELIM,
                           flow->rval.isn, YF_PRINT_DELIM);

    /* print vlan tags */
    if (flow->rval.oct) {
        g_string_append_printf(rstr, "%03hx%s%03hx%s", flow->val.vlan,
                               YF_PRINT_DELIM, flow->rval.vlan,
                               YF_PRINT_DELIM);
    } else {
        g_string_append_printf(rstr, "%03hx%s%03hx%s", flow->key.vlanId,
                               YF_PRINT_DELIM, rvlan, YF_PRINT_DELIM);
    }

    /* print flow counters */
    g_string_append_printf(rstr, "%8llu%s%8llu%s%8llu%s%8llu%s",
                           (long long unsigned int)flow->val.pkt,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->val.oct,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->rval.pkt,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->rval.oct,
                           YF_PRINT_DELIM);

    /* if app label is enabled, print the label */
#ifdef YAF_ENABLE_APPLABEL
    g_string_append_printf(rstr, "%5u%s", flow->appLabel, YF_PRINT_DELIM);
#endif

    /* if entropy is enabled, print the entropy values */
#ifdef YAF_ENABLE_ENTROPY
    g_string_append_printf(rstr, "%3u%s%3u%s",
                           flow->val.entropy, YF_PRINT_DELIM,
                           flow->rval.entropy, YF_PRINT_DELIM);
#endif

    /* end reason flags */
    if ((flow->reason & YAF_END_MASK) == YAF_END_IDLE) {
        g_string_append(rstr, "idle ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_ACTIVE) {
        g_string_append(rstr, "active ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_FORCED) {
        g_string_append(rstr, "eof ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_RESOURCE) {
        g_string_append(rstr, "rsrc ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_UDPFORCE) {
        g_string_append(rstr, "force ");
    }

    /* finish line */
    g_string_append(rstr, "\n");

    /* not printing payload - but need to free */
#if YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        g_free(flow->val.payload);
        flow->val.payload = NULL;
        flow->val.paylen = 0;
    }
    if (flow->rval.payload) {
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
        flow->rval.paylen = 0;
    }
#endif /* if YAF_ENABLE_PAYLOAD */
}


/**
 * yfPrint
 *
 *
 *
 */
gboolean
yfPrint(
    FILE      *out,
    yfFlow_t  *flow,
    GError   **err)
{
    GString *rstr = NULL;
    int      rc = 0;

    rstr = g_string_new(NULL);

    yfPrintString(rstr, flow);

    rc = fwrite(rstr->str, rstr->len, 1, out);

    if (rc != 1) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "error printing flow: %s", strerror(errno));
    }

    g_string_free(rstr, TRUE);

    return (rc == 1);
}


/**
 * yfPrintDelimited
 *
 *
 *
 */
gboolean
yfPrintDelimited(
    FILE      *out,
    yfFlow_t  *flow,
    gboolean   yaft_mac,
    GError   **err)
{
    GString *rstr = NULL;
    int      rc = 0;

    rstr = g_string_new(NULL);

    yfPrintDelimitedString(rstr, flow, yaft_mac);

    rc = fwrite(rstr->str, rstr->len, 1, out);

    if (rc != 1) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "error printing delimited flow: %s", strerror(errno));
    }

    g_string_free(rstr, TRUE);

    return (rc == 1);
}


/**
 * yfPrintColumnHeaders
 *
 *
 */
void
yfPrintColumnHeaders(
    FILE      *out,
    gboolean   yaft_mac,
    GError   **err)
{
    GString *rstr = NULL;

    rstr = g_string_new(NULL);

    g_string_append_printf(rstr, "start-time%14s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "end-time%16s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "duration%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rtt%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "proto%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "sip%36s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "sp%4s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "dip%38s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "dp%4s", YF_PRINT_DELIM);
    if (yaft_mac) {
        g_string_append_printf(rstr, "srcMacAddress%5s", YF_PRINT_DELIM);
        g_string_append_printf(rstr, "destMacAddress%4s", YF_PRINT_DELIM);
    }
    g_string_append_printf(rstr, "iflags%3s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "uflags%3s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "riflags%2s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "ruflags%2s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "isn%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "risn%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "tag%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rtag%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "pkt%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "oct%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rpkt%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "roct%5s", YF_PRINT_DELIM);

#if YAF_ENABLE_APPLABEL
    g_string_append_printf(rstr, "app%3s", YF_PRINT_DELIM);
#endif
#if YAF_ENABLE_ENTROPY
    g_string_append_printf(rstr, "entropy%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rentropy%s", YF_PRINT_DELIM);
#endif

    g_string_append_printf(rstr, "end-reason");
    g_string_append(rstr, "\n");

    fwrite(rstr->str, rstr->len, 1, out);

    g_string_free(rstr, TRUE);
}
