/*
 *  Copyright 2014-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  ldapplugin.c
 *
 *  This tries to recognize the ldap protocol.
 *  Decoder based on RFC 4511.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso
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
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <payloadScanner.h>

#define LDAP_PORT_NUMBER 389

YC_SCANNER_PROTOTYPE(ldapplugin_LTX_ycLdapScanScan);

typedef struct asn_tlv_st {
    uint8_t   class    : 2;
    uint8_t   p_c      : 1;
    uint8_t   tag      : 5;

    uint8_t   longform : 1;
    uint8_t   length   : 7;
} asn_tlv_t;



/* Local Prototypes */
static
void
ldapDecodeTLV(
    const uint8_t  *payload,
    asn_tlv_t      *tlv);

/**
 * ldapplugin_LTX_ycLdapScanScan
 *
 * the scanner for recognizing ldap packets
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return ldap_port_number
 *         otherwise 0
 */
uint16_t
ldapplugin_LTX_ycLdapScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t     offset = 0;
    uint16_t     min_length = 7;
    unsigned int i;
    uint64_t     num_packets = val->pkt;
    size_t       pkt_length = payloadSize;
    asn_tlv_t    tlv;

    /* must have SEQUENCE Tag, Integer TAG for Message ID, protocol Op Tag */
    if (payloadSize < min_length) {
        return 0;
    }

    if (*payload != 0x30) {
        return 0;
    }

    if (num_packets > YAF_MAX_PKT_BOUNDARY) {
        num_packets = YAF_MAX_PKT_BOUNDARY;
    }

    for (i = 0; i < num_packets; ++i) {
        if (val->paybounds[i]) {
            pkt_length = val->paybounds[i];
            if (pkt_length > payloadSize) {
                pkt_length = payloadSize;
            }
            break;
        }
    }

    ldapDecodeTLV(payload, &tlv);

    offset += 2;

    if (tlv.longform) {
        offset += tlv.length;
        min_length += tlv.length;
        if (pkt_length < min_length) {
            return 0;
        }
    }

    ldapDecodeTLV((payload + offset), &tlv);

    if (tlv.tag != 0x02) {
        return 0;
    }

    if (tlv.length > 4) {
        /* MAX INTEGER is 2^31-1 */
        return 0;
    }

    offset += 2 + tlv.length;

    /* I already count 1 in the minimum length so subtract that */
    min_length += tlv.length - 1;

    if (pkt_length < min_length) {
        return 0;
    }

    ldapDecodeTLV((payload + offset), &tlv);

    if (tlv.class != 1) {
        /* must be Application Class: Bit 8 = 0, Bit 7 = 1 */
        return 0;
    }

    if (tlv.tag > 25) {
        /* valid types are 0-25 */
        return 0;
    }

    if (tlv.longform) {
        /* if this is a long packet, it's close enough */
        return LDAP_PORT_NUMBER;
    }

    offset += 2 + tlv.length;

    min_length += tlv.length;

    if (pkt_length < min_length) {
        return 0;
    }

    /* response should have a resultCode */
    if (tlv.tag % 2) {
        min_length += 2;
        if (pkt_length < min_length) {
            return 0;
        }

        if (*(payload + offset) != 0x02) {
            return 0;
        }
        /* could test resultCode 0-123, 4096 */
    }

    return LDAP_PORT_NUMBER;
}


/**
 * ldapDecodeTLV
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octet stream directly into an ASN.1 structure
 *
 * @param payload a network stream capture
 * @param asn_tlv_t asn.1 tlv struct
 *
 *
 */
static
void
ldapDecodeTLV(
    const uint8_t  *payload,
    asn_tlv_t      *tlv)
{
    uint8_t byte1 = *payload;
    uint8_t byte2 = *(payload + 1);

    tlv->class = (byte1 & 0xD0) >> 6;
    tlv->p_c = (byte1 & 0x20) >> 5;
    tlv->tag = (byte1 & 0x1F);

    tlv->longform = (byte2 & 0x80) >> 7;
    tlv->length = (byte2 & 0x7F);

    /*g_debug("tlv->class: %d, tlv->pc: %d, tlv->tag: %d",
     *      tlv->class, tlv->p_c, tlv->tag);
     *      g_debug("tlv->longform: %d, tlv->length %d", tlv->longform,
     * tlv->length);*/
}
