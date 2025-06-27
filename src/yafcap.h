/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafcap.h
 *  YAF libpcap input support
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

#ifndef _YAF_CAP_H_
#define _YAF_CAP_H_

#include <yaf/autoinc.h>
#include "yafctx.h"

struct yfCapSource_st;
typedef struct yfCapSource_st yfCapSource_t;

yfCapSource_t *
yfCapOpenFile(
    const char  *path,
    int         *datalink,
    const char  *tmp_dir,
    GError     **err);

yfCapSource_t *
yfCapOpenFileList(
    const char  *path,
    int         *datalink,
    const char  *tmp_dir,
    GError     **err);

yfCapSource_t *
yfCapOpenLive(
    const char  *ifname,
    int          snaplen,
    int         *datalink,
    GError     **err);

void
yfSetPromiscMode(
    int   mode);

void
yfCapClose(
    yfCapSource_t  *pcap);

gboolean
yfCapMain(
    yfContext_t  *ctx);

void
yfCapDumpStats(
    void);

#endif /* ifndef _YAF_CAP_H_ */
