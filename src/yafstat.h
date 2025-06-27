/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafstat.h
 *  YAF Statistics Signal Handler
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

#ifndef _YAF_STAT_H_
#define _YAF_STAT_H_

#include <yaf/autoinc.h>
#include "yafctx.h"

void
yfStatInit(
    yfContext_t  *ctx);

void
yfStatDumpLoop(
    void);

void
yfStatComplete(
    void);

GTimer *
yfStatGetTimer(
    void);

#endif /* ifndef _YAF_STAT_H_ */
