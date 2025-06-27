/*
 *  Copyright 2007-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafapplabel.h
 *  This defines the interface to the YAF application labeler.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio
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

#ifndef YAF_APP_LABEL_H_
#define YAF_APP_LABEL_H_

#define _YAF_SOURCE_
#include <yaf/autoinc.h>

#if YAF_ENABLE_APPLABEL

#include <yaf/yafcore.h>
#include <yaf/decode.h>

#include "applabel/payloadScanner.h"


/**
 * Initializes the application labeler engine from a specified rules file.
 *
 * @param ruleFileName the name of the file to use for the rules
 *        of the app labeler engine.
 * @param err an error descriptor.
 *
 * @return TRUE on success, FALSE otherwise
 */
gboolean
yfAppLabelInit(
    const char  *ruleFileName,
    GError     **err);

/**
 * Labels a flow's protocol according to its payload. Sets the appLabel
 * field within the flow.
 *
 * @param flow A YAF flow.
 *
 */
void
yfAppLabelFlow(
    yfFlow_t  *flow);

#endif /* YAF_ENABLE_APPLABEL */

#endif /* ifndef YAF_APP_LABEL_H_ */
