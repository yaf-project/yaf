/*
 *  Copyright 2007-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  ring.c
 *  General ring array implementation
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

#ifndef _YAF_RING_H_
#define _YAF_RING_H_
#include <yaf/autoinc.h>

struct rgaRing_st;
typedef struct rgaRing_st rgaRing_t;

rgaRing_t *
rgaAlloc(
    size_t   elt_sz,
    size_t   cap);

void
rgaFree(
    rgaRing_t  *ring);

uint8_t *
rgaNextHead(
    rgaRing_t  *ring);

void
rgaRewindHead(
    rgaRing_t  *ring);

uint8_t *
rgaNextTail(
    rgaRing_t  *ring);

size_t
rgaCount(
    rgaRing_t  *ring);

size_t
rgaPeak(
    rgaRing_t  *ring);

#if YAF_RING_THREAD

rgaRing_t *
rgaAllocThreaded(
    size_t   elt_sz,
    size_t   cap);

uint8_t *
rgaWaitHead(
    rgaRing_t  *ring);

void
rgaReleaseHead(
    rgaRing_t  *ring,
    size_t      rsv);

uint8_t *
rgaWaitTail(
    rgaRing_t  *ring);

void
rgaReleaseTail(
    rgaRing_t  *ring,
    size_t      rsv);

void
rgaSetInterrupt(
    rgaRing_t  *ring);

void
rgaClearInterrupt(
    rgaRing_t  *ring);

#endif /* if YAF_RING_THREAD */
#endif /* ifndef _YAF_RING_H_ */
