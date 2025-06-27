/*
 *  Copyright 2006-2025 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  picq.c
 *  General pickable queue implementation
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
#include <yaf/picq.h>

typedef struct _PicQNode {
    struct _PicQNode  *p;
    struct _PicQNode  *n;
} PicQNode;

typedef struct _PicQ {
    PicQNode  *tail;
    PicQNode  *head;
} PicQ;

void
piqPick(
    void  *vq,
    void  *vn)
{
    PicQ     *queue = (PicQ *)vq;
    PicQNode *node = (PicQNode *)vn;

    /* only allow picking a double-null node if it's both head and tail. */
    if (!node->n && !node->p &&
        !(node == queue->head && node == queue->tail))
    {
        return;
    }

    /* connect previous to next */
    if (node->p) {
        node->p->n = node->n;
    } else {
        queue->tail = node->n;
    }

    /* connect next to previous */
    if (node->n) {
        node->n->p = node->p;
    } else {
        queue->head = node->p;
    }

    /* mark node picked */
    node->n = NULL;
    node->p = NULL;
}


void
piqEnQ(
    void  *vq,
    void  *vn)
{
    PicQ     *queue = (PicQ *)vq;
    PicQNode *node = (PicQNode *)vn;

    g_assert(!node->n && !node->p);

    if (queue->head) {
        queue->head->n = node;
    } else {
        queue->tail = node;
    }

    node->p = queue->head;
    queue->head = node;
}


void
piqUnshift(
    void  *vq,
    void  *vn)
{
    PicQ     *queue = (PicQ *)vq;
    PicQNode *node = (PicQNode *)vn;

    g_assert(!node->n && !node->p);

    if (queue->tail) {
        queue->tail->p = node;
    } else {
        queue->head = node;
    }

    node->n = queue->tail;
    queue->tail = node;
}


void *
piqShift(
    void  *vq)
{
    PicQ     *queue = (PicQ *)vq;
    PicQNode *node = NULL;

    if (queue->head) {
        node = queue->head;
        piqPick(queue, node);
    }
    return node;
}


void *
piqDeQ(
    void  *vq)
{
    PicQ     *queue = (PicQ *)vq;
    PicQNode *node = NULL;

    if (queue->tail) {
        node = queue->tail;
        piqPick(queue, node);
    }
    return node;
}
