##  Copyright 2005-2025 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (documentation)
##  autotools build system for NAF applications
##  ------------------------------------------------------------------------
##  Authors: Brian Trammell
##  ------------------------------------------------------------------------
##  @DISTRIBUTION_STATEMENT_BEGIN@
##  YAF 2.16
##
##  Copyright 2024 Carnegie Mellon University.
##
##  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
##  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
##  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
##  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
##  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
##  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
##  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
##  INFRINGEMENT.
##
##  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
##  contact permission@sei.cmu.edu for full terms.
##
##  [DISTRIBUTION STATEMENT A] This material has been approved for public
##  release and unlimited distribution.  Please see Copyright notice for
##  non-US Government use and distribution.
##
##  This Software includes and/or makes use of Third-Party Software each
##  subject to its own license.
##
##  DM24-1063
##  @DISTRIBUTION_STATEMENT_END@
##  ------------------------------------------------------------------------

docs: releases.xml

releases.xml: $(top_srcdir)/NEWS
	$(AM_V_GEN)$(PERL) $(srcdir)/news2xhtml.pl < "$<" > "$@" || { rm -f "$@" ; exit 1 ; }


CLEANFILES = releases.xml

YF_TUTORIAL_MD = \
    howto/yaf_orcus.md \
    howto/yaf_pcap.md \
    howto/yaf_pcap2.md \
    howto/yaf_service.md \
    howto/yaf_silk.md \
    howto/yaf_super_pipeline.md \
    howto/yaf_super_silk.md

EXTRA_DIST = \
    Doxyfoot.html \
    Doxyhead.html \
    add-header.pl \
    doxygen.css \
    news2xhtml.pl \
    $(YF_TUTORIAL_MD)



