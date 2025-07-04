##  Copyright 2006-2025 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (source)
##  autotools build system for YAF
##  ------------------------------------------------------------------------
##  Authors: Emily Sarneso
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

AM_CFLAGS = $(WARN_CFLAGS) $(DEBUG_CFLAGS)
AM_CPPFLAGS = $(YAF_CPPFLAGS) $(GLIB_CFLAGS) \
	$(OPENSSL_CPPFLAGS) $(libfixbuf_CFLAGS)
AM_LDFLAGS = $(libfixbuf_LIBS) $(GLIB_LIBS)
LDADD = $(top_builddir)/airframe/src/libairframe.la $(GLIB_LDADD)

PODFILES = getFlowKeyHash.pod yafMeta2Pcap.pod yafzcbalance.pod
man1_MANS = getFlowKeyHash.1 yafMeta2Pcap.1
HTMLFILES = getFlowKeyHash.html yafMeta2Pcap.html yafzcbalance.html

bin_PROGRAMS = getFlowKeyHash yafMeta2Pcap

if HASPFRINGZC
bin_PROGRAMS += yafzcbalance
man1_MANS += yafzcbalance.1
endif

.pod.1:
	$(AM_V_GEN) $(POD2MAN) $(YAF_POD2MAN_ARGS) --section=1 $< $@

.pod.html:
	$(POD2HTML) --noindex --infile="$<" --outfile="$@"
	$(top_srcdir)/doc/add-header.pl "$@"

copy-man-pages: $(HTMLFILES)
	mkdir -p $(top_builddir)/doc/html
	cp $(HTMLFILES) $(top_builddir)/doc/html

dist-hook: $(HTMLFILES)
	mkdir -p $(top_distdir)/doc/html
	cp $(HTMLFILES) $(top_distdir)/doc/html

docs: $(man1_MANS) copy-man-pages

clean-docs:
	rm -f $(man1_MANS) $(HTMLFILES)

CLEANFILES = $(man1_MANS) $(HTMLFILES)

EXTRA_DIST = $(PODFILES)

clean-local:
	rm -f pod2htm*.tmp

getFlowKeyHash_SOURCES = getFlowKeyHash.c

yafMeta2Pcap_SOURCES = yafMeta2Pcap.c

yafzcbalance_SOURCES = yafzcbalance.c
yafzcbalance_LDFLAGS = $(GLIB_LIBS) -lpthread
yafzcbalance_CPPFLAGS = $(YAF_CPPFLAGS) $(GLIB_CFLAGS)
