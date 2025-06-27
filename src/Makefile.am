##  Copyright 2006-2025 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (source)
##  autotools build system for YAF
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


SUBDIRS = applabel

AM_CFLAGS = $(WARN_CFLAGS) $(DEBUG_CFLAGS)
AM_CPPFLAGS = $(YAF_CPPFLAGS) $(LTDLINCL) $(GLIB_CFLAGS) \
	$(OPENSSL_CPPFLAGS) $(libfixbuf_CFLAGS)
AM_LDFLAGS = $(libfixbuf_LIBS) $(GLIB_LIBS)
LDADD = libyaf.la $(top_builddir)/airframe/src/libairframe.la \
    $(GLIB_LDADD) $(LIBLTDL)

CPPFLAGS_YAF_COMMON = \
	$(AM_CPPFLAGS) \
	$(libp0f_CFLAGS) $(libndpi_CFLAGS) $(SPREAD_CFLAGS) \
	-DYAF_CONF_DIR='"$(sysconfdir)"' -DYAF_APPLABEL_PATH=\"${libdir}/yaf\"
LDFLAGS_YAF_COMMON = \
	$(AM_LDFLAGS) \
	$(libp0f_LIBS) $(libndpi_LIBS) $(SPREAD_LDFLAGS) $(SPREAD_LIBS)

PODFILES = yaf.pod.in yafscii.pod applabel.pod.in yafdpi.pod.in \
    yafdhcp.pod yaf.init.pod
HTMLFILES = yaf.html yafscii.html applabel.html yafdpi.html \
    yafdhcp.html yaf.init.html
man1_MANS = yaf.1 yafscii.1 applabel.1 yafdpi.1 \
    yafdhcp.1 yaf.init.1

EXTRA_DIST = $(PODFILES)


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

clean-local:
	rm -f pod2htm*.tmp

lib_LTLIBRARIES = libyaf.la
bin_PROGRAMS = yaf yafscii yafcollect

libyaf_la_SOURCES  = \
	yafcore.c yafctx.h yaftab.c yafrag.c decode.c picq.c ring.c \
	yafapplabel.c yafapplabel.h \
	applabel/payloadScanner.c applabel/payloadScanner.h \
	applabel/portHash.c applabel/portHash.h
libyaf_la_LIBADD = $(LIBLTDL)
libyaf_la_LDFLAGS  = \
	$(LDFLAGS_YAF_COMMON) \
	-version-info $(LIBCOMPAT) -release $(VERSION)
libyaf_la_CPPFLAGS = \
	$(CPPFLAGS_YAF_COMMON)

if PLUGINENABLE
libyaf_la_SOURCES += yafhooks.c
endif

if P0FENABLE
libyaf_la_SOURCES += applabel/p0f/crc32.c applabel/p0f/p0ftcp.h \
	applabel/p0f/yfp0f.c applabel/p0f/yfp0f.h
endif

if CYGWIN
libyaf_la_SOURCES += yafcygwin.c
endif

yaf_SOURCES  = \
	yaf.c yafstat.c yafstat.h yafdag.c yafdag.h yafcap.c yafcap.h \
	yafout.c yafout.h yaflush.c yaflush.h yafpcapx.c yafpcapx.h \
	yafnfe.c yafnfe.h yafpfring.c yafpfring.h
yaf_LDADD    = $(LDADD) $(top_builddir)/lua/src/liblua.la
yaf_LDFLAGS  = $(LDFLAGS_YAF_COMMON) -export-dynamic
yaf_CPPFLAGS = $(CPPFLAGS_YAF_COMMON)

yafscii_SOURCES = yafscii.c

yafcollect_SOURCES = yafcollect.c


BUILT_SOURCES = infomodel.c infomodel.h
nodist_libyaf_la_SOURCES = infomodel.c infomodel.h
CLEANFILES += infomodel.c infomodel.h

RUN_MAKE_INFOMODEL = $(AM_V_GEN) \
 srcdir=$(top_builddir) ; \
 test -f $(top_builddir)/make-infomodel || srcdir=$(top_srcdir) ; \
 $(PERL) $${srcdir}/make-infomodel --package $(PACKAGE) --dir-name=$(top_builddir)/infomodel $(INFOMODEL_REGISTRY_PREFIXES)

infomodel.c : infomodel.h
infomodel.h : $(top_builddir)/make-infomodel Makefile
	$(RUN_MAKE_INFOMODEL)
