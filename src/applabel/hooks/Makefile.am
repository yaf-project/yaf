##  Copyright 2012-2025 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (source)
##  autotools build system for YAF
##  ------------------------------------------------------------------------
##  Authors: Chris Inacio
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
AM_CPPFLAGS = -I$(top_srcdir)/src/applabel $(YAF_CPPFLAGS) $(GLIB_CFLAGS) \
	$(OPENSSL_CPPFLAGS) $(libfixbuf_CFLAGS)

HOOK_MODULE_FLAGS = -version-info $(version_info) -module

if CYGWIN
AM_CPPFLAGS += -DYAF_CONF_DIR='yfGetCygwinConfDir()'
else
AM_CPPFLAGS += -DYAF_CONF_DIR='"$(sysconfdir)"'
endif


pkglib_LTLIBRARIES = dpacketplugin.la dhcp_fp_plugin.la

dpacketplugin_la_SOURCES = dpacketplugin.c dpacketplugin.h
dpacketplugin_la_LDFLAGS = $(HOOK_MODULE_FLAGS) $(OPENSSL_LDFLAGS)

dhcp_fp_plugin_la_SOURCES = dhcp_fp_plugin.c
dhcp_fp_plugin_la_LDFLAGS = $(HOOK_MODULE_FLAGS)
