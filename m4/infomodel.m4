dnl Copyright (C) 2018-2025 Carnegie Mellon University
dnl See license information in LICENSE.txt.

dnl @DISTRIBUTION_STATEMENT_BEGIN@
dnl YAF 2.16
dnl
dnl Copyright 2024 Carnegie Mellon University.
dnl
dnl NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
dnl INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
dnl UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
dnl AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
dnl PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
dnl THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
dnl ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
dnl INFRINGEMENT.
dnl
dnl Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
dnl contact permission@sei.cmu.edu for full terms.
dnl
dnl [DISTRIBUTION STATEMENT A] This material has been approved for public
dnl release and unlimited distribution.  Please see Copyright notice for
dnl non-US Government use and distribution.
dnl
dnl This Software includes and/or makes use of Third-Party Software each
dnl subject to its own license.
dnl
dnl DM24-1063
dnl @DISTRIBUTION_STATEMENT_END@

# ---------------------------------------------------------------------------
# INFOMODEL_AC_COLLECT_REGISTRIES(infomodel_dir)
#
#    Create a list of infomodel IE registries located in
#    $(top_srcdir)/$infomodel_dir.  Place the list of registry names in
#    INFOMODEL_REGISTRIES.  Place a list of registry names in
#    INFOMODEL_REGISTRY_PREFIXES.  Place a list of registry include
#    files in INFOMODEL_REGISTRY_INCLUDE_FILES.  Place a list of
#    registry include dependencies based from $srcdir in
#    INFOMODEL_REGISTRY_INCLUDES.
#
#    Output variables: INFOMODEL_REGISTRIES INFOMODEL_REGISTRY_PREFIXES
#        INFOMODEL_REGISTRY_INCLUDE_FILES INFOMODEL_REGISTRY_INCLUDES
#
AC_DEFUN([INFOMODEL_AC_COLLECT_REGISTRIES],[
    AC_SUBST(INFOMODEL_REGISTRY_PREFIXES)
    AC_SUBST(INFOMODEL_REGISTRY_INCLUDES)
    AC_SUBST(INFOMODEL_REGISTRY_INCLUDE_FILES)
    AC_SUBST(INFOMODEL_REGISTRIES)

    AC_MSG_CHECKING([for information element files])
    files=[`echo $][srcdir/$1/[A-Za-z0-9_]*.xml`]
    prefixes=[`echo $files | sed 's,[^ ]*/\([^/ ]*\)\.xml,\1,g'`]
    xml=[`echo $prefixes | sed 's,\([^ ]*\),\1.xml,g'`]
    inc_files=[`echo $prefixes | sed 's,\([^ ]*\),\1.i,g'`]
    includes=[`echo $inc_files | sed 's,\([^ ]*\),$(top_builddir)/$1/\1,g'`]
    INFOMODEL_REGISTRY_PREFIXES=$prefixes
    INFOMODEL_REGISTRY_INCLUDE_FILES=$inc_files
    INFOMODEL_REGISTRY_INCLUDES=$includes
    INFOMODEL_REGISTRIES=$xml
    AC_MSG_RESULT([$1/{$INFOMODEL_REGISTRY_PREFIXES}])
])
