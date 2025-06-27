dnl -*- mode: autoconf -*-
dnl Copyright (C) 2004-2025 Carnegie Mellon University
dnl See license information in LICENSE.txt.

dnl ------------------------------------------------------------------------
dnl ax_lib_openssl.m4
dnl ------------------------------------------------------------------------
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
dnl ------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AX_LIB_OPENSSL
#
#   Check for the OpenSSL library (-lssl -lcrypt) and header files.
#
#   Expects three arguments:
#
#   1. First should be "yes", "no", or "auto". "yes" means to fail if
#   OpenSSL cannot be found unless the user explicitly disables it.
#   "no" means only use OpenSSL when requested by the user. "auto" (or
#   any other value) means to check for OpenSSL unless disabled by the
#   user, but do not error if it is not found.  It is a fatal error if
#   the user specifies --with-openssl and it cannot be found.
#
#   2. Second is the minimum version to accept.
#
#   3. Third is the help string to print for the --with-openssl argument.
#
#   Output definitions: HAVE_EVP_MD5, HAVE_EVP_MD_FETCH, HAVE_EVP_Q_DIGEST,
#   HAVE_EVP_SHA1, HAVE_EVP_SHA256, HAVE_MD5, HAVE_OPENSSL,
#   HAVE_OPENSSL_EVP_H, HAVE_OPENSSL_MD5_H, HAVE_OPENSSL_SHA_H, HAVE_SHA1,
#   HAVE_SHA256
#
AC_DEFUN([AX_LIB_OPENSSL],[
    default="$1"
    ssl_min_version="$2"
    m4_define(openssl_helpstring,[[$3]])

    YF_HAVE_OPENSSL=

    AC_SUBST([OPENSSL_CPPFLAGS])
    AC_SUBST([OPENSSL_LDFLAGS])

    if test "x${default}" = xyes
    then
        request_require=required
    else
        request_require=requested
    fi

    AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl@<:@=DIR@:>@],dnl
        openssl_helpstring)],[],
    [
        # Option not given, use default
        if test "x${default}" = xyes || test "x${default}" = xno
        then
            with_openssl="${default}"
        fi
    ])

    if test "x${with_openssl}" = xno
    then
        AC_MSG_NOTICE([not checking for openssl])
    else
        # If an argument is given, prepend it to PKG_CONFIG_PATH
        yf_save_PKG_CONFIG_PATH="${PKG_CONFIG_PATH}"
        if test -n "${with_openssl}" && test "x${with_openssl}" != xyes
        then
            PKG_CONFIG_PATH="${with_openssl}${PKG_CONFIG_PATH+:${PKG_CONFIG_PATH}}"
            export PKG_CONFIG_PATH

            if expr "x${with_openssl}" : '.*/pkgconfig$' > /dev/null
            then
                :
            else
                AC_MSG_WARN([Argument to --with-openssl should probably end with '/pkgconfig'])
            fi
        fi

        # Check for the module
        PKG_CHECK_MODULES([openssl],
            [openssl >= ${ssl_min_version}],
            [YF_HAVE_OPENSSL=yes],dnl
        [
            if test "x${with_openssl}" != x
            then
                AC_MSG_WARN([pkg-config cannot find a suitable openssl (>= ${ssl_min_version}). Do you need to install openssl-devel or adjust PKG_CONFIG_PATH?: $openssl_PKG_ERRORS])
                AC_MSG_ERROR([openssl is ${request_require} but is not found; use --with-openssl=no to disable])
            else
                AC_MSG_NOTICE([not building with OpenSSL support])
            fi
        ])

        if test -n "${yf_save_PKG_CONFIG_PATH}"
        then
            PKG_CONFIG_PATH="${yf_save_PKG_CONFIG_PATH}"
        fi
    fi

    if test "x${YF_HAVE_OPENSSL}" = xyes
    then
        # pkg-config found openssl; try to compile a program using it
        yf_save_CFLAGS="${CFLAGS}"
        yf_save_LIBS="${LIBS}"
        CFLAGS="${CFLAGS} ${openssl_CFLAGS}"
        LIBS="${openssl_LIBS} ${LIBS}"

        AC_MSG_CHECKING([usability of openssl library and headers])
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([
#include <stdio.h>
#include <openssl/evp.h>
                ],[[
const char text[] = "foobar";
const EVP_MD *digest_type;
unsigned char digest[EVP_MAX_MD_SIZE];
unsigned int sz = 0;
int rv;

digest_type = EVP_md_null();
rv = EVP_Digest(text, sizeof(text), digest, &sz, digest_type, NULL);
printf("%d\n", rv);
                 ]])],
             [],[YF_HAVE_OPENSSL=]
        )

        if test "x${YF_HAVE_OPENSSL}" != xyes
        then
            AC_MSG_RESULT([no])
            AC_MSG_WARN([pkg-config found openssl but configure cannot compile a program that uses it. Details in config.log.])
            if test "x${with_openssl}" != x
            then
                AC_MSG_ERROR([openssl is ${request_require} but unable to use it; use --with-openssl=no to disable])
            else
                AC_MSG_NOTICE([building without OpenSSL])
            fi
        else
            AC_MSG_RESULT([yes])
            AC_MSG_NOTICE([building with OpenSSL support])
            AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 to enable OpenSSL support])
            AC_SUBST([YAF_PC_OPENSSL],["openssl >= ${ssl_min_version},"])
            OPENSSL_CPPFLAGS="${openssl_CFLAGS}"
            OPENSSL_LDFLAGS="${openssl_LIBS}"

            # Additional functions and headers to check for; no error
            AC_CHECK_FUNCS([EVP_Q_digest EVP_MD_fetch EVP_md5 EVP_sha1 EVP_sha256 MD5 SHA1 SHA256])
            AC_CHECK_HEADERS([openssl/sha.h openssl/md5.h])
        fi

        # Restore values
        CFLAGS="${yf_save_CFLAGS}"
        LIBS="${yf_save_LIBS}"
    fi
])
