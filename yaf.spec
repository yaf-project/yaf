##  Copyright 2006-2025 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  yaf.spec: Generated from yaf.spec.in by make.

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

#   The following --with X and --without X options are supported with
#   the default shown in brackets.
#
#   These require no special libraries:
#
#   applabel [with]: enables protocol detection only
#   entropy [without]: enables Shannon Entropy calculation
#   fpexporter [without]: enables export of handshake headers for external
#                         fingerprinting
#   plugins [with]: enables plugin support (dpacketplugin,dhcpplugin)
#
#   These require additional libraries:
#
#   napatech [without]: Supports collection with Napatech cards
#   ndpi [without]: Supports nDPI packet analysis from ntop
#   p0f [without]: Supports p0f-based OS fingerprinting (libp0f)
#   pfring [without]: Supports PF_RING collection from ntop

%if %{defined bcond}
%bcond applabel    1
%bcond entropy     0
%bcond fpexporter  0
%bcond plugins     1
%bcond napatech    0
%bcond ndpi        0
%bcond p0f         0
%bcond pfring      0
%else
%if %{defined bcond_with}
# Default is to build with applabel and plugins; add options to
# disable them
%bcond_without  applabel
%bcond_without  plugins
# Default is to build without entropy, fpexporter, napatech, ndpi,
# p0f, and pfring; add options to enable them
%bcond_with     entropy
%bcond_with     fpexporter
%bcond_with     napatech
%bcond_with     ndpi
%bcond_with     p0f
%bcond_with     pfring
%endif
%endif

%if %{with plugins}
%if !%{with applabel}
%define enable_applabel 1
%endif
%endif

%if %{with applabel}
%define enable_applabel 1
%endif

%define name    yaf
%define version 2.16.3
%define release 1%{!?with_applabel:_noApplabel}%{!?with_plugins:_noPlugins}%{?with_entropy:_entropy}%{?with_fpexporter:_fpexporter}%{?with_napatech:_napatech}%{?with_ndpi:_ndpi}%{?with_p0f:_p0f}%{?with_pfring:_pfring}%{?dist}

Summary:        Yet Another Flow sensor
Name:           %{name}
Version:        %{version}
Release:        %{release}
Group:          Applications/System
License:        GPLv2
Source:         https://tools.netsa.cert.org/releases/%{name}-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros
BuildRequires:  gcc, make, perl-interpreter
BuildRequires:  glib2-devel >= 2.34.0
BuildRequires:  libfixbuf-devel >= 2.3.0
BuildRequires:  libxslt
BuildRequires:  libpcap-devel
BuildRequires:  pkgconfig >= 0.16
BuildRequires:  zlib-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}
%if 0%{?enable_applabel:1}
BuildRequires:  pcre-devel >= 7.3
Requires:       pcre >= 7.3
%endif
%if %{with plugins}
BuildRequires:  openssl-devel >= 1.0.2
Requires:       openssl-libs >= 1.0.2
%endif
%if %{with ndpi}
# Note: The ndpi.spec file on their github uses "dev" and not "devel"
BuildRequires:  ndpi-dev
Requires:       ndpi
%endif
%if %{with libp0f}
Requires:       libp0f >= 2.0.8
%endif
%if %{with pfring}
Requires:       pfring
%endif
%if %{with napatech}
%define napatech_dir /opt/napatech3
BuildRequires:  nt-driver-3gd-devel nt_libpcap-devel
Requires:       nt-driver-3gd nt_libpcap
%endif
Vendor:         https://tools.netsa.cert.org/
URL:            https://tools.netsa.cert.org/yaf2/
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires:       glib2 >= 2.34.0
Requires:       libfixbuf >= 2.3.0
Requires:       libpcap
Requires:       zlib

# To apply a patch to the YAF sources: (1)put the patch file into the
# SOURCES directory of your rpmbuild area, (2)uncomment the 'Patch0:'
# line below and replace FILENAME with name of the patch file,
# (3)uncomment the 'patch0' line in the 'prep' section below.
#
# To apply another patch, repeat the process using the next sequential
# number.
#
#Patch0: FILENAME
#Patch1: FILENAME
#Patch2: FILENAME


%description
YAF is Yet Another Flow sensor. It processes packet data from pcap(3) dumpfiles
as generated by tcpdump(1) or via live capture from an interface using pcap(3)
or an Endace DAG card into bidirectional flows, then exports those flows to
IPFIX Collecting Processes or in an IPFIX-based file format. YAF's output can
be used with the SiLK tools, yafscii, and super_mediator.

%package devel
Summary:        Unversioned libraries and C header files for yaf
Group:          Development/Libraries
Requires:       %{name} = %{version}
Requires:       pkgconfig >= 0.16

%description devel
Unversioned libraries and C header files for yaf.

%prep
%setup -q -n %{name}-%{version}
#
# Uncomment the patch<N> line for each patch file named in the
# 'Patch<N>: FILENAME' lines above.
#
#%patch0 -p1
#%patch1 -p1
#%patch2 -p1

%build
%configure \
    --disable-doxygen-doc \
    --enable-interface=no \
    --enable-localtime=no \
    --enable-mpls=no \
    --enable-nonip=no \
    --enable-type-export=yes \
    --enable-applabel=%{?enable_applabel:yes}%{!?enable_applabel:no} \
    --enable-plugins=%{?with_plugins:yes}%{!?with_plugins:no} \
    --enable-entropy=%{?with_entropy:yes}%{!?with_entropy:no} \
    --enable-fpexporter=%{?with_fpexporter:yes}%{!?with_fpexporter:no} \
    --enable-ndpi=%{?with_ndpi:yes}%{!?with_ndpi:no} \
    --enable-p0fprinter=%{?with_p0f:yes}%{!?with_p0f:no} \
    --with-napatech=%{?napatech_dir}%{!?with_napatech:no} \
    --with-pfring=%{?with_pfring:yes}%{!?with_pfring:no} \
    --with-openssl=yes \
    --with-popt=no \
    --with-zlib=yes
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_bindir}
%make_install
rm -f $RPM_BUILD_ROOT/%{_libdir}/yaf/*.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/*.la

mkdir -p $RPM_BUILD_ROOT%{_unitdir}
mkdir -p $RPM_BUILD_ROOT%{_bindir}
mkdir -p $RPM_BUILD_ROOT%{_libexecdir}/yaf
install --mode=0644 etc/yaf.conf $RPM_BUILD_ROOT%{_sysconfdir}
install --mode=0644 etc/systemd/yaf.service $RPM_BUILD_ROOT%{_unitdir}
install --mode=0644 etc/systemd/yaf@.service $RPM_BUILD_ROOT%{_unitdir}
install --mode=0755 etc/systemd/yaf_startup $RPM_BUILD_ROOT%{_libexecdir}/yaf

%post
/sbin/ldconfig
%systemd_post yaf.service

%postun
/sbin/ldconfig
%systemd_postun_with_restart yaf.service

%preun
if test -e "/sbin/chkconfig" && chkconfig --list yaf 2>/dev/null ; then
    /sbin/chkconfig --del yaf
fi
%systemd_preun yaf.service

%clean
rm -rf $RPM_BUILD_ROOT

%files
%{_unitdir}/yaf.service
%{_unitdir}/yaf@.service
%{_libexecdir}/yaf/yaf_startup
%defattr(-, root, root)
%doc AUTHORS LICENSE.txt NEWS README doc/html/*.html
%{_bindir}/yaf
%{_bindir}/yafscii
%{_bindir}/yafcollect
%{_bindir}/airdaemon
%{_bindir}/filedaemon
%{_bindir}/getFlowKeyHash
%{_bindir}/yafMeta2Pcap
%{_libdir}/*.so.*
%if 0%{?enable_applabel:1}
%{_libdir}/yaf/*.so*
%endif
%{_mandir}/man*/*
%dir %{_datadir}/yaf
%{_datadir}/yaf/yaf.init
%if 0%{?enable_applabel:1}
%config(noreplace) %{_sysconfdir}/yafApplabelRules.conf
%endif
%if %{with plugins}
%config(noreplace) %{_sysconfdir}/yafDPIRules.conf
%config(noreplace) %{_sysconfdir}/dhcp_fingerprints.conf
%endif
%if %{with p0f}
%config(noreplace) %{_sysconfdir}/p0f.fp
%endif
%config(noreplace) %{_sysconfdir}/yaf.conf

%files devel
%doc doc/html/libyaf
%defattr(-, root, root)
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/pkgconfig/*

%changelog
