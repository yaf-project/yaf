Explanation of YAF services {#yaf_service}
==========================================

<!--
    Copyright 2024 Carnegie Mellon University
    See license information in LICENSE.txt.
-->
<!--
    @DISTRIBUTION_STATEMENT_BEGIN@
    YAF 2.16

    Copyright 2024 Carnegie Mellon University.

    NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
    INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
    UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
    AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
    PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
    THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
    ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
    INFRINGEMENT.

    Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
    contact permission@sei.cmu.edu for full terms.

    [DISTRIBUTION STATEMENT A] This material has been approved for public
    release and unlimited distribution.  Please see Copyright notice for
    non-US Government use and distribution.

    This Software includes and/or makes use of Third-Party Software each
    subject to its own license.

    DM24-1063
    @DISTRIBUTION_STATEMENT_END@
-->

This page explains the service features included with YAF.

* [systemd](#systemd)
  * [Instantiated Services](#instantiated_services)
* [init.d](#init_d)

systemd {#systemd}
==================

On systems that support it, systemd is an option for managing yaf services (as
of YAF 2.16.0). The implementation of yaf as a systemd service is intended to
provide an easy transition for those migrating from the init.d service
implementation.

When running a yaf service for the first time, you must first modify the
configuration file, ``yaf.conf``, with relevant parameters for your intended
use. If you are upgrading from a previous version of yaf, your configuration
file will have persisted during the upgrade. The ``yaf.conf`` file is
typically found in ``/etc``.

>   **Note:** The ``yaf.conf`` configuration file in this document sets shell
>   variables that are used when starting yaf, and the file is unrelated to
>   the [``yaf.init``](https://tools.netsa.cert.org/yaf2/yaf.init.html) file,
>   written in Lua, that is the argument to ``yaf``'s ``--config`` option.

Once the configuration file is completed, starting yaf as a service is the
same as starting any other systemd service:

    # systemctl start yaf.service

Checking the service's status and stopping the service are also typical:

    # systemctl status yaf.service

and:

    # systemctl stop yaf.service

Instantiated Services {#instantiated_services}
----------------------------------------------

With systemd functionality comes the ability to start a yaf service as an
instance, with a unique configuration per instance.

To start YAF as an instantiated service, you must create a unique
configuration file in the configuration file directory. The config file
should be named ``yaf.foo.conf`` where **foo** is the name you want to give
your instantiated service. Once this is done, you can start the instantiated
service by passing your service name.

For example:

    # systemctl start yaf@foo.service

starts an instantiated service using the configuration file yaf.foo.conf.

init.d {#init_d}
================

For systems that do not support systemd, the init.d service script is still
available, however this capability is not present when installing via rpm.

(For YAF 2.15.0 or earlier, the init.d capability is installed by the rpm and
administrators should follow the instructions in this section.)

Running a yaf service using init.d is very similar to using systemd. The
``yaf.conf`` configuration file must be configured prior to first use with
the parameters you want the service to use. The configuration file is
typically located in ``/etc``.

Once your configuration file is complete, you can start the yaf service
using the following command:

    # service yaf start

You can stop the service or check its status using:

    # service yaf stop

and

    # service yaf status

The init.d service has one additional feature that does not exist in
systemd: dumpstats. This sends a signal to the service telling it write its
collection statistics to the yaf log, and the service continues to run. The
command has no effect if yaf is not running. It can be called using the
command:

    # service yaf dumpstats

One can mimic the [instantiated services](#instantiated_services) of systemd
by creating a configuration file ``/etc/yaf-foo.conf`` and either copying or
linking ``/etc/init.d/yaf`` to ``/etc/init.d/yaf-foo``.

    # ln /etc/init.d/yaf /etc/init.d/yaf-foo

Running

    # service yaf-foo start

will use the configuration settings in ``/etc/yaf-foo.conf``. This approach
should only be used on systems which do not support systemd, and it is not
forward-compatible with systemd.



[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
