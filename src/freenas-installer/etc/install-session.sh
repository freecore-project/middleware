#!/bin/sh
#
# the internal development record: getty(8) starts this as the login program of the
# installer's autologin sessions (argv: login -fp root), with the console as
# controlling terminal and TERM set by init(8) from /etc/ttys.  getty's
# arguments are dropped: install.sh reads its own arguments as an unattended
# install.  When the installer exits, getty is respawned and it starts again.
exec /etc/install.sh
