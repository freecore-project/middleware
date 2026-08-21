#!/bin/sh
# FreeCORE jail-init (the internal development record): run a lifted jail's rc(8) system
# as the container's process, exactly the way jail(8) does with exec.start and
# exec.stop. The container stops when rc.shutdown has run.
stop() {
	echo "jail-init: stopping"
	/bin/sh /etc/rc.shutdown jail
	exit 0
}
trap stop TERM INT
/bin/sh /etc/rc
echo "jail-init: rc(8) finished, holding"
while :; do
	sleep 60 &
	wait $!
done
