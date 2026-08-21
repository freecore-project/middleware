"""the internal development record: jib serialises the actions that change bridges."""
import os
import subprocess
from pathlib import Path

import pytest

JIB = Path(__file__).resolve().parents[4] / 'freenas' / 'usr' / 'local' / 'bin' / 'jib'


def source():
    return JIB.read_text()


def test_the_script_parses():
    assert subprocess.run(['/bin/sh', '-n', str(JIB)], capture_output=True).returncode == 0


def test_bridge_changing_actions_run_under_the_lock_before_the_dispatch():
    text = source()
    lock = text.index('/usr/bin/lockf -k -t 60 "$JIB_LOCK" /bin/sh "$0" "$@"')
    dispatch = text.index('eval "jib_$action"')
    stanza = text[text.index('case "$action" in'):lock]

    assert lock < dispatch
    assert 'addm|destroy)' in stanza
    # The re-executed copy must not take the lock again.
    assert '[ -z "$JIB_LOCKED" ]' in stanza and 'JIB_LOCKED=1' in text[:lock]


def test_a_bridge_that_cannot_take_the_interface_is_destroyed():
    text = source()
    create = text.index('new=$( ifconfig bridge create )')
    block = text[create:text.index('ifconfig $new name "$iface$bridge"', create)]

    assert 'if ! ifconfig $new addm $iface; then' in block
    assert 'ifconfig $new destroy' in block and 'return 1' in block


@pytest.mark.skipif(not os.access('/usr/bin/lockf', os.X_OK), reason='needs lockf(1)')
def test_two_locked_actions_do_not_overlap(tmp_path):
    """The lock stanza on its own: two `addm` calls never run their body at the same time."""
    text = source()
    stanza = text[text.index('JIB_LOCK=/var/run/jib.lock'):text.index('#\n# Validate action argument')]
    script = tmp_path / 'jib'
    log = tmp_path / 'log'
    script.write_text(
        '#!/bin/sh\naction="$1"\n' + stanza.replace('/var/run/jib.lock', str(tmp_path / 'lock')) +
        f'echo "start $2" >> {log}; sleep 0.4; echo "end $2" >> {log}\n'
    )
    script.chmod(0o755)

    procs = [subprocess.Popen([str(script), 'addm', name]) for name in ('a', 'b')]
    assert [proc.wait() for proc in procs] == [0, 0]

    lines = log.read_text().split()
    words = [lines[i] for i in range(0, len(lines), 2)]
    assert words == ['start', 'end', 'start', 'end']
