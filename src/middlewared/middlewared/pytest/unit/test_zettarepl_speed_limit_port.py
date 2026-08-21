from pathlib import Path

PORT = Path(__file__).parents[5] / 'nas_ports/sysutils/py-zettarepl'
PATCH = PORT / 'files/patch-zettarepl_transport_ssh.py'


def test_speed_limit_pipes_through_mbuffer_not_throttle():
    # the internal development record: throttle is not in the image; upstream zettarepl
    # 338301302dd5 replaced it with mbuffer.
    text = PATCH.read_text()
    removed = [line for line in text.splitlines() if line.startswith('-') and not line.startswith('---')]
    added = [line for line in text.splitlines() if line.startswith('+') and not line.startswith('+++')]

    assert text.startswith('--- zettarepl/transport/ssh.py.orig\n+++ zettarepl/transport/ssh.py\n')
    assert removed == ['-                send = pipe(send, ["throttle", "-B", str(self.speed_limit)])']
    assert not any('throttle' in line for line in added)
    assert '+                    "mbuffer",' in added
    for option in ('"-m", f"{self.speed_limit}b"', '"-r", str(self.speed_limit)', '"-R", str(self.speed_limit)'):
        assert any(option in line for line in added), option


def test_port_depends_on_mbuffer():
    makefile = (PORT / 'Makefile').read_text()
    assert 'mbuffer:misc/mbuffer' in makefile
