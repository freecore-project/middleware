"""the internal development record: the shipped devfs.rules defines Bastille's VNET ruleset.

Bastille 1.4.0 hard-codes `devfs_ruleset = 13` for its VNET jails and leaves the
definition to `bastille setup vnet`, which the appliance never runs and whose
result /etc would lose at the next boot anyway. An undefined ruleset hides nothing,
so the image must carry the definition itself, and it must stay what upstream's
setup.sh writes.
"""
import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
DEVFS_RULES = REPOSITORY_ROOT / 'src/freenas/etc/devfs.rules'

# `configure_vnet` in Bastille 1.4.0.260219's setup.sh, verbatim.
BASTILLE_VNET_RULESET = '''[bastille_vnet=13]
add include $devfsrules_hide_all
add include $devfsrules_unhide_basic
add include $devfsrules_unhide_login
add include $devfsrules_jail
add include $devfsrules_jail_vnet
add path 'bpf*' unhide
'''


def rulesets():
    """Map each `[name=number]` heading to its rule lines, comments dropped."""
    result = {}
    current = None
    for line in DEVFS_RULES.read_text(encoding='utf8').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        heading = re.fullmatch(r'\[(?P<name>[a-z_]+)=(?P<number>\d+)\]', stripped)
        if heading:
            current = (heading['name'], int(heading['number']))
            result[current] = []
            continue
        assert current is not None, f'rule outside any ruleset: {line!r}'
        result[current].append(stripped)
    return result


def test_the_image_defines_bastilles_vnet_ruleset_exactly_as_upstream_would():
    defined = rulesets()

    assert ('bastille_vnet', 13) in defined
    expected = [line for line in BASTILLE_VNET_RULESET.splitlines()[1:] if line]
    assert defined[('bastille_vnet', 13)] == expected


def test_the_inherited_usb_ruleset_is_still_there():
    # `devfs_system_ruleset="usbrules"` in the shipped rc.conf applies this one to /dev.
    defined = rulesets()

    assert ('usbrules', 100) in defined
    assert "add path 'usbctl' mode 660 group uucp" in defined[('usbrules', 100)]


def test_ruleset_numbers_do_not_collide_with_the_freebsd_defaults():
    # /etc/defaults/devfs.rules owns 1-5; a duplicate number would silently merge rules.
    numbers = [number for _, number in rulesets()]

    assert all(number > 5 for number in numbers)
    assert len(numbers) == len(set(numbers))
