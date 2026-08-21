"""A PCI passthru device reaches bhyve once, through libvirt's <hostdev> (the internal development record).

Off-box like the other vm tests: the device is assembled by hand around its XML builder — no
libvirt, no middleware, no ppt device. libvirt >= 11.10.0 turns the <hostdev> element into the
bhyve `-s N:F,passthru,B/S/F` argument itself; the raw <bhyve:commandline> copy the class used
to add put the same device on the same slot twice ("pci slot 0:6:0 already occupied!").
"""
from xml.etree import ElementTree as etree

from middlewared.plugins.vm import PCI


def pci(host_bsf=(68, 0, 0), guest_bsf=(0, 6, 0)):
    device = object.__new__(PCI)
    device.data = {'id': 1, 'dtype': 'PCI', 'order': 1008, 'attributes': {'pptdev': '/'.join(map(str, host_bsf))}}
    device.middleware = None
    device.ppt_map = {'host_bsf': list(host_bsf), 'guest_bsf': list(guest_bsf)}
    return device


def as_element(xml):
    return xml if isinstance(xml, etree.Element) else etree.fromstring(str(xml))


def test_nothing_goes_on_the_bhyve_command_line():
    assert pci().bhyve_args() is None


def test_the_hostdev_element_carries_host_source_and_guest_address():
    hostdev = as_element(pci().xml())
    assert hostdev.tag == 'hostdev'
    assert (hostdev.get('mode'), hostdev.get('type'), hostdev.get('managed')) == ('subsystem', 'pci', 'no')
    source = hostdev.find('source/address')
    assert (source.get('bus'), source.get('slot'), source.get('function')) == ('0x0044', '0x0000', '0x0000')
    guest = hostdev.find('address')
    assert guest.get('type') == 'pci'
    assert (guest.get('bus'), guest.get('slot'), guest.get('function')) == ('0x0000', '0x0006', '0x0000')


def test_a_second_function_of_the_same_card_shares_the_guest_slot():
    audio = pci(host_bsf=(68, 0, 1), guest_bsf=(0, 6, 1))
    guest = as_element(audio.xml()).find('address')
    assert (guest.get('slot'), guest.get('function')) == ('0x0006', '0x0001')
    assert audio.bhyve_args() is None


def test_an_unmapped_device_is_silent():
    device = pci()
    device.ppt_map['guest_bsf'] = None
    assert device.xml() is None
    assert device.bhyve_args() is None
