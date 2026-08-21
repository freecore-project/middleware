from pathlib import Path

PKG_PLIST = (
    Path(__file__).parents[5]
    / 'nas_ports/freenas/freenas-pkgtools/pkg-plist'
)
PUBLIC_CERTIFICATE_PATHS = {
    'share/certs/FreeCORE-15.0-Nightlies.pem',
    'share/certs/FreeCORE-15.0-STABLE.pem',
    'share/certs/FreeCORE-15.1-Nightlies.pem',
    'share/certs/FreeCORE-15.1-STABLE.pem',
    'share/certs/FreeCORE-Nightlies.pem',
    'share/certs/FreeCORE-Production.pem',
    'share/certs/freecore-applications-catalog.pem',
    'share/certs/freecore-update-ca.pem',
}


def test_pkgtools_installs_only_the_expected_public_certificates_once():
    paths = PKG_PLIST.read_text().splitlines()
    packaged_certificates = [path for path in paths if path.startswith('share/certs/')]

    assert set(packaged_certificates) == PUBLIC_CERTIFICATE_PATHS
    assert len(packaged_certificates) == len(PUBLIC_CERTIFICATE_PATHS)
    assert all(path.endswith('.pem') for path in packaged_certificates)
