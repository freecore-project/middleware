from pathlib import Path

PORT_MAKEFILE = Path(__file__).parents[5] / 'nas_ports/sysutils/iocage/Makefile'
PORT = PORT_MAKEFILE.read_text()


def make_variable(name):
    lines = PORT.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f'{name}='))
    value = []

    for line in lines[start:]:
        value.append(line)
        if not line.rstrip().endswith('\\'):
            break

    return '\n'.join(value)


def test_iocage_port_preserves_appliance_identity_and_local_source_staging():
    assert 'PORTVERSION=\t${PRODUCT_VERSION:C/\\-.*//:C/\\_.*//}' in PORT
    assert 'PORTREVISION=\t${REVISION}' in PORT
    assert 'NAS_SRC?=\t/usr/iocage_src' in PORT
    assert '${CP} -R ${NAS_SRC}/. ${WRKSRC}/' in PORT


def test_iocage_port_uses_hatchling_pep517_without_distutils():
    assert make_variable('BUILD_DEPENDS') == (
        'BUILD_DEPENDS=\t${PYTHON_PKGNAMEPREFIX}hatchling>0:'
        'devel/py-hatchling@${PY_FLAVOR}'
    )
    assert make_variable('USE_PYTHON') == 'USE_PYTHON=\tautoplist pep517'
    assert make_variable('IOCAGE_PYDISTVERSION') == 'IOCAGE_PYDISTVERSION=\t1.13'
    assert make_variable('IOCAGE_PYDISTNAME') == (
        'IOCAGE_PYDISTNAME=\t${PORTNAME:C|[-_]+|_|g}-${IOCAGE_PYDISTVERSION}'
    )
    assert make_variable('IOCAGE_WHEEL') == (
        'IOCAGE_WHEEL=\t\t${BUILD_WRKSRC}/dist/${IOCAGE_PYDISTNAME}-*.whl'
    )
    assert make_variable('IOCAGE_DISTINFO') == (
        'IOCAGE_DISTINFO=\t${STAGEDIR}${PYTHONPREFIX_SITELIBDIR}/'
        '${IOCAGE_PYDISTNAME}.dist-info'
    )
    assert make_variable('PEP517_INSTALL_CMD') == (
        'PEP517_INSTALL_CMD=\t${PYTHON_CMD} -m installer --destdir ${STAGEDIR} \\\n'
        '\t\t\t--prefix ${PREFIX} ${IOCAGE_WHEEL}'
    )
    assert 'distutils' not in PORT
    assert 'setup.py' not in PORT


def test_iocage_port_generates_autoplist_from_python_distribution_record():
    assert PORT.count('strip_RECORD.py') == 1
    assert '${IOCAGE_DISTINFO}/RECORD >> ${_PYTHONPKGLIST}' in PORT
    assert '${DISTVERSION}*.dist-info/RECORD' not in PORT


def test_iocage_port_runtime_dependencies_match_freebsd_port():
    runtime_dependencies = make_variable('RUN_DEPENDS')
    expected_origins = {
        'devel/py-click',
        'devel/py-coloredlogs',
        'devel/py-gitpython',
        'devel/py-jsonschema',
        'devel/py-six',
        'dns/py-dnspython',
        'net/py-netifaces',
        'textproc/py-texttable',
        'www/py-requests',
    }

    assert {
        dependency.split(':', 1)[1].split('@', 1)[0]
        for dependency in runtime_dependencies.replace('\\\n', ' ').split()[1:]
    } == expected_origins
    assert 'py-libzfs' not in runtime_dependencies


def test_iocage_port_asserts_single_distribution_and_complete_stage():
    expected_paths = {
        '${STAGEDIR}${PREFIX}/bin/iocage',
        '${STAGEDIR}${PREFIX}/etc/rc.d/iocage',
        '${STAGEDIR}${PREFIX}/share/man/man8/iocage.8',
        '${STAGEDIR}${PREFIX}/share/zsh/site-functions/_iocage',
        '${STAGEDIR}${PYTHON_SITELIBDIR}/iocage_cli',
        '${STAGEDIR}${PYTHON_SITELIBDIR}/iocage_lib',
    }

    for path in expected_paths:
        assert PORT.count(path) == 1

    assert PORT.count('${STAGEDIR}${PYTHON_SITELIBDIR}/iocage[-_]*.dist-info') == 1
    assert "${GREP} -qx 'Name: iocage'" in PORT
    assert "${GREP} -qx 'Version: 1.13'" in PORT
    assert "${GREP} -qx 'iocage = iocage_cli:cli'" in PORT
    assert '${STAGEDIR}${PYTHON_SITELIBDIR}/iocage[-_]*.egg-info' in PORT
