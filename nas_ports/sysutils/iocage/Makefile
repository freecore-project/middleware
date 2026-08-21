# $FreeBSD$

PORTNAME=	iocage
# Keep the pkg identity tied to the TrueNAS product release.  The Python
# distribution version staged from pyproject.toml is verified below.
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	sysutils python
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeBSD jail manager - TrueNAS fork

EXTRACT_ONLY=

NAS_SRC?=	/usr/iocage_src
WRKSRC=		${WRKDIR}/iocage

BUILD_DEPENDS=	${PYTHON_PKGNAMEPREFIX}hatchling>0:devel/py-hatchling@${PY_FLAVOR}

USES=		python
USE_PYTHON=	autoplist pep517
IOCAGE_PYDISTVERSION=	1.13
IOCAGE_PYDISTNAME=	${PORTNAME:C|[-_]+|_|g}-${IOCAGE_PYDISTVERSION}
IOCAGE_WHEEL=		${BUILD_WRKSRC}/dist/${IOCAGE_PYDISTNAME}-*.whl
IOCAGE_DISTINFO=	${STAGEDIR}${PYTHONPREFIX_SITELIBDIR}/${IOCAGE_PYDISTNAME}.dist-info
# The framework defaults use DISTVERSION for both the wheel and RECORD paths.
# This port keeps DISTVERSION tied to the appliance package identity, so use
# the Python distribution version for both PEP 517 paths explicitly.
PEP517_INSTALL_CMD=	${PYTHON_CMD} -m installer --destdir ${STAGEDIR} \
			--prefix ${PREFIX} ${IOCAGE_WHEEL}

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}netifaces>0:net/py-netifaces@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}click>=6.7:devel/py-click@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}six>=1.15.0:devel/py-six@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}coloredlogs>0:devel/py-coloredlogs@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}texttable>=0.8.7:textproc/py-texttable@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}requests>=2.11.1:www/py-requests@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}dnspython>0:dns/py-dnspython@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}gitpython>0:devel/py-gitpython@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}jsonschema>0:devel/py-jsonschema@${PY_FLAVOR}

NO_ARCH=	yes

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

post-extract:
	@${MKDIR} ${WRKSRC}
	@${CP} -R ${NAS_SRC}/. ${WRKSRC}/

do-install:
	@${MKDIR} ${STAGEDIR}${PYTHONPREFIX_SITELIBDIR}
	@cd ${INSTALL_WRKSRC} && ${SETENVI} ${WRK_ENV} ${MAKE_ENV} ${PEP517_INSTALL_CMD}
	@${PYTHON_CMD} -B ${PORTSDIR}/Mk/Scripts/strip_RECORD.py \
		${IOCAGE_DISTINFO}/RECORD >> ${_PYTHONPKGLIST}
	@${REINPLACE_CMD} \
		-e '/\.pyc$$/d' \
		-e 's|^|${PYTHONPREFIX_SITELIBDIR}/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../etc/|etc/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../bin/|bin/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../include/|include/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../lib/|lib/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../libdata/|libdata/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../libexec/|libexec/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../man/|man/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../sbin/|sbin/|' \
		-e 's|^${PYTHONPREFIX_SITELIBDIR}/../../../share/|share/|' \
		${_PYTHONPKGLIST}
	@cd ${STAGEDIR}${PREFIX} && ${FIND} lib -name '*.pyc' >> ${_PYTHONPKGLIST}

post-stage:
	@${TEST} -x ${STAGEDIR}${PREFIX}/bin/iocage
	@${TEST} -f ${STAGEDIR}${PREFIX}/etc/rc.d/iocage
	@${TEST} -f ${STAGEDIR}${PREFIX}/share/man/man8/iocage.8
	@${TEST} -f ${STAGEDIR}${PREFIX}/share/zsh/site-functions/_iocage
	@${TEST} -d ${STAGEDIR}${PYTHON_SITELIBDIR}/iocage_cli
	@${TEST} -d ${STAGEDIR}${PYTHON_SITELIBDIR}/iocage_lib
	@set -- ${STAGEDIR}${PYTHON_SITELIBDIR}/iocage[-_]*.dist-info; \
		${TEST} "$$#" -eq 1 && ${TEST} -d "$$1" && \
		${GREP} -qx 'Name: iocage' "$$1/METADATA" && \
		${GREP} -qx 'Version: 1.13' "$$1/METADATA" && \
		${GREP} -qx 'iocage = iocage_cli:cli' "$$1/entry_points.txt"
	@for legacy in ${STAGEDIR}${PYTHON_SITELIBDIR}/iocage[-_]*.egg-info; do \
		${TEST} ! -e "$$legacy" || exit 1; \
	done

.include <bsd.port.mk>
