# $FreeBSD$

PORTNAME=	licenselib
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}
CATEGORIES=	freenas
VALID_CATEGORIES+=freenas

MAINTAINER=	wg@FreeBSD.org
COMMENT=	License library for FreeNAS/TrueNAS

USES=		python
USE_PYTHON=	autoplist distutils

EXTRACT_ONLY=
NAS_SRC?=	/usr/nas_source/py-licenselib
WRKSRC=		${WRKDIR}/py-licenselib

# no checksum, we just used git!
checksum fetch:
	echo ${.TARGET} not needed because building direct

post-extract:
	@${MKDIR} ${WRKSRC}
	@${CP} -R ${NAS_SRC}/. ${WRKSRC}/

.include <bsd.port.mk>
