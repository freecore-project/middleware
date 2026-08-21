# $FreeBSD$

PORTNAME=	cam
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	devel python
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	Python bindings for FreeBSD CAM/CTL/iSCSI/NVMe subsystems

EXTRACT_ONLY=

NAS_SRC?=	/usr/nas_source/py-cam
WRKSRC=		${WRKDIR}/py-cam

USES=		python:3.11+
USE_PYTHON=	autoplist cython distutils

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

post-extract:
	@${MKDIR} ${WRKSRC}
	@${CP} -R ${NAS_SRC}/. ${WRKSRC}/

.include <bsd.port.mk>
