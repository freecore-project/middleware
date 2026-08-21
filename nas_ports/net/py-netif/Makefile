# $FreeBSD$

PORTNAME=	netif
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	net python
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	Python bindings for FreeBSD network interface ioctls

EXTRACT_ONLY=

NAS_SRC?=	/usr/nas_source/py-netif
WRKSRC=		${WRKDIR}/py-netif

USES=		python
USE_PYTHON=	autoplist cython distutils

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

post-extract:
	@${MKDIR} ${WRKSRC}
	@${CP} -R ${NAS_SRC}/. ${WRKSRC}/

.include <bsd.port.mk>
