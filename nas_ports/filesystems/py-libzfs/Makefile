# $FreeBSD$

PORTNAME=	libzfs
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	filesystems devel python
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	Python libzfs bindings

EXTRACT_ONLY=

NAS_SRC?=	/usr/nas_source/py-libzfs
WRKSRC=		${WRKDIR}/py-libzfs

HAS_CONFIGURE=	yes
USES=		compiler:c11 python:3.11+
USE_PYTHON=	autoplist distutils cython

CONFIGURE_ENV=	freebsd_src=${SRC_BASE}
MAKE_ENV=	freebsd_src=${SRC_BASE}

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

post-extract:
	@${MKDIR} ${WRKSRC}
	@${CP} -R ${NAS_SRC}/. ${WRKSRC}/

.include <bsd.port.mk>
