# $FreeBSD$

PORTNAME=	bsd
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	Python wrappers for various BSD interfaces

EXTRACT_ONLY=
NAS_SRC?=	/usr/nas_source/py-bsd
WRKSRC=		${WRKDIR}/py-bsd

BUILD_DEPENDS=	${LOCALBASE}/include/cdialog/dialog.h:devel/cdialog
LIB_DEPENDS=	libcdialog.so:devel/cdialog

USES=		python
USE_PYTHON=	autoplist cython distutils

CFLAGS+=	-I${LOCALBASE}/include -I${LOCALBASE}/include/cdialog

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

post-extract:
	@${MKDIR} ${WRKSRC}
	@${CP} -R ${NAS_SRC}/. ${WRKSRC}/

.include <bsd.port.mk>
