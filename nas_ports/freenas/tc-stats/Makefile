# $FreeBSD$

PORTNAME=	tc-stats
PORTVERSION=	0.1.8
DISTVERSIONPREFIX=	v

CATEGORIES=	freenas
VALID_CATEGORIES+=	freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	TrueCommand Stats Collection Engine

USES=		go:no_targets
USE_GITHUB=	yes
GH_ACCOUNT=	freenas
GH_PROJECT=	truecommand-stats

.include <bsd.port.pre.mk>

do-build:
	cd ${WRKSRC}/src-go && ${SETENV} ${MAKE_ENV} GO111MODULE=off \
	    ${LOCALBASE}/bin/go build -o ${WRKDIR}/trueview-stats trueview-stats.go

do-install:
	@${MKDIR} ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/trueview-stats ${STAGEDIR}${PREFIX}/bin/trueview_stats.sh

.include <bsd.port.post.mk>
