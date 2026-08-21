# $FreeBSD$

PORTNAME=	swagger-ui
PORTVERSION=	5.32.13

CATEGORIES=		freenas
VALID_CATEGORIES+=	freenas
MASTER_SITES=	https://registry.npmjs.org/swagger-ui-dist/-/
DISTNAME=	swagger-ui-dist-${PORTVERSION}
EXTRACT_SUFX=	.tgz

MAINTAINER=	dev@ixsystems.com
COMMENT=	OpenAPI spec renderer UI

NO_BUILD=	yes
WRKSRC=		${WRKDIR}/package

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/www/swagger-ui/node_modules/swagger-ui-dist
	(cd ${WRKSRC} && ${COPYTREE_SHARE} . \
		${STAGEDIR}${PREFIX}/www/swagger-ui/node_modules/swagger-ui-dist)
	(cd ${STAGEDIR}${PREFIX}/www/swagger-ui; ${FIND} . -type f \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| cut -d " " -f 2- \
		| ${AWK} '{print "www/swagger-ui/"$$0 }' >> ${TMPPLIST})

.include <bsd.port.mk>
