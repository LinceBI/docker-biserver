#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

sed -r \
	-e "s|%INSTANCE_ID%|${INSTANCE_ID_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository.xml.local.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository.xml

########

sed -r \
	-e "s|%HSQLDB_PORT%|${HSQLDB_PORT_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/hsql.hibernate.cfg.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/hsql.hibernate.cfg.xml

########

sed -r \
	-e "s|%INSTANCE_ID%|${INSTANCE_ID_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/quartz/quartz.properties.local.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/quartz/quartz.properties

########

sed -r \
	-e "s|%HSQLDB_PORT%|${HSQLDB_PORT_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/simple-jndi/jdbc.properties.local.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/simple-jndi/jdbc.properties

########

sed -r \
	-e "s|%SOLUTIONS_DIRNAME%|${SOLUTIONS_DIRNAME_SUBST}|g" \
	-e "s|%DATA_DIRNAME%|${DATA_DIRNAME_SUBST}|g" \
	-e "s|%HSQLDB_PORT%|${HSQLDB_PORT_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/web.xml.local.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/web.xml

sed -r \
	-e "s|%WEBAPP_PENTAHO_DIRNAME%|${WEBAPP_PENTAHO_DIRNAME_SUBST}|g" \
	-e "s|%HSQLDB_PORT%|${HSQLDB_PORT_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/META-INF/context.xml.local.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/META-INF/context.xml
