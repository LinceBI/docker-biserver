#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

sed -r \
	-e "s|%ROOT_WEBAPP_DIRNAME%|${WEBAPP_PENTAHO_DIRNAME_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/ROOT/index.html.tmpl \
	> "${CATALINA_BASE}"/webapps/ROOT/index.html

########

sed -r \
	-e "s|%SOLUTIONS_DIRNAME%|${SOLUTIONS_DIRNAME_SUBST}|g" \
	-e "s|%DATA_DIRNAME%|${DATA_DIRNAME_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/web.xml.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/web.xml

sed -r \
	-e "s|%WEBAPP_PENTAHO_DIRNAME%|${WEBAPP_PENTAHO_DIRNAME_SUBST}|g" \
	-e "s|%DBCON_DRIVER_CLASS%|${DBCON_DRIVER_CLASS_SUBST}|g" \
	-e "s|%DBCON_VALIDATIONQUERY%|${DBCON_VALIDATIONQUERY_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_URL%|${DBCON_HIBERNATE_URL_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_USER%|${DBCON_HIBERNATE_USER_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_PASSWORD%|${DBCON_HIBERNATE_PASSWORD_SUBST}|g" \
	-e "s|%DBCON_QUARTZ_URL%|${DBCON_QUARTZ_URL_SUBST}|g" \
	-e "s|%DBCON_QUARTZ_USER%|${DBCON_QUARTZ_USER_SUBST}|g" \
	-e "s|%DBCON_QUARTZ_PASSWORD%|${DBCON_QUARTZ_PASSWORD_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/META-INF/context.xml.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/META-INF/context.xml

sed -r \
	-e "s|%WEBAPP_PENTAHO_DIRNAME%|${WEBAPP_PENTAHO_DIRNAME_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/classes/log4j.xml.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/WEB-INF/classes/log4j.xml

########

sed -r \
	-e "s|%WEBAPP_PENTAHO_STYLE_DIRNAME%|${WEBAPP_PENTAHO_STYLE_DIRNAME_SUBST}|g" \
	"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}"/META-INF/context.xml.tmpl \
	> "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}"/META-INF/context.xml

########

sed -r \
	-e "s|%FQSU%|${FQSU_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/server.properties.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/server.properties

########

sed -r \
	-e "s|%INSTANCE_ID%|${INSTANCE_ID_SUBST}|g" \
	-e "s|%DBCON_DATABASE_TYPE%|${DBCON_DATABASE_TYPE_SUBST}|g" \
	-e "s|%DBCON_FILESYSTEM_CLASS%|${DBCON_FILESYSTEM_CLASS_SUBST}|g" \
	-e "s|%DBCON_DATASTORE_CLASS%|${DBCON_DATASTORE_CLASS_SUBST}|g" \
	-e "s|%DBCON_PERSISTENCEMANAGER_CLASS%|${DBCON_PERSISTENCEMANAGER_CLASS_SUBST}|g" \
	-e "s|%DBCON_DRIVER_CLASS%|${DBCON_DRIVER_CLASS_SUBST}|g" \
	-e "s|%DBCON_JACKRABBIT_URL%|${DBCON_JACKRABBIT_URL_SUBST}|g" \
	-e "s|%DBCON_JACKRABBIT_USER%|${DBCON_JACKRABBIT_USER_SUBST}|g" \
	-e "s|%DBCON_JACKRABBIT_PASSWORD%|${DBCON_JACKRABBIT_PASSWORD_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository.xml.local.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository.xml

########

sed -r \
	-e "s|%DBCON_HIBERNATE_CONFIG_FILE%|${DBCON_HIBERNATE_CONFIG_FILE_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/hibernate-settings.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/hibernate-settings.xml

sed -r \
	-e "s|%SOLUTIONS_DIRNAME%|${SOLUTIONS_DIRNAME_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_USER%|${DBCON_HIBERNATE_USER_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_PASSWORD%|${DBCON_HIBERNATE_PASSWORD_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_DATABASE%|${DBCON_HIBERNATE_DATABASE_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/h2.hibernate.cfg.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/h2.hibernate.cfg.xml

########

sed -r \
	-e "s|%INSTANCE_ID%|${INSTANCE_ID_SUBST}|g" \
	-e "s|%DBCON_DRIVERDELEGATE_CLASS%|${DBCON_DRIVERDELEGATE_CLASS_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/quartz/quartz.properties.local.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/quartz/quartz.properties

########

sed -r \
	-e "s|%DBCON_DRIVER_CLASS%|${DBCON_DRIVER_CLASS_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_URL%|${DBCON_HIBERNATE_URL_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_USER%|${DBCON_HIBERNATE_USER_SUBST}|g" \
	-e "s|%DBCON_HIBERNATE_PASSWORD%|${DBCON_HIBERNATE_PASSWORD_SUBST}|g" \
	-e "s|%DBCON_QUARTZ_URL%|${DBCON_QUARTZ_URL_SUBST}|g" \
	-e "s|%DBCON_QUARTZ_USER%|${DBCON_QUARTZ_USER_SUBST}|g" \
	-e "s|%DBCON_QUARTZ_PASSWORD%|${DBCON_QUARTZ_PASSWORD_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/simple-jndi/jdbc.properties.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/simple-jndi/jdbc.properties

######

sed -r \
	-e "s|%WEBAPP_PENTAHO_DIRNAME%|${WEBAPP_PENTAHO_DIRNAME_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/osgi/log4j.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/osgi/log4j.xml

######

sed -ri "s|^(DI_HOME)=.*$|\1=\"\$DIR/${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.sh
sed -ri "s|^(SET DI_HOME)=.*$|\1=\"%~dp0${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.bat
