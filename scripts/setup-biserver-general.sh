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
	-e "s|%HSQLDB_PORT%|${HSQLDB_PORT_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/pentaho.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/pentaho.xml

sed -r \
	-e "s|%FQSU%|${FQSU_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/server.properties.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/server.properties

########

sed -r \
	-e "s|%KARAF_STARTPORT%|${KARAF_STARTPORT_SUBST}|g" \
	-e "s|%KARAF_ENDPORT%|${KARAF_ENDPORT_SUBST}|g" \
	-e "s|%OSGI_SERVICE_STARTPORT%|${OSGI_SERVICE_STARTPORT_SUBST}|g" \
	-e "s|%OSGI_SERVICE_ENDPORT%|${OSGI_SERVICE_ENDPORT_SUBST}|g" \
	-e "s|%RMI_SERVER_STARTPORT%|${RMI_SERVER_STARTPORT_SUBST}|g" \
	-e "s|%RMI_SERVER_ENDPORT%|${RMI_SERVER_ENDPORT_SUBST}|g" \
	-e "s|%RMI_REGISTRY_STARTPORT%|${RMI_REGISTRY_STARTPORT_SUBST}|g" \
	-e "s|%RMI_REGISTRY_ENDPORT%|${RMI_REGISTRY_ENDPORT_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/karaf/etc/KarafPorts.yaml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/karaf/etc/KarafPorts.yaml

########

sed -r \
	-e "s|%HIBERNATE_CONFIG_FILE%|${HIBERNATE_CONFIG_FILE_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/hibernate-settings.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/hibernate-settings.xml

sed -r \
	-e "s|%SOLUTIONS_DIRNAME%|${SOLUTIONS_DIRNAME_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/h2.hibernate.cfg.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/hibernate/h2.hibernate.cfg.xml

######

sed -r \
	-e "s|%WEBAPP_PENTAHO_DIRNAME%|${WEBAPP_PENTAHO_DIRNAME_SUBST}|g" \
	"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/osgi/log4j.xml.tmpl \
	> "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/osgi/log4j.xml

######

sed -ri "s|^(DI_HOME)=.*$|\1=\"\$DIR/${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.sh
sed -ri "s|^(SET DI_HOME)=.*$|\1=\"%~dp0${KETTLE_DIRNAME_SUBST}\"|" "${BISERVER_HOME}"/start-pentaho.bat
