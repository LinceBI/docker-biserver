#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

# Rename solutions directory
if [ "${SOLUTIONS_DIRNAME:?}" != 'pentaho-solutions' ] && [ -e "${BISERVER_HOME:?}"/pentaho-solutions/ ]; then
	logInfo 'Moving solutions directory...'
	rsync -rlp --remove-source-files --ignore-existing \
		"${BISERVER_HOME:?}"/pentaho-solutions/ \
		"${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/
	rm -rf "${BISERVER_HOME:?}"/pentaho-solutions/
fi

# Rename data directory
if [ "${DATA_DIRNAME:?}" != 'data' ] && [ -e "${BISERVER_HOME:?}"/data/ ]; then
	logInfo 'Moving data directory...'
	rsync -rlp --remove-source-files --ignore-existing \
		"${BISERVER_HOME:?}"/data/ \
		"${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/
	rm -rf "${BISERVER_HOME:?}"/data/
fi

# Rename Pentaho webapp directory
if [ "${WEBAPP_PENTAHO_DIRNAME:?}" != 'pentaho' ] && [ -e "${CATALINA_BASE:?}"/webapps/pentaho/ ]; then
	logInfo 'Moving Pentaho webapp directory...'
	rsync -rlp --remove-source-files --ignore-existing \
		"${CATALINA_BASE:?}"/webapps/pentaho/ \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/
	rm -rf "${CATALINA_BASE:?}"/webapps/pentaho/
fi

# Rename Pentaho style webapp directory
if [ "${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" != 'pentaho-style' ] && [ -e "${CATALINA_BASE:?}"/webapps/pentaho-style/ ]; then
	logInfo 'Moving Pentaho style webapp directory...'
	rsync -rlp --remove-source-files --ignore-existing \
		"${CATALINA_BASE:?}"/webapps/pentaho-style/ \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"/
	rm -rf "${CATALINA_BASE:?}"/webapps/pentaho-style/
fi

########

# Extract HSQLDB data if the directory is empty
if [ -z "$(ls -A "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/hsqldb/)" ]; then
	(cd "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" && unzip -qo ./hsqldb.zip)
fi

# Create Kettle directory if it does not exist
if [ ! -e "${KETTLE_HOME:?}"/.kettle/ ]; then
	mkdir "${KETTLE_HOME:?}"/.kettle/
	chmod 775 "${KETTLE_HOME:?}"/.kettle/
fi

# Create Kettle properties file if it does not exist
if [ ! -e "${KETTLE_HOME:?}"/.kettle/kettle.properties ]; then
	touch "${KETTLE_HOME:?}"/.kettle/kettle.properties
	chmod 664 "${KETTLE_HOME:?}"/.kettle/kettle.properties
fi
