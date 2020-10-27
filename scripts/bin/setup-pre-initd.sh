#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

# Rename solutions directory
if [ -e "${BISERVER_HOME:?}"/pentaho-solutions/ ] && [ ! -e "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" ]; then
	logInfo 'Moving solutions directory...'
	mv -f "${BISERVER_HOME:?}"/pentaho-solutions/ "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"
fi

# Rename data directory
if [ -e "${BISERVER_HOME:?}"/data/ ] && [ ! -e "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" ]; then
	logInfo 'Moving data directory...'
	mv -f "${BISERVER_HOME:?}"/data/ "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"
fi

# Rename Pentaho webapp directory
if [ -e "${CATALINA_BASE:?}"/webapps/pentaho/ ] && [ ! -e "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" ]; then
	logInfo 'Moving Pentaho webapp directory...'
	mv -f "${CATALINA_BASE:?}"/webapps/pentaho/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"

	# WARN: this replacement is too generic and has not been thoroughly tested.
	# logInfo 'Updating references of Pentaho webapp...'
	# find \
	#	"${BISERVER_HOME:?}/${SOLUTIONS_DIRNAME:?}" \
	#	"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
	#	"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
	#	-type f '(' -iname '*.html' -o -iname '*.jsp' ')' \
	#	-exec sed -i "s|/pentaho/|/$(quoteSubst "${WEBAPP_PENTAHO_DIRNAME:?}")/|g" '{}' ';'
fi

# Rename Pentaho style webapp directory
if [ -e "${CATALINA_BASE:?}"/webapps/pentaho-style/ ] && [ ! -e "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" ]; then
	logInfo 'Moving Pentaho style webapp directory...'
	mv -f "${CATALINA_BASE:?}"/webapps/pentaho-style/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"

	logInfo 'Updating references of Pentaho style webapp...'
	find \
		"${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
		-type f '(' -iname '*.css' -o -iname '*.html' -o -iname '*.jsp' -o -iname '*.properties' -o -iname '*.xsl' ')' \
		-exec sed -i "s|/pentaho-style/|/$(quoteSubst "${WEBAPP_PENTAHO_STYLE_DIRNAME:?}")/|g" '{}' ';'
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
