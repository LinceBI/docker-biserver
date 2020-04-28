#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

#SOLUTIONS_DIRNAME_WAS_RENAMED=false
if [ "${SOLUTIONS_DIRNAME:?}" != 'pentaho-solutions' ]; then
	logInfo "Solutions directory was renamed to \"${SOLUTIONS_DIRNAME:?}\""
	#SOLUTIONS_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" ]; then
		logInfo 'Moving solutions directory...'
		cp -a "${BISERVER_HOME:?}"/pentaho-solutions/ "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"
		rm -r "${BISERVER_HOME:?}"/pentaho-solutions/
	fi
fi

#DATA_DIRNAME_WAS_RENAMED=false
if [ "${DATA_DIRNAME:?}" != 'data' ]; then
	logInfo "Data directory was renamed to \"${DATA_DIRNAME:?}\""
	#DATA_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" ]; then
		logInfo 'Moving data directory...'
		cp -a "${BISERVER_HOME:?}"/data/ "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"
		rm -r "${BISERVER_HOME:?}"/data/
	fi
fi

########

#WEBAPP_PENTAHO_DIRNAME_WAS_RENAMED=false
if [ "${WEBAPP_PENTAHO_DIRNAME:?}" != 'pentaho' ]; then
	logInfo "Pentaho webapp directory was renamed to \"${WEBAPP_PENTAHO_DIRNAME:?}\""
	#WEBAPP_PENTAHO_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" ]; then
		logInfo 'Moving Pentaho webapp directory...'
		cp -a "${CATALINA_BASE:?}"/webapps/pentaho/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"
		rm -r "${CATALINA_BASE:?}"/webapps/pentaho/
	fi
fi

WEBAPP_PENTAHO_STYLE_DIRNAME_WAS_RENAMED=false
if [ "${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" != 'pentaho-style' ]; then
	logInfo "Pentaho style webapp directory was renamed to \"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}\""
	WEBAPP_PENTAHO_STYLE_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" ]; then
		logInfo 'Moving Pentaho style webapp directory...'
		cp -a "${CATALINA_BASE:?}"/webapps/pentaho-style/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"
		rm -r "${CATALINA_BASE:?}"/webapps/pentaho-style/
	fi
fi

# This replacement is too generic and has not been thoroughly tested.
# Uncomment only if there is a bug related to the rename operation.
#
#if [ "${WEBAPP_PENTAHO_DIRNAME_WAS_RENAMED:?}" = 'true' ]; then
#	logInfo 'Updating references of Pentaho webapp...'
#	find \
#		"${BISERVER_HOME:?}/${SOLUTIONS_DIRNAME:?}" \
#		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
#		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
#		-type f '(' -iname '*.html' -o -iname '*.jsp' ')' \
#		-exec sed -i "s|/pentaho/|/$(quoteSubst "${WEBAPP_PENTAHO_DIRNAME:?}")/|g" '{}' ';'
#fi

if [ "${WEBAPP_PENTAHO_STYLE_DIRNAME_WAS_RENAMED:?}" = 'true' ]; then
	logInfo 'Updating references of Pentaho style webapp...'
	find \
		"${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
		-type f '(' -iname '*.css' -o -iname '*.html' -o -iname '*.jsp' -o -iname '*.properties' -o -iname '*.xsl' ')' \
		-exec sed -i "s|/pentaho-style/|/$(quoteSubst "${WEBAPP_PENTAHO_STYLE_DIRNAME:?}")/|g" '{}' ';'
fi
