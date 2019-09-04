#!/bin/sh

set -eu
export LC_ALL=C

. /usr/share/biserver/bin/set-utils.sh

########

#KETTLE_DIRNAME_WAS_RENAMED=false
if [ "${KETTLE_DIRNAME:?}" != "${KETTLE_DEFAULT_DIRNAME:?}" ]; then
	logInfo "Kettle directory was renamed to \"${KETTLE_DIRNAME:?}\""
	#KETTLE_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${BISERVER_HOME:?}"/"${KETTLE_DIRNAME:?}" ]; then
		logInfo 'Moving kettle directory...'
		cp -a "${BISERVER_HOME:?}"/"${KETTLE_DEFAULT_DIRNAME:?}"/ "${BISERVER_HOME:?}"/"${KETTLE_DIRNAME:?}"
		rm -r "${BISERVER_HOME:?}"/"${KETTLE_DEFAULT_DIRNAME:?}"/
	fi
fi

#SOLUTIONS_DIRNAME_WAS_RENAMED=false
if [ "${SOLUTIONS_DIRNAME:?}" != "${SOLUTIONS_DEFAULT_DIRNAME:?}" ]; then
	logInfo "Solutions directory was renamed to \"${SOLUTIONS_DIRNAME:?}\""
	#SOLUTIONS_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" ]; then
		logInfo 'Moving solutions directory...'
		cp -a "${BISERVER_HOME:?}"/"${SOLUTIONS_DEFAULT_DIRNAME:?}"/ "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"
		rm -r "${BISERVER_HOME:?}"/"${SOLUTIONS_DEFAULT_DIRNAME:?}"/
	fi
fi

#DATA_DIRNAME_WAS_RENAMED=false
if [ "${DATA_DIRNAME:?}" != "${DATA_DEFAULT_DIRNAME:?}" ]; then
	logInfo "Data directory was renamed to \"${DATA_DIRNAME:?}\""
	#DATA_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" ]; then
		logInfo 'Moving data directory...'
		cp -a "${BISERVER_HOME:?}"/"${DATA_DEFAULT_DIRNAME:?}"/ "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"
		rm -r "${BISERVER_HOME:?}"/"${DATA_DEFAULT_DIRNAME:?}"/
	fi
fi

########

#WEBAPP_PENTAHO_DIRNAME_WAS_RENAMED=false
if [ "${WEBAPP_PENTAHO_DIRNAME:?}" != "${WEBAPP_PENTAHO_DEFAULT_DIRNAME:?}" ]; then
	logInfo "Pentaho webapp directory was renamed to \"${WEBAPP_PENTAHO_DIRNAME:?}\""
	#WEBAPP_PENTAHO_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" ]; then
		logInfo 'Moving Pentaho webapp directory...'
		cp -a "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DEFAULT_DIRNAME:?}"/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"
		rm -r "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DEFAULT_DIRNAME:?}"/
	fi
fi

WEBAPP_PENTAHO_STYLE_DIRNAME_WAS_RENAMED=false
if [ "${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" != "${WEBAPP_PENTAHO_STYLE_DEFAULT_DIRNAME:?}" ]; then
	logInfo "Pentaho style webapp directory was renamed to \"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}\""
	WEBAPP_PENTAHO_STYLE_DIRNAME_WAS_RENAMED=true
	if [ ! -e "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" ]; then
		logInfo 'Moving Pentaho style webapp directory...'
		cp -a "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DEFAULT_DIRNAME:?}"/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}"
		rm -r "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DEFAULT_DIRNAME:?}"/
	fi
fi

#
# This recursive replacement has dangerous implications compared to the benefits it brings.
# Uncomment only if there is a bug related to the rename operation.
#
#if [ "${WEBAPP_PENTAHO_DIRNAME_WAS_RENAMED:?}" = true ]; then
#	logInfo 'Updating references of Pentaho webapp...'
#	find \
#		"${BISERVER_HOME:?}/${SOLUTIONS_DIRNAME:?}" \
#		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
#		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
#		-type f \( -iname '*.html' -o -iname '*.jsp' \) \
#		-exec sed -i "s|/${WEBAPP_PENTAHO_DEFAULT_DIRNAME_RE:?}/|/${WEBAPP_PENTAHO_DIRNAME_SUBST:?}/|g" '{}' \;
#fi
#

if [ "${WEBAPP_PENTAHO_STYLE_DIRNAME_WAS_RENAMED:?}" = true ]; then
	logInfo 'Updating references of Pentaho style webapp...'
	find \
		"${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
		-type f \( -iname '*.css' -o -iname '*.html' -o -iname '*.jsp' -o -iname '*.properties' -o -iname '*.xsl' \) \
		-exec sed -i "s|/${WEBAPP_PENTAHO_STYLE_DEFAULT_DIRNAME_RE:?}/|/${WEBAPP_PENTAHO_STYLE_DIRNAME_SUBST:?}/|g" '{}' \;
fi
