#!/bin/sh

set -eu
export LC_ALL=C

. /opt/scripts/set-utils.sh

########

DEFAULT_WEBAPP_PENTAHO_DIRNAME=$(printf -- '%s' "${SETUP_JSON}" | jq -r '.root')
export DEFAULT_WEBAPP_PENTAHO_DIRNAME

SERVER_LIST=$(printf -- '%s' "${SETUP_JSON}" | jq -c '.servers|map(select(.enabled))')
SERVER_COUNT=$(printf -- '%s' "${SERVER_LIST}" | jq -r '.|length-1')

WAS_DEFAULT_NAME_FOUND=false

_IFS=${IFS}; IFS="$(printf '\nx')"; IFS="${IFS%x}"
for server_index in $(seq 0 "${SERVER_COUNT}"); do
	server=$(printf -- '%s' "${SERVER_LIST}" | jq -r --arg i "${server_index}" ".[\$i|tonumber]")
	name=$(printf -- '%s' "${server}" | jq -r '.name')
	env_map=$(printf -- '%s' "${server}" | jq -r '.env')
	env_keys=$(printf -- '%s' "${env_map}" | jq -r 'keys[]')

	if [ "${name}" = "${WEBAPP_PENTAHO_DEFAULT_DIRNAME}" ]; then
		WAS_DEFAULT_NAME_FOUND=true
	fi

	logInfo "Configuring \"${name}\" server..."

	( # Server environment
		export MULTI_SETUP_ENABLED=true

		if [ "${name}" = "${WEBAPP_PENTAHO_DEFAULT_DIRNAME}" ]; then
			#export KETTLE_DIRNAME="${KETTLE_DEFAULT_DIRNAME}"
			export SOLUTIONS_DIRNAME="${SOLUTIONS_DEFAULT_DIRNAME}"
			export DATA_DIRNAME="${DATA_DEFAULT_DIRNAME}"
			export WEBAPP_PENTAHO_DIRNAME="${WEBAPP_PENTAHO_DEFAULT_DIRNAME}"
			export WEBAPP_PENTAHO_STYLE_DIRNAME="${WEBAPP_PENTAHO_STYLE_DEFAULT_DIRNAME}"
		else
			#export KETTLE_DIRNAME="${name}-kettle"
			export SOLUTIONS_DIRNAME="${name}-solutions"
			export DATA_DIRNAME="${name}-data"
			export WEBAPP_PENTAHO_DIRNAME="${name}"
			export WEBAPP_PENTAHO_STYLE_DIRNAME="${name}-style"
		fi

		for env_key in ${env_keys}; do
			env_value=$(printf -- '%s' "${env_map}" | jq -r --arg k "${env_key}" ".[\$k]")
			export "${env_key}=${env_value}"
		done

		/opt/scripts/setup-biserver.sh
	)
done
IFS=${_IFS}

########

if [ "${WAS_DEFAULT_NAME_FOUND}" != true ]; then
	rm -rf \
		"${BISERVER_HOME:?}"/"${SOLUTIONS_DEFAULT_DIRNAME}"/ \
		"${BISERVER_HOME:?}"/"${DATA_DEFAULT_DIRNAME}"/ \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DEFAULT_DIRNAME}"/ \
		"${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DEFAULT_DIRNAME}"/
fi
