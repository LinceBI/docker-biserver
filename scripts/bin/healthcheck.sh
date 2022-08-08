#!/bin/sh

set -eu
export LC_ALL=C

########

if [ "${SERVICE_BISERVER_ENABLED:?}" = 'true' ]; then
	AJP_RESPONSE_DATA=$(printf '\022\064\000\001\012' | nc -q 0 -w 1 localhost "${TOMCAT_AJP_PORT:?}")
	if [ "${AJP_RESPONSE_DATA?}" != "$(printf '\101\102\000\001\011')" ]; then
		>&2 printf '%s\n' 'AJP connector returned an unexpected result'
		exit 1
	fi

	HTTP_RESPONSE_CODE=$(curl -so /dev/null -w '%{http_code}' -m 5 "http://localhost:${TOMCAT_HTTP_PORT:?}/${WEBAPP_PENTAHO_DIRNAME:?}")
	if [ "${HTTP_RESPONSE_CODE?}" -lt 200 ] || [ "${HTTP_RESPONSE_CODE?}" -gt 399 ]; then
		>&2 printf '%s\n' 'HTTP connector returned an unexpected result'
		exit 1
	fi
fi
