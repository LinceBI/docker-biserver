#!/bin/sh

set -eu

USER="${1:-${REPOSITORY_SINGLE_TENANT_ADMIN_USERNAME:-admin}}"
PASS="${2:-${DEFAULT_ADMIN_PASSWORD:-password}}"
URL="${3:-http://127.0.0.1:${TOMCAT_HTTP_PORT:-8080}/${WEBAPP_PENTAHO_DIRNAME:-pentaho}}"

exec curl --location-trusted --globoff \
	--user "${USER:?}:${PASS:?}" \
	--url "${URL:?}/api/repo/files/systemRestore" \
	--form 'fileUpload=@-' \
	--form 'overwriteFile=true' \
	--form 'applyAclSettings=true' \
	--form 'overwriteAclSettings=true'
