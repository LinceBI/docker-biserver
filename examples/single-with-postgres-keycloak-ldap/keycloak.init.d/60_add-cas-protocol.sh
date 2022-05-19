#!/bin/sh

set -eu
export LC_ALL=C

KEYCLOAK_DIR='/opt/keycloak/'
KEYCLOAK_PROTOCOL_CAS_VERSION="$("${KEYCLOAK_DIR:?}"/bin/kc.sh --version | awk '/^Keycloak /{print($2)}')"
KEYCLOAK_PROTOCOL_CAS_URL="https://github.com/jacekkow/keycloak-protocol-cas/releases/download/${KEYCLOAK_PROTOCOL_CAS_VERSION:?}/keycloak-protocol-cas-${KEYCLOAK_PROTOCOL_CAS_VERSION:?}.jar"
KEYCLOAK_PROTOCOL_CAS_CHECKSUM=''

( cd "${KEYCLOAK_DIR:?}"/providers/ && curl -LO "${KEYCLOAK_PROTOCOL_CAS_URL:?}" )
if [ -n "${KEYCLOAK_PROTOCOL_CAS_CHECKSUM?}" ]; then
	printf '%s  %s' "${KEYCLOAK_PROTOCOL_CAS_CHECKSUM:?}" "${KEYCLOAK_DIR:?}"/providers/keycloak-protocol-cas-*.jar | sha256sum -c
fi
