#!/bin/sh

set -eu
export LC_ALL=C

DEPLOYMENTS_DIR="${PWD:?}/standalone/deployments/"

KEYCLOAK_PROTOCOL_CAS_VERSION="${KEYCLOAK_VERSION:?}"
KEYCLOAK_PROTOCOL_CAS_URL="https://github.com/jacekkow/keycloak-protocol-cas/releases/download/${KEYCLOAK_PROTOCOL_CAS_VERSION:?}/keycloak-protocol-cas-${KEYCLOAK_PROTOCOL_CAS_VERSION:?}.jar"
KEYCLOAK_PROTOCOL_CAS_CHECKSUM=''

( cd "${DEPLOYMENTS_DIR:?}" && curl -LO "${KEYCLOAK_PROTOCOL_CAS_URL:?}" )
if [ -n "${KEYCLOAK_PROTOCOL_CAS_CHECKSUM?}" ]; then
	printf '%s  %s' "${KEYCLOAK_PROTOCOL_CAS_CHECKSUM:?}" "${DEPLOYMENTS_DIR:?}"/keycloak-protocol-cas-*.jar | sha256sum -c
fi
