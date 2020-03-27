#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck disable=SC1091
. /usr/share/biserver/bin/set-utils.sh

########

find "${BISERVER_HOME:?}" "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type d -not -perm 0775 -exec chmod -c 0775 '{}' '+'
find "${BISERVER_HOME:?}" "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type f -not '(' -perm 0664 -o -regex '^.*\.sh\(\.erb\)?$' ')' -exec chmod -c 0664 '{}' '+'
find "${BISERVER_HOME:?}" "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type f '(' -not -perm 0775 -a -regex '^.*\.sh\(\.erb\)?$' ')' -exec chmod -c 0775 '{}' '+'

find "${BIUSER_HOME:?}" "${KETTLE_HOME:?}" -type d -not -perm 0775 -exec chmod -c 0775 '{}' '+'
find "${BIUSER_HOME:?}" "${KETTLE_HOME:?}" -type f -not '(' -perm 0664 -o -regex '^.*\.sh$' ')' -exec chmod -c 0664 '{}' '+'
find "${BIUSER_HOME:?}" "${KETTLE_HOME:?}" -type f '(' -not -perm 0775 -a -regex '^.*\.sh$' ')' -exec chmod -c 0775 '{}' '+'

find "${BISERVER_INITD:?}" -type d -not -perm 0775 -exec chmod -c 0775 '{}' '+'
find "${BISERVER_INITD:?}" -type f -not '(' -perm 0664 -o -regex '^.*\.\(sh\|run\)$' ')' -exec chmod -c 0664 '{}' '+'
find "${BISERVER_INITD:?}" -type f '(' -not -perm 0775 -a -regex '^.*\.\(sh\|run\)$' ')' -exec chmod -c 0775 '{}' '+'

find /usr/share/biserver/bin/ -type d -not -perm 0775 -exec chmod -c 0775 '{}' '+'
find /usr/share/biserver/bin/ -type f -not -perm 0775 -exec chmod -c 0775 '{}' '+'

find /usr/share/biserver/service/ -type d -not '(' -perm 0775 -o -name 'supervise' ')' -exec chmod -c 0775 '{}' '+'
find /usr/share/biserver/service/ -type f '(' -not -perm 0775 -a -regex '^.*\/\(run\|finish\|t\)$' ')' -exec chmod -c 0775 '{}' '+'
