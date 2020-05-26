#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

[ -z "${EXPORT_ENABLED-}" ] && export EXPORT_ENABLED='false'

if [ -z "${INSTANCE_ID-}" ]; then
	# Each instance has a random 12 characters alphanumeric string
	INSTANCE_ID="$(tr -dc 'a-z0-9' < /dev/urandom | head -c12)"
	export INSTANCE_ID
fi

[ -z "${IS_PROXIED-}"   ] && export IS_PROXIED='false'
[ -z "${PROXY_SCHEME-}" ] && export PROXY_SCHEME='https'
[ -z "${PROXY_PORT-}"   ] && export PROXY_PORT='443'

[ -z "${TOMCAT_SHUTDOWN_PORT-}"   ] && export TOMCAT_SHUTDOWN_PORT='8005'
[ -z "${TOMCAT_HTTP_PORT-}"       ] && export TOMCAT_HTTP_PORT='8080'
[ -z "${TOMCAT_AJP_PORT-}"        ] && export TOMCAT_AJP_PORT='8009'
[ -z "${HSQLDB_PORT-}"            ] && export HSQLDB_PORT='9001'
[ -z "${KARAF_STARTPORT-}"        ] && export KARAF_STARTPORT='8801'
[ -z "${KARAF_ENDPORT-}"          ] && export KARAF_ENDPORT='8899'
[ -z "${OSGI_SERVICE_STARTPORT-}" ] && export OSGI_SERVICE_STARTPORT='9050'
[ -z "${OSGI_SERVICE_ENDPORT-}"   ] && export OSGI_SERVICE_ENDPORT='9149'

[ -z "${FQSU_PROTOCOL-}" ] && export FQSU_PROTOCOL='http'
[ -z "${FQSU_DOMAIN-}"   ] && export FQSU_DOMAIN='localhost'
[ -z "${FQSU_PORT-}"     ] && export FQSU_PORT="${TOMCAT_HTTP_PORT:?}"

[ -z "${STORAGE_TYPE-}" ] && export STORAGE_TYPE='local'

if [ "${STORAGE_TYPE:?}" = 'local' ]; then
	[ -z "${HIBERNATE_CONFIG_FILE-}" ] && export HIBERNATE_CONFIG_FILE='system/hibernate/hsql.hibernate.cfg.xml'
fi

[ -z "${POSTGRES_HOST-}"                   ] && export POSTGRES_HOST='localhost'
[ -z "${POSTGRES_PORT-}"                   ] && export POSTGRES_PORT='5432'
[ -z "${POSTGRES_USER-}"                   ] && export POSTGRES_USER="${POSTGRES_MAINTENANCE_USER-postgres}"
[ -z "${POSTGRES_PASSWORD-}"               ] && export POSTGRES_PASSWORD="${POSTGRES_MAINTENANCE_PASSWORD-postgres}"
[ -z "${POSTGRES_DATABASE-}"               ] && export POSTGRES_DATABASE="${POSTGRES_MAINTENANCE_DATABASE-postgres}"
[ -z "${POSTGRES_JDBC_URL-}"               ] && export POSTGRES_JDBC_URL="jdbc:postgresql://${POSTGRES_HOST:?}:${POSTGRES_PORT:?}"
[ -z "${POSTGRES_JDBC_PROPS-}"             ] && export POSTGRES_JDBC_PROPS=''
[ -z "${POSTGRES_JACKRABBIT_USER-}"        ] && export POSTGRES_JACKRABBIT_USER='jcr_user'
[ -z "${POSTGRES_JACKRABBIT_PASSWORD-}"    ] && export POSTGRES_JACKRABBIT_PASSWORD='jcr_password'
[ -z "${POSTGRES_JACKRABBIT_DATABASE-}"    ] && export POSTGRES_JACKRABBIT_DATABASE='jackrabbit'
[ -z "${POSTGRES_JACKRABBIT_JDBC_URL-}"    ] && export POSTGRES_JACKRABBIT_JDBC_URL="${POSTGRES_JDBC_URL:?}/${POSTGRES_JACKRABBIT_DATABASE:?}?${POSTGRES_JDBC_PROPS?}"
[ -z "${POSTGRES_HIBERNATE_USER-}"         ] && export POSTGRES_HIBERNATE_USER='hibuser'
[ -z "${POSTGRES_HIBERNATE_PASSWORD-}"     ] && export POSTGRES_HIBERNATE_PASSWORD='hibpassword'
[ -z "${POSTGRES_HIBERNATE_DATABASE-}"     ] && export POSTGRES_HIBERNATE_DATABASE='hibernate'
[ -z "${POSTGRES_HIBERNATE_JDBC_URL-}"     ] && export POSTGRES_HIBERNATE_JDBC_URL="${POSTGRES_JDBC_URL:?}/${POSTGRES_HIBERNATE_DATABASE:?}?${POSTGRES_JDBC_PROPS?}"
[ -z "${POSTGRES_QUARTZ_USER-}"            ] && export POSTGRES_QUARTZ_USER='pentaho_user'
[ -z "${POSTGRES_QUARTZ_PASSWORD-}"        ] && export POSTGRES_QUARTZ_PASSWORD='pentaho_password'
[ -z "${POSTGRES_QUARTZ_DATABASE-}"        ] && export POSTGRES_QUARTZ_DATABASE='quartz'
[ -z "${POSTGRES_QUARTZ_JDBC_URL-}"        ] && export POSTGRES_QUARTZ_JDBC_URL="${POSTGRES_JDBC_URL:?}/${POSTGRES_QUARTZ_DATABASE:?}?${POSTGRES_JDBC_PROPS?}"

if [ "${STORAGE_TYPE:?}" = 'postgres' ]; then
	[ -z "${HIBERNATE_CONFIG_FILE-}" ] && export HIBERNATE_CONFIG_FILE='system/hibernate/postgresql.hibernate.cfg.xml'
fi

[ -z "${COCKROACH_HOST-}"                   ] && export COCKROACH_HOST='localhost'
[ -z "${COCKROACH_PORT-}"                   ] && export COCKROACH_PORT='26257'
[ -z "${COCKROACH_USER-}"                   ] && export COCKROACH_USER="${COCKROACH_MAINTENANCE_USER-root}"
[ -z "${COCKROACH_PASSWORD-}"               ] && export COCKROACH_PASSWORD="${COCKROACH_MAINTENANCE_PASSWORD-root}"
[ -z "${COCKROACH_DATABASE-}"               ] && export COCKROACH_DATABASE="${COCKROACH_MAINTENANCE_DATABASE-postgres}"
[ -z "${COCKROACH_JDBC_URL-}"               ] && export COCKROACH_JDBC_URL="jdbc:postgresql://${COCKROACH_HOST:?}:${COCKROACH_PORT:?}"
[ -z "${COCKROACH_JDBC_PROPS-}"             ] && export COCKROACH_JDBC_PROPS=''
[ -z "${COCKROACH_JACKRABBIT_USER-}"        ] && export COCKROACH_JACKRABBIT_USER='jcr_user'
[ -z "${COCKROACH_JACKRABBIT_PASSWORD-}"    ] && export COCKROACH_JACKRABBIT_PASSWORD='jcr_password'
[ -z "${COCKROACH_JACKRABBIT_DATABASE-}"    ] && export COCKROACH_JACKRABBIT_DATABASE='jackrabbit'
[ -z "${COCKROACH_JACKRABBIT_JDBC_URL-}"    ] && export COCKROACH_JACKRABBIT_JDBC_URL="${COCKROACH_JDBC_URL:?}/${COCKROACH_JACKRABBIT_DATABASE:?}?${COCKROACH_JDBC_PROPS?}"
[ -z "${COCKROACH_HIBERNATE_USER-}"         ] && export COCKROACH_HIBERNATE_USER='hibuser'
[ -z "${COCKROACH_HIBERNATE_PASSWORD-}"     ] && export COCKROACH_HIBERNATE_PASSWORD='hibpassword'
[ -z "${COCKROACH_HIBERNATE_DATABASE-}"     ] && export COCKROACH_HIBERNATE_DATABASE='hibernate'
[ -z "${COCKROACH_HIBERNATE_JDBC_URL-}"     ] && export COCKROACH_HIBERNATE_JDBC_URL="${COCKROACH_JDBC_URL:?}/${COCKROACH_HIBERNATE_DATABASE:?}?${COCKROACH_JDBC_PROPS?}"
[ -z "${COCKROACH_QUARTZ_USER-}"            ] && export COCKROACH_QUARTZ_USER='pentaho_user'
[ -z "${COCKROACH_QUARTZ_PASSWORD-}"        ] && export COCKROACH_QUARTZ_PASSWORD='pentaho_password'
[ -z "${COCKROACH_QUARTZ_DATABASE-}"        ] && export COCKROACH_QUARTZ_DATABASE='quartz'
[ -z "${COCKROACH_QUARTZ_JDBC_URL-}"        ] && export COCKROACH_QUARTZ_JDBC_URL="${COCKROACH_JDBC_URL:?}/${COCKROACH_QUARTZ_DATABASE:?}?${COCKROACH_JDBC_PROPS?}"

if [ "${STORAGE_TYPE:?}" = 'cockroach' ]; then
	[ -z "${HIBERNATE_CONFIG_FILE-}" ] && export HIBERNATE_CONFIG_FILE='system/hibernate/cockroach.hibernate.cfg.xml'
fi

[ -z "${MYSQL_HOST-}"                   ] && export MYSQL_HOST='localhost'
[ -z "${MYSQL_PORT-}"                   ] && export MYSQL_PORT='3306'
[ -z "${MYSQL_USER-}"                   ] && export MYSQL_USER="${MYSQL_MAINTENANCE_USER-root}"
[ -z "${MYSQL_PASSWORD-}"               ] && export MYSQL_PASSWORD="${MYSQL_MAINTENANCE_PASSWORD-root}"
[ -z "${MYSQL_DATABASE-}"               ] && export MYSQL_DATABASE="${MYSQL_MAINTENANCE_DATABASE-mysql}"
[ -z "${MYSQL_JDBC_URL-}"               ] && export MYSQL_JDBC_URL="jdbc:mysql://${MYSQL_HOST:?}:${MYSQL_PORT:?}"
[ -z "${MYSQL_JDBC_PROPS-}"             ] && export MYSQL_JDBC_PROPS=''
[ -z "${MYSQL_JACKRABBIT_USER-}"        ] && export MYSQL_JACKRABBIT_USER='jcr_user'
[ -z "${MYSQL_JACKRABBIT_PASSWORD-}"    ] && export MYSQL_JACKRABBIT_PASSWORD='jcr_password'
[ -z "${MYSQL_JACKRABBIT_DATABASE-}"    ] && export MYSQL_JACKRABBIT_DATABASE='jackrabbit'
[ -z "${MYSQL_JACKRABBIT_JDBC_URL-}"    ] && export MYSQL_JACKRABBIT_JDBC_URL="${MYSQL_JDBC_URL:?}/${MYSQL_JACKRABBIT_DATABASE:?}?${MYSQL_JDBC_PROPS?}"
[ -z "${MYSQL_HIBERNATE_USER-}"         ] && export MYSQL_HIBERNATE_USER='hibuser'
[ -z "${MYSQL_HIBERNATE_PASSWORD-}"     ] && export MYSQL_HIBERNATE_PASSWORD='hibpassword'
[ -z "${MYSQL_HIBERNATE_DATABASE-}"     ] && export MYSQL_HIBERNATE_DATABASE='hibernate'
[ -z "${MYSQL_HIBERNATE_JDBC_URL-}"     ] && export MYSQL_HIBERNATE_JDBC_URL="${MYSQL_JDBC_URL:?}/${MYSQL_HIBERNATE_DATABASE:?}?${MYSQL_JDBC_PROPS?}"
[ -z "${MYSQL_QUARTZ_USER-}"            ] && export MYSQL_QUARTZ_USER='pentaho_user'
[ -z "${MYSQL_QUARTZ_PASSWORD-}"        ] && export MYSQL_QUARTZ_PASSWORD='pentaho_password'
[ -z "${MYSQL_QUARTZ_DATABASE-}"        ] && export MYSQL_QUARTZ_DATABASE='quartz'
[ -z "${MYSQL_QUARTZ_JDBC_URL-}"        ] && export MYSQL_QUARTZ_JDBC_URL="${MYSQL_JDBC_URL:?}/${MYSQL_QUARTZ_DATABASE:?}?${MYSQL_JDBC_PROPS?}"

if [ "${STORAGE_TYPE:?}" = 'mysql' ]; then
	[ -z "${HIBERNATE_CONFIG_FILE-}" ] && export HIBERNATE_CONFIG_FILE='system/hibernate/mysql5.hibernate.cfg.xml'
fi

[ -z "${DEFAULT_ADMIN_PASSWORD-}"     ] && export DEFAULT_ADMIN_PASSWORD='password'
[ -z "${DEFAULT_NON_ADMIN_PASSWORD-}" ] && export DEFAULT_NON_ADMIN_PASSWORD="${DEFAULT_ADMIN_PASSWORD:?}"

########

# Directory rename setup
/usr/share/biserver/bin/setup-rename.sh

# General setup
/usr/share/biserver/bin/setup-general.sh

# biserver.priv.init.d/ setup
if [ -d "${BISERVER_PRIV_INITD:?}" ]; then
	/usr/share/biserver/bin/setup-initd.sh "${BISERVER_PRIV_INITD:?}"
fi

# biserver.init.d/ setup
if [ -d "${BISERVER_INITD:?}" ]; then
	/usr/share/biserver/bin/setup-initd.sh "${BISERVER_INITD:?}"
fi

# PostgreSQL setup
if [ "${STORAGE_TYPE:?}" = 'postgres' ]; then
	/usr/share/biserver/bin/setup-storage-postgres.sh
fi

# CockroachDB setup
if [ "${STORAGE_TYPE:?}" = 'cockroach' ]; then
	/usr/share/biserver/bin/setup-storage-cockroach.sh
fi

# MySQL setup
if [ "${STORAGE_TYPE:?}" = 'mysql' ]; then
	/usr/share/biserver/bin/setup-storage-mysql.sh
fi
