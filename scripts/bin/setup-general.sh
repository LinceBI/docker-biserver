#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

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
