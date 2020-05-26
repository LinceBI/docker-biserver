#!/bin/sh

set -eu
export LC_ALL=C

# shellcheck source=./set-utils.sh
. /usr/share/biserver/bin/set-utils.sh

########

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
