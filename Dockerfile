FROM ubuntu:18.04

# Install dependencies
RUN export DEBIAN_FRONTEND=noninteractive \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
		apt-transport-https \
		apt-utils \
		bash \
		bzip2 \
		ca-certificates \
		curl \
		diffutils \
		file \
		findutils \
		gnupg \
		gzip \
		jq \
		libarchive-tools \
		libwebkitgtk-1.0-0 \
		locales \
		lsb-release \
		lzip \
		lzma \
		lzop \
		nano \
		netcat-openbsd \
		openjdk-8-jdk \
		openssl \
		ruby \
		tar \
		tzdata \
		unzip \
		xxd \
		xz-utils \
		zip \
	&& rm -rf /var/lib/apt/lists/*

# Install PostgreSQL client
RUN export DEBIAN_FRONTEND=noninteractive \
	&& printf '%s\n' 'deb https://apt.postgresql.org/pub/repos/apt/ bionic-pgdg main' > /etc/apt/sources.list.d/pgdg.list \
	&& curl -fsSL 'https://www.postgresql.org/media/keys/ACCC4CF8.asc' | apt-key add - \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
		postgresql-client-11 \
	&& rm -rf /var/lib/apt/lists/*

# Install MySQL client
RUN export DEBIAN_FRONTEND=noninteractive \
	&& printf '%s\n' 'deb https://repo.mysql.com/apt/ubuntu/ bionic mysql-8.0' > /etc/apt/sources.list.d/mysql.list \
	&& curl -fsSL 'https://repo.mysql.com/RPM-GPG-KEY-mysql' | apt-key add - \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
		mysql-client \
	&& rm -rf /var/lib/apt/lists/*

# Setup locale
RUN sed -i 's|^# \(en_US\.UTF-8 UTF-8\)$|\1|' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# Setup timezone
ENV TZ=Etc/UTC
RUN ln -sf /usr/share/zoneinfo/"${TZ}" /etc/localtime

# Java environment
RUN ln -rs "$(dirname $(dirname $(readlink -f $(which javac))))" /usr/lib/jvm/java
ENV JAVA_HOME="/usr/lib/jvm/java"
ENV JDK_HOME="${JAVA_HOME}"
ENV JRE_HOME="${JAVA_HOME}/jre"

# Tomcat environment
ENV CATALINA_HOME="/var/lib/biserver/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV CATALINA_PID="${CATALINA_BASE}/bin/catalina.pid"

# Copy build scripts
COPY --chown=root:root build-scripts/ /opt/build-scripts/

ENV TOMCAT_GID=5000
ENV TOMCAT_UID=5000
RUN printf '%s\n' 'Creating users and groups...' \
	# Create users and groups
	&& groupadd --gid "${TOMCAT_GID}" tomcat \
	&& useradd \
		--uid "${TOMCAT_UID}" \
		--gid "${TOMCAT_GID}" \
		--shell "$(command -v bash)" \
		--home-dir /var/cache/tomcat/ \
		--create-home \
		tomcat

ARG TOMCAT_MAJOR_VERSION=8
ARG TOMCAT_MINOR_VERSION=5
ARG TOMCAT_PATCH_VERSION=latest
RUN printf '%s\n' 'Installing Tomcat...' \
	# Install dependencies
	&& RUN_PKGS="libapr1 libssl1.1" \
	&& BUILD_PKGS="make gcc libapr1-dev libssl-dev" \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
		${RUN_PKGS} ${BUILD_PKGS} \
	# Download Tomcat
	&& /opt/build-scripts/download-tomcat.sh \
		"${TOMCAT_MAJOR_VERSION}" \
		"${TOMCAT_MINOR_VERSION}" \
		"${TOMCAT_PATCH_VERSION}" \
		/tmp/tomcat/ \
	# Install Tomcat
	&& mkdir -p "${CATALINA_HOME}" "${CATALINA_BASE}" \
	&& (cd /tmp/tomcat/ \
		&& mv ./bin/ "${CATALINA_HOME}" \
		&& mv ./lib/ "${CATALINA_HOME}" \
		&& mv ./conf/ "${CATALINA_BASE}" \
		&& mkdir "${CATALINA_BASE}"/conf/Catalina/ \
		&& mkdir "${CATALINA_BASE}"/logs/ \
		&& mkdir "${CATALINA_BASE}"/temp/ \
		&& mkdir "${CATALINA_BASE}"/webapps/ \
		&& mkdir "${CATALINA_BASE}"/work/ \
	) \
	# Build and install Tomcat Native Library
	&& mkdir /tmp/tomcat-native \
	&& (cd /tmp/tomcat-native/ \
		&& tar --strip-components=1 -xvf "${CATALINA_HOME}"/bin/tomcat-native.tar.gz \
		&& cd ./native/ && ./configure --prefix="${CATALINA_HOME}" \
		&& make && make install \
	) \
	# Hide version number
	&& mkdir -p "${CATALINA_HOME}"/lib/org/apache/catalina/util/ \
	&& bsdtar -xOf "${CATALINA_HOME}"/lib/catalina.jar org/apache/catalina/util/ServerInfo.properties \
		| sed 's|^\(server\.info\)=.*$|\1=Apache Tomcat|g' \
		> "${CATALINA_HOME}"/lib/org/apache/catalina/util/ServerInfo.properties \
	# Set permissions
	&& find \
		"${CATALINA_HOME}" "${CATALINA_BASE}" \
		-exec chown tomcat:tomcat '{}' ';' \
		-exec sh -c 'if [ -d "{}" ]; then chmod 755 "{}"; fi' ';' \
		-exec sh -c 'if [ -f "{}" ]; then chmod 644 "{}"; fi' ';' \
	&& chmod 755 "${CATALINA_HOME}"/bin/*.sh \
	# Cleanup
	&& apt-get purge -y ${BUILD_PKGS} \
	&& apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/* \
	&& find /tmp/ -mindepth 1 -delete

# Copy Tomcat libraries and placeholders
COPY --chown=tomcat:tomcat config/biserver/tomcat/lib/ "${CATALINA_BASE}"/lib/

# Download Tomcat libraries
RUN printf '%s\n' 'Downloading Tomcat libraries...' \
	&& jsonFile="${CATALINA_BASE}"/lib/jars.json \
	&& jarsCount="$(jq -r '.|length-1' "${jsonFile}")" \
	&& for i in $(seq 0 "${jarsCount}"); do \
		filename=$(jq -r --arg i "${i}" '.[$i|tonumber].filename' "${jsonFile}"); \
		checksum=$(jq -r --arg i "${i}" '.[$i|tonumber].checksum' "${jsonFile}"); \
		download=$(jq -r --arg i "${i}" '.[$i|tonumber].download' "${jsonFile}"); \
		output="${CATALINA_BASE}"/lib/"${filename}" \
		&& printf '%s\n' "Downloading \"${filename}\"..." \
		&& curl -Lo "${output}" "${download}" \
		&& printf '%s\n' "Verifying checksum..." \
		&& printf '%s\n' "${checksum}  ${output}" | sha256sum -c \
		&& chown tomcat:tomcat "${output}"; \
	done && rm -f "${jsonFile}"

# Pentaho BI Server environment
ENV BISERVER_HOME="/var/lib/biserver"
ENV BISERVER_INITD="/etc/biserver.init.d"

ARG KETTLE_DIRNAME="kettle"
ENV KETTLE_DIRNAME="${KETTLE_DIRNAME}"
ENV KETTLE_DEFAULT_DIRNAME="${KETTLE_DIRNAME}"

ARG SOLUTIONS_DIRNAME="pentaho-solutions"
ENV SOLUTIONS_DIRNAME="${SOLUTIONS_DIRNAME}"
ENV SOLUTIONS_DEFAULT_DIRNAME="${SOLUTIONS_DIRNAME}"

ARG DATA_DIRNAME="data"
ENV DATA_DIRNAME="${DATA_DIRNAME}"
ENV DATA_DEFAULT_DIRNAME="${DATA_DIRNAME}"

ARG WEBAPP_PENTAHO_DIRNAME="pentaho"
ENV WEBAPP_PENTAHO_DIRNAME="${WEBAPP_PENTAHO_DIRNAME}"
ENV WEBAPP_PENTAHO_DEFAULT_DIRNAME="${WEBAPP_PENTAHO_DIRNAME}"

ARG WEBAPP_PENTAHO_STYLE_DIRNAME="pentaho-style"
ENV WEBAPP_PENTAHO_STYLE_DIRNAME="${WEBAPP_PENTAHO_STYLE_DIRNAME}"
ENV WEBAPP_PENTAHO_STYLE_DEFAULT_DIRNAME="${WEBAPP_PENTAHO_STYLE_DIRNAME}"

ARG BISERVER_VERSION='8.3.0.0-371'
ARG BISERVER_MAVEN_REPO='https://repo.stratebi.com/repository/pentaho-mvn/'
#ARG BISERVER_MAVEN_REPO='https://nexus.pentaho.org/content/groups/omni/'
RUN printf '%s\n' 'Installing Pentaho BI Server...' \
	# Download Pentaho BI Server
	&& /opt/build-scripts/download-biserver.sh "${BISERVER_VERSION}" "${BISERVER_MAVEN_REPO}" /tmp/biserver/ \
	# Install Pentaho BI Server
	&& mkdir -p \
		"${BISERVER_HOME}"/"${KETTLE_DIRNAME}" \
		"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}" \
		"${BISERVER_HOME}"/"${DATA_DIRNAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}" \
	&& (cd /tmp/biserver/ \
		&& bsdtar -C "${BISERVER_HOME}"/"${KETTLE_DIRNAME}" --strip-components=3 -xvf ./pentaho-solutions.zip 'pentaho-solutions/system/kettle/*' \
		&& bsdtar -C "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}" --strip-components=1 --exclude 'pentaho-solutions/system/kettle/*' -xvf ./pentaho-solutions.zip \
		&& bsdtar -C "${BISERVER_HOME}"/"${DATA_DIRNAME}" --strip-components=1 -xvf ./pentaho-data.zip\
		&& bsdtar -C "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}" -xvf ./pentaho.war \
		&& bsdtar -C "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}" -xvf ./pentaho-style.war \
	) \
	# Download Pentaho BI Server resources
	&& /opt/build-scripts/download-biserver-resources.sh "${BISERVER_VERSION}" "${BISERVER_HOME}" \
	# Set permissions
	&& chown tomcat:tomcat "${BISERVER_HOME}" \
	&& find \
		"${BISERVER_HOME}"/"${KETTLE_DIRNAME}" \
		"${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}" \
		"${BISERVER_HOME}"/"${DATA_DIRNAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}" \
		-exec chown tomcat:tomcat '{}' ';' \
		-exec sh -c 'if [ -d "{}" ]; then chmod 755 "{}"; fi' ';' \
		-exec sh -c 'if [ -f "{}" ]; then chmod 644 "{}"; fi' ';' \
	&& chmod 755 "${BISERVER_HOME}"/*.sh \
	# Cleanup
	&& find /tmp/ -mindepth 1 -delete

# Copy Tomcat config
COPY --chown=tomcat:tomcat config/biserver/tomcat/conf/ "${CATALINA_BASE}"/conf/
COPY --chown=tomcat:tomcat config/biserver/tomcat/webapps/ROOT/ "${CATALINA_BASE}"/webapps/ROOT/
COPY --chown=tomcat:tomcat config/biserver/tomcat/webapps/pentaho/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/
COPY --chown=tomcat:tomcat config/biserver/tomcat/webapps/pentaho-style/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}"/

# Copy Pentaho BI Server config
COPY --chown=tomcat:tomcat config/biserver/pentaho-solutions/ "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/
COPY --chown=tomcat:tomcat config/biserver/data/ "${BISERVER_HOME}"/"${DATA_DIRNAME}"/
COPY --chown=root:root config/biserver.init.d/ "${BISERVER_INITD}"/

# Copy runtime scripts
COPY --chown=root:root scripts/ /opt/scripts/

# Don't declare volumes, let the user decide
#VOLUME "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository/
#VOLUME "${BISERVER_HOME}"/"${DATA_DIRNAME}/hsqldb/"
#VOLUME "${CATALINA_BASE}"/logs/

# Drop root privileges
USER tomcat:tomcat

WORKDIR "${BISERVER_HOME}"
CMD ["/opt/scripts/start.sh"]
