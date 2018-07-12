FROM ubuntu:18.04

# Install dependencies
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		curl \
		netcat-traditional \
		openjdk-8-jdk \
		postgresql-client \
		unzip tar bzip2 gzip lzip lzma lzop xz-utils \
	&& rm -rf /var/lib/apt/lists/*

# Pentaho BI Server environment
ENV BISERVER_HOME="/opt/biserver"
ENV BISERVER_SOLUTION_PATH="${BISERVER_HOME}/pentaho-solutions"
ENV BISERVER_DATA_PATH="${BISERVER_HOME}/data"
ENV BISERVER_INITD="/opt/biserver.init.d"

ARG BISERVER_STORAGE="local"
ENV BISERVER_STORAGE="${BISERVER_STORAGE}"

ENV CATALINA_HOME="${BISERVER_HOME}/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV CATALINA_PID="${CATALINA_BASE}/bin/catalina.pid"

ARG WEBAPP_PENTAHO_NAME="pentaho"
ENV WEBAPP_PENTAHO_NAME="${WEBAPP_PENTAHO_NAME}"
ARG WEBAPP_PENTAHO_STYLE_NAME="pentaho-style"
ENV WEBAPP_PENTAHO_STYLE_NAME="${WEBAPP_PENTAHO_STYLE_NAME}"

# Copy build scripts
COPY --chown=root:root scripts/build-* /usr/local/bin/

# Create pentaho user and group
ENV PENTAHO_UID=5000
ENV PENTAHO_GID=5000
RUN groupadd \
		--gid "${PENTAHO_GID}" \
		pentaho \
	&& useradd \
		--uid "${PENTAHO_UID}" \
		--gid "${PENTAHO_GID}" \
		--home-dir /var/cache/pentaho/ \
		--create-home \
		pentaho

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
	&& /usr/local/bin/build-tomcat-dl \
		"${TOMCAT_MAJOR_VERSION}" \
		"${TOMCAT_MINOR_VERSION}" \
		"${TOMCAT_PATCH_VERSION}" \
		/tmp/tomcat/ \
	# Install Tomcat
	&& mkdir -p "${CATALINA_HOME}" "${CATALINA_BASE}" \
	&& (cd /tmp/tomcat/ \
		&& mv ./bin/ "${CATALINA_HOME}" \
		&& mv ./conf/ "${CATALINA_BASE}" \
		&& mv ./lib/ "${CATALINA_HOME}" \
		# Skip logs, temp, webapps and work
		&& mkdir "${CATALINA_BASE}"/logs/ \
		&& mkdir "${CATALINA_BASE}"/temp/ \
		&& mkdir "${CATALINA_BASE}"/webapps/ \
		&& mkdir "${CATALINA_BASE}"/work/ \
	) \
	# Build and install Tomcat Native Library
	&& mkdir /tmp/tomcat-native \
	&& (cd /tmp/tomcat/ \
		&& tar \
			--strip-components=1 \
			-xvf "${CATALINA_HOME}"/bin/tomcat-native.tar.gz \
		&& cd ./native \
		&& ./configure \
			--with-java-home="$(dirname $(dirname $(readlink -f $(which javac))))" \
			--prefix="${CATALINA_HOME}" \
		&& make \
		&& make install \
	) \
	# Set permissions
	&& chown -R pentaho:pentaho \
		"${CATALINA_HOME}" "${CATALINA_BASE}" \
	&& find \
		"${CATALINA_HOME}" "${CATALINA_BASE}" \
		-type f \
		-exec chmod 644 '{}' \; \
	&& find \
		"${CATALINA_HOME}" "${CATALINA_BASE}" \
		-type d -o \( -type f -iname '*.sh' \) \
		-exec chmod 755 '{}' \; \
	# Cleanup
	&& apt-get purge -y ${BUILD_PKGS} \
	&& apt-get autoremove -y \
	&& find /tmp/ -mindepth 1 -delete

# Copy Tomcat libraries and placeholders
COPY --chown=pentaho:pentaho config/biserver/tomcat/lib/ "${CATALINA_BASE}"/lib/

# Download Tomcat libraries
RUN printf '%s\n' 'Downloading Tomcat libraries...' \
	&& for placeholder in "${CATALINA_BASE}"/lib/*.download; do \
		url=$(cat "${placeholder}" | tr -d '\n'); \
		file=$(basename "${placeholder}" .download); \
		printf '%s\n' "Downloading \"${file}\"..."; \
		curl -o "${CATALINA_BASE}"/lib/"${file}" "${url}"; \
		chown pentaho:pentaho "${CATALINA_BASE}"/lib/"${file}"; \
		rm "${placeholder}"; \
	done

ARG BISERVER_VERSION='7.1.0.0-12'
ARG BISERVER_MAVEN_REPO='https://nexus.pentaho.org/content/groups/omni/'
RUN printf '%s\n' 'Installing Pentaho BI Server...' \
	# Download Pentaho BI Server
	&& /usr/local/bin/build-biserver-dl \
		"${BISERVER_VERSION}" \
		"${BISERVER_MAVEN_REPO}" \
		/tmp/biserver/ \
	# Install Pentaho BI Server
	&& mkdir -p "${BISERVER_HOME}" \
	&& (cd /tmp/biserver/ \
		&& unzip ./pentaho-solutions.zip \
		&& unzip ./pentaho-data.zip \
		&& mv ./pentaho-solutions "${BISERVER_SOLUTION_PATH}" \
		&& mv ./data "${BISERVER_DATA_PATH}" \
	) \
	&& (mkdir "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		&& cd "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		&& jar -xvf /tmp/biserver/pentaho.war \
	) \
	&& (mkdir "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
		&& cd "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
		&& jar -xvf /tmp/biserver/pentaho-style.war \
	) \
	# Set permissions
	&& chown -R pentaho:pentaho \
		"${BISERVER_HOME}" \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
	&& find \
		"${BISERVER_HOME}" \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
		-type f -exec chmod 644 '{}' \; \
	&& find \
		"${BISERVER_HOME}" \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
		-type d -o \( -type f -iname '*.sh' \) \
		-exec chmod 755 '{}' \; \
	# Cleanup
	&& find /tmp/ -mindepth 1 -delete

# Copy Tomcat config
COPY --chown=pentaho:pentaho config/biserver/tomcat/conf/ "${CATALINA_BASE}"/conf/
COPY --chown=pentaho:pentaho config/biserver/tomcat/webapps/ROOT/ "${CATALINA_BASE}"/webapps/ROOT/
COPY --chown=pentaho:pentaho config/biserver/tomcat/webapps/pentaho/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}"/
COPY --chown=pentaho:pentaho config/biserver/tomcat/webapps/pentaho-style/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}"/

# Copy Pentaho BI Server config
COPY --chown=pentaho:pentaho config/biserver/pentaho-solutions/ "${BISERVER_SOLUTION_PATH}"/
COPY --chown=pentaho:pentaho config/biserver/data/ "${BISERVER_DATA_PATH}"/
COPY --chown=pentaho:pentaho config/biserver.init.d/ "${BISERVER_INITD}"/

# Copy runtime scripts
COPY --chown=root:root scripts/setup-* /usr/local/bin/
COPY --chown=root:root scripts/start-* /usr/local/bin/

# Don't declare volumes, let the user decide
#VOLUME "${BISERVER_SOLUTION_PATH}/system/jackrabbit/repository/"
#VOLUME "${BISERVER_DATA_PATH}/hsqldb/"
#VOLUME "${CATALINA_BASE}/logs/"

WORKDIR "${BISERVER_HOME}"

EXPOSE 8080/tcp
EXPOSE 8009/tcp

USER pentaho:pentaho

CMD ["/usr/local/bin/start-biserver"]
