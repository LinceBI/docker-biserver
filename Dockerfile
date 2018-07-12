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

# Download and install Tomcat
ARG TOMCAT_MAJOR_VERSION=8
ARG TOMCAT_MINOR_VERSION=5
ARG TOMCAT_PATCH_VERSION=latest
RUN mkdir -p "${CATALINA_HOME}" "${CATALINA_BASE}" \
	&& /usr/local/bin/build-tomcat-dl \
		${TOMCAT_MAJOR_VERSION} \
		${TOMCAT_MINOR_VERSION} \
		${TOMCAT_PATCH_VERSION} \
		/tmp/tomcat/ \
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
	&& find /tmp/ -mindepth 1 -delete

# Download and install Pentaho BI Server
ARG BISERVER_VERSION='7.1.0.0-12'
ARG BISERVER_MAVEN_REPO='https://nexus.pentaho.org/content/groups/omni/'
RUN mkdir -p "${BISERVER_HOME}" \
	&& /usr/local/bin/build-biserver-dl \
		${BISERVER_VERSION} \
		${BISERVER_MAVEN_REPO} \
		/tmp/biserver/ \
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

# Copy Tomcat libraries and placeholders
COPY --chown=pentaho:pentaho config/biserver/tomcat/lib/ "${CATALINA_BASE}"/lib/

# Download Tomcat libraries
RUN for placeholder in "${CATALINA_BASE}"/lib/*.download; do \
		url=$(cat "${placeholder}" | tr -d '\n'); \
		file=$(basename "${placeholder}" .download); \
		printf '%s\n' "Downloading \"${file}\"..."; \
		curl -o "${CATALINA_BASE}"/lib/"${file}" "${url}"; \
		chown pentaho:pentaho "${CATALINA_BASE}"/lib/"${file}"; \
		rm "${placeholder}"; \
	done

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
