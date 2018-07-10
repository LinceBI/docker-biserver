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
ENV BISERVER_STORAGE="local"

ENV CATALINA_HOME="${BISERVER_HOME}/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV CATALINA_PID="${CATALINA_BASE}/bin/catalina.pid"

ENV WEBAPP_PENTAHO_NAME="pentaho"
ENV WEBAPP_PENTAHO_PATH="${CATALINA_BASE}/webapps/${WEBAPP_PENTAHO_NAME}"
ENV WEBAPP_PENTAHO_STYLE_NAME="pentaho-style"
ENV WEBAPP_PENTAHO_STYLE_PATH="${CATALINA_BASE}/webapps/${WEBAPP_PENTAHO_STYLE_NAME}"

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
ARG TOMCAT_PKG_URL=
RUN if [ -z "${TOMCAT_PKG_URL}" ]; then \
		printf '%s\n' 'TOMCAT_PKG_URL cannot be blank!'; \
		exit 1; \
	fi \
	# Download and extract package
	&& mkdir -p "${CATALINA_HOME}" "${CATALINA_BASE}" \
	&& curl -Lo /tmp/tomcat.zip "${TOMCAT_PKG_URL}" \
	&& unzip /tmp/tomcat.zip -d /tmp/tomcat/ \
	&& (cd /tmp/tomcat/apache-tomcat-*/ \
		&& mv ./bin/ "${CATALINA_HOME}" \
		&& mv ./conf/ "${CATALINA_BASE}" \
		&& mv ./lib/ "${CATALINA_HOME}" \
		&& mv ./logs/ "${CATALINA_BASE}" \
		&& mv ./temp/ "${CATALINA_BASE}" \
		&& mv ./work/ "${CATALINA_BASE}" \
		# Skip default webapps
		&& mkdir "${CATALINA_BASE}"/webapps/ \
	) \
	# Cleanup
	&& rm -r /tmp/tomcat/ /tmp/tomcat.zip \
	# Set permissions
	&& chown -R pentaho:pentaho \
		"${CATALINA_HOME}" "${CATALINA_BASE}" \
	&& find \
		"${CATALINA_HOME}" "${CATALINA_BASE}" \
		-type f \
		-exec chmod 644 '{}' \; \
	&& find \
		"${CATALINA_HOME}" "${CATALINA_BASE}" \
		-type d -or \( -type f -iname '*.sh' \) \
		-exec chmod 755 '{}' \;

# Download and install Pentaho BI Server
ARG BISERVER_PKG_URL=
RUN if [ -z "${BISERVER_PKG_URL}" ]; then \
		printf '%s\n' 'BISERVER_PKG_URL cannot be blank!'; \
		exit 1; \
	fi \
	# Download and extract package
	&& mkdir -p "${BISERVER_HOME}" \
	&& curl -Lo /tmp/biserver.zip "${BISERVER_PKG_URL}" \
	&& unzip /tmp/biserver.zip -d /tmp/biserver/ \
	&& (cd /tmp/biserver/ \
		&& unzip ./pentaho-solutions.zip \
		&& mv ./pentaho-solutions "${BISERVER_SOLUTION_PATH}" \
		&& unzip ./pentaho-data.zip \
		&& mv ./data "${BISERVER_DATA_PATH}" \
	) \
	&& (mkdir "${WEBAPP_PENTAHO_PATH}" \
		&& cd "${WEBAPP_PENTAHO_PATH}" \
		&& jar -xvf /tmp/biserver/pentaho.war \
	) \
	&& (mkdir "${WEBAPP_PENTAHO_STYLE_PATH}" \
		&& cd "${WEBAPP_PENTAHO_STYLE_PATH}" \
		&& jar -xvf /tmp/biserver/pentaho-style.war \
	) \
	# Cleanup
	&& rm -r /tmp/biserver/ /tmp/biserver.zip \
	# Set permissions
	&& chown -R pentaho:pentaho \
		"${BISERVER_HOME}" \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${WEBAPP_PENTAHO_PATH}" "${WEBAPP_PENTAHO_STYLE_PATH}" \
	&& find \
		"${BISERVER_HOME}" \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${WEBAPP_PENTAHO_PATH}" "${WEBAPP_PENTAHO_STYLE_PATH}" \
		-type f -exec chmod 644 '{}' \; \
	&& find \
		"${BISERVER_HOME}" \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${WEBAPP_PENTAHO_PATH}" "${WEBAPP_PENTAHO_STYLE_PATH}" \
		-type d -or \( -type f -iname '*.sh' \) \
		-exec chmod 755 '{}' \;

# Copy Tomcat config
COPY --chown=pentaho:pentaho config/biserver/tomcat/ "${CATALINA_BASE}"

# Download Tomcat libraries
RUN for placeholder in "${CATALINA_BASE}"/lib/*.download; do \
		url=$(cat "${placeholder}" | tr -d '\n'); \
		file=$(basename "${placeholder}" .download); \
		printf '%s\n' "Downloading \"${file}\"..."; \
		curl -o "${CATALINA_BASE}"/lib/"${file}" "${url}"; \
		chown pentaho:pentaho "${CATALINA_BASE}"/lib/"${file}"; \
		rm "${placeholder}"; \
	done

# Copy Pentaho BI Server config
COPY --chown=pentaho:pentaho config/biserver/pentaho-solutions/ "${BISERVER_SOLUTION_PATH}"
COPY --chown=pentaho:pentaho config/biserver/data/ "${BISERVER_DATA_PATH}"
COPY --chown=pentaho:pentaho config/biserver.init.d/ "${BISERVER_INITD}"

# Copy scripts
COPY --chown=root:root scripts/ /usr/local/bin/

VOLUME "${BISERVER_SOLUTION_PATH}/system/jackrabbit/repository"
VOLUME "${BISERVER_DATA_PATH}/hsqldb"
VOLUME "${CATALINA_BASE}/logs"

WORKDIR "${BISERVER_HOME}"

EXPOSE 8080/tcp
EXPOSE 8009/tcp

USER pentaho:pentaho

CMD ["/usr/local/bin/start-pentaho"]
