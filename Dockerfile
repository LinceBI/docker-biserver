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

# Download and install Tomcat 8
ARG TOMCAT_PKG_URL=
ENV CATALINA_BASE=/opt/biserver/tomcat
ENV CATALINA_HOME=/opt/biserver/tomcat
ENV CATALINA_TMPDIR=/opt/biserver/tomcat/temp
ENV CATALINA_PID=/opt/biserver/tomcat/bin/catalina.pid
RUN if [ -z "${TOMCAT_PKG_URL}" ]; then \
		printf '%s\n' 'TOMCAT_PKG_URL cannot be blank!'; \
		exit 1; \
	fi \
	&& mkdir -p "${CATALINA_HOME}" \
	&& curl -Lo /tmp/tomcat.zip "${TOMCAT_PKG_URL}" \
	&& unzip /tmp/tomcat.zip -d /tmp/tomcat/ \
	&& mv /tmp/tomcat/apache-tomcat-*/* "${CATALINA_HOME}" \
	&& chown -R pentaho:pentaho "${CATALINA_HOME}" \
	&& find "${CATALINA_HOME}" -type f -iname '*.sh' -exec chmod 755 '{}' \; \
	&& rm -r \
		"${CATALINA_HOME}"/webapps/* \
		/tmp/tomcat/ /tmp/tomcat.zip

# Download and install Pentaho BI Server
ARG BISERVER_PKG_URL=
ARG BISERVER_ENABLE_POSTGRES=false
ENV BISERVER_HOME=/opt/biserver
ENV BISERVER_INITD=/opt/biserver.init.d
RUN if [ -z "${BISERVER_PKG_URL}" ]; then \
		printf '%s\n' 'BISERVER_PKG_URL cannot be blank!'; \
		exit 1; \
	fi \
	&& mkdir -p "${BISERVER_HOME}" \
	&& curl -Lo /tmp/biserver.zip "${BISERVER_PKG_URL}" \
	&& unzip /tmp/biserver.zip -d /tmp/biserver/ \
	&& (mkdir "${CATALINA_HOME}"/webapps/pentaho/ \
		&& cd "${CATALINA_HOME}"/webapps/pentaho/ \
		&& jar -xvf /tmp/biserver/pentaho.war \
	) \
	&& (mkdir "${CATALINA_HOME}"/webapps/pentaho-style/ \
		&& cd "${CATALINA_HOME}"/webapps/pentaho-style/ \
		&& jar -xvf /tmp/biserver/pentaho-style.war \
	) \
	&& unzip /tmp/biserver/pentaho-solutions.zip -d "${BISERVER_HOME}" \
	&& unzip /tmp/biserver/pentaho-data.zip -d "${BISERVER_HOME}" \
	&& chown -R pentaho:pentaho "${BISERVER_HOME}" \
	&& find "${BISERVER_HOME}" -type f -iname '*.sh' -exec chmod 755 '{}' \; \
	&& rm -r /tmp/biserver/ /tmp/biserver.zip

# Copy resources
COPY --chown=root:root scripts/ /usr/local/bin/
COPY --chown=pentaho:pentaho config/biserver/ /opt/biserver/
COPY --chown=pentaho:pentaho config/biserver.init.d/ /opt/biserver.init.d/

# Download Tomcat libraries
RUN for download in "${CATALINA_HOME}"/lib/*.download; do \
		url=$(cat -- "${download}" | tr -d '\n'); \
		file=$(basename -- "${download}" .download); \
		printf '%s\n' "Downloading \"${file}\"..."; \
		curl -o "${CATALINA_HOME}/lib/${file}" "${url}"; \
		chown pentaho:pentaho "${CATALINA_HOME}/lib/${file}"; \
		rm -- "${download}"; \
	done

USER pentaho:pentaho

VOLUME /opt/biserver/data/hsqldb
VOLUME /opt/biserver/pentaho-solutions/system/jackrabbit/repository
VOLUME /opt/biserver/tomcat/logs

WORKDIR /opt/biserver

EXPOSE 8080/tcp
EXPOSE 8009/tcp

CMD ["/usr/local/bin/start-pentaho"]
