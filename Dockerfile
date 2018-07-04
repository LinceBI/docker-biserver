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
		unzip \
	&& rm -rf /var/lib/apt/lists/*

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
	&& rm -r \
		"${CATALINA_HOME}"/webapps/* \
		/tmp/tomcat/ /tmp/tomcat.zip

# Download and install Pentaho BI Server
ARG BISERVER_PKG_URL=
ENV BISERVER_HOME=/opt/biserver
ENV BISERVER_ENABLE_POSTGRES=false
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
	&& find "${BISERVER_HOME}" -type f -iname '*.sh' -exec chmod 755 '{}' \; \
	&& rm -r /tmp/biserver/ /tmp/biserver.zip

# Copy config
COPY config/pentaho-solutions/ /opt/biserver/pentaho-solutions/
COPY config/tomcat/ /opt/biserver/tomcat/

# Download Tomcat libraries
RUN for download in "${CATALINA_HOME}"/lib/*.download; do \
		url=$(cat -- "${download}" | tr -d '\n'); \
		file=$(basename -- "${download}" .download); \
		printf '%s\n' "Downloading \"${file}\"..."; \
		curl -o "${CATALINA_HOME}/lib/${file}" "${url}"; \
		rm -- "${download}"; \
	done

# Copy scripts
COPY scripts/start-pentaho /usr/local/bin/
COPY scripts/setup-postgres /usr/local/bin/
COPY scripts/biserver.init.d/ /etc/biserver.init.d/

VOLUME /opt/biserver/data/hsqldb
VOLUME /opt/biserver/pentaho-solutions/system/jackrabbit/repository
VOLUME /opt/biserver/tomcat/logs

WORKDIR /opt/biserver

EXPOSE 8080/tcp
EXPOSE 8009/tcp

ENTRYPOINT ["/usr/local/bin/start-pentaho"]
