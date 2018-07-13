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

# Java environment
RUN ln -rs "$(dirname $(dirname $(readlink -f $(which javac))))" /usr/lib/jvm/java
ENV JAVA_HOME="/usr/lib/jvm/java"
ENV JDK_HOME="${JAVA_HOME}"
ENV JRE_HOME="${JAVA_HOME}/jre"

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

ENV TOMCAT_GID=5000
ENV TOMCAT_UID=5000
RUN printf '%s\n' 'Creating users and groups...' \
	# Create users and groups
	&& groupadd --gid "${TOMCAT_GID}" tomcat \
	&& useradd \
		--uid "${TOMCAT_UID}" \
		--gid "${TOMCAT_GID}" \
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
	&& (cd /tmp/tomcat-native/ \
		&& tar --strip-components=1 -xvf "${CATALINA_HOME}"/bin/tomcat-native.tar.gz \
		&& cd ./native/ && ./configure --prefix="${CATALINA_HOME}" \
		&& make && make install \
	) \
	# Hide version number
	&& (cd "${CATALINA_HOME}"/lib/ \
		&& jar -xf catalina.jar org/apache/catalina/util/ServerInfo.properties \
		&& sed -i 's|^\(server\.info\)=.*$|\1=Apache Tomcat|g' \
			./org/apache/catalina/util/ServerInfo.properties \
	) \
	# Set permissions
	&& chown -R root:tomcat "${CATALINA_HOME}" "${CATALINA_BASE}" \
	&& find "${CATALINA_HOME}" "${CATALINA_BASE}" -type f -exec chmod 644 '{}' \; \
	&& find "${CATALINA_HOME}" "${CATALINA_BASE}" -type d -exec chmod 755 '{}' \; \
	&& chmod 775 \
		"${CATALINA_BASE}"/logs/ \
		"${CATALINA_BASE}"/temp/ \
		"${CATALINA_BASE}"/work/ \
	# Cleanup
	&& apt-get purge -y ${BUILD_PKGS} \
	&& apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/* \
	&& find /tmp/ -mindepth 1 -delete

# Copy Tomcat libraries and placeholders
COPY --chown=root:tomcat config/biserver/tomcat/lib/ "${CATALINA_BASE}"/lib/

# Download Tomcat libraries
RUN printf '%s\n' 'Downloading Tomcat libraries...' \
	&& for placeholder in "${CATALINA_BASE}"/lib/*.download; do \
		url=$(cat "${placeholder}" | tr -d '\n'); \
		file=$(basename "${placeholder}" .download); \
		printf '%s\n' "Downloading \"${file}\"..."; \
		curl -o "${CATALINA_BASE}"/lib/"${file}" "${url}"; \
		chown root:tomcat "${CATALINA_BASE}"/lib/"${file}"; \
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
	&& chown -R tomcat:tomcat \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
	&& find \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
		-type f -exec chmod 644 '{}' \; \
	&& find \
		"${BISERVER_SOLUTION_PATH}" "${BISERVER_DATA_PATH}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}" \
		"${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}" \
		-type d -exec chmod 755 '{}' \; \
	# Cleanup
	&& find /tmp/ -mindepth 1 -delete

# Copy Tomcat config
COPY --chown=root:tomcat config/biserver/tomcat/conf/ "${CATALINA_BASE}"/conf/
COPY --chown=tomcat:tomcat config/biserver/tomcat/webapps/ROOT/ "${CATALINA_BASE}"/webapps/ROOT/
COPY --chown=tomcat:tomcat config/biserver/tomcat/webapps/pentaho/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_NAME}"/
COPY --chown=tomcat:tomcat config/biserver/tomcat/webapps/pentaho-style/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_NAME}"/

# Copy Pentaho BI Server config
COPY --chown=tomcat:tomcat config/biserver/pentaho-solutions/ "${BISERVER_SOLUTION_PATH}"/
COPY --chown=tomcat:tomcat config/biserver/data/ "${BISERVER_DATA_PATH}"/
COPY --chown=root:root config/biserver.init.d/ "${BISERVER_INITD}"/

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

USER tomcat:tomcat

CMD ["/usr/local/bin/start-biserver"]
