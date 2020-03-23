FROM docker.io/ubuntu:18.04

# Install system packages
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
		dnsutils \
		file \
		findutils \
		git \
		gnupg \
		gzip \
		iputils-ping \
		jq \
		lftp \
		libarchive-tools \
		locales \
		lsb-release \
		lzip \
		lzma \
		lzop \
		mime-support \
		nano \
		netcat-openbsd \
		openjdk-8-jdk \
		openssh-client \
		openssl \
		patch \
		rsync \
		ruby \
		runit \
		subversion \
		tar \
		tzdata \
		unzip \
		xxd \
		xz-utils \
		zip \
	&& rm -rf /var/lib/apt/lists/*

# Install Tini
ARG TINI_VERSION="0.18.0"
ARG TINI_BIN_URL="https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini-amd64"
ARG TINI_BIN_CHECKSUM="12d20136605531b09a2c2dac02ccee85e1b874eb322ef6baf7561cd93f93c855"
RUN curl -Lo /usr/bin/tini "${TINI_BIN_URL:?}" \
	&& printf '%s  %s' "${TINI_BIN_CHECKSUM:?}" /usr/bin/tini | sha256sum -c \
	&& chmod 0755 /usr/bin/tini

# Install Supercronic
ARG SUPERCRONIC_VERSION="0.1.9"
ARG SUPERCRONIC_BIN_URL="https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-amd64"
ARG SUPERCRONIC_BIN_CHECKSUM="9f6760d7b5cea5c698ea809598803c6ccca23cf5828fc55e79d1f1c3005d905f"
RUN curl -Lo /usr/bin/supercronic "${SUPERCRONIC_BIN_URL:?}" \
	&& printf '%s  %s' "${SUPERCRONIC_BIN_CHECKSUM:?}" /usr/bin/supercronic | sha256sum -c \
	&& chmod 0755 /usr/bin/supercronic

# Install PostgreSQL client
RUN export DEBIAN_FRONTEND=noninteractive \
	&& printf '%s\n' 'deb https://apt.postgresql.org/pub/repos/apt/ bionic-pgdg main' > /etc/apt/sources.list.d/pgdg.list \
	&& curl -fsSL 'https://www.postgresql.org/media/keys/ACCC4CF8.asc' | apt-key add - \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends postgresql-client-12 \
	&& rm -rf /var/lib/apt/lists/*

# Install MySQL client
RUN export DEBIAN_FRONTEND=noninteractive \
	&& printf '%s\n' 'deb https://repo.mysql.com/apt/ubuntu/ bionic mysql-5.7' > /etc/apt/sources.list.d/mysql.list \
	&& curl -fsSL 'https://repo.mysql.com/RPM-GPG-KEY-mysql' | apt-key add - \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends mysql-client \
	&& rm -rf /var/lib/apt/lists/*

# Create users and groups
ENV BISERVER_USER_UID=1000
ENV BISERVER_USER_GID=1000
RUN printf '%s\n' 'Creating users and groups...' \
	&& groupadd \
		--gid "${BISERVER_USER_GID:?}" \
		biserver \
	&& useradd \
		--uid "${BISERVER_USER_UID:?}" \
		--gid "${BISERVER_USER_GID:?}" \
		--shell "$(command -v bash)" \
		--home-dir /home/biserver/ \
		--create-home \
		biserver

# Setup locale
RUN printf '%s\n' 'en_US.UTF-8 UTF-8' > /etc/locale.gen
RUN localedef -c -i en_US -f UTF-8 en_US.UTF-8 ||:
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# Setup timezone
ENV TZ=UTC
RUN ln -snf "/usr/share/zoneinfo/${TZ:?}" /etc/localtime
RUN printf '%s\n' "${TZ:?}" > /etc/timezone

# Java environment
ENV JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
RUN update-java-alternatives --set java-1.8.0-openjdk-amd64

# Tomcat environment
ENV CATALINA_HOME="/var/lib/biserver/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV CATALINA_PID="${CATALINA_BASE}/bin/catalina.pid"
ENV CATALINA_OPTS_JAVA_XMS="1024m"
ENV CATALINA_OPTS_JAVA_XMX="4096m"
ENV CATALINA_OPTS_EXTRA=

# Install Tomcat
ARG TOMCAT_VERSION="8.5.53"
ARG TOMCAT_PKG_URL="https://archive.apache.org/dist/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
ARG TOMCAT_PKG_CHECKSUM="72e3defbff444548ce9dc60935a1eab822c7d5224f2a8e98c849954575318c08"
RUN printf '%s\n' 'Installing Tomcat...' \
	# Install dependencies
	&& RUN_PKGS="libapr1 libssl1.1" \
	&& BUILD_PKGS="make gcc libapr1-dev libssl-dev" \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends ${RUN_PKGS:?} ${BUILD_PKGS:?} \
	# Download Tomcat
	&& curl -Lo /tmp/tomcat.tar.gz "${TOMCAT_PKG_URL:?}" \
	&& printf '%s  %s' "${TOMCAT_PKG_CHECKSUM:?}" /tmp/tomcat.tar.gz | sha256sum -c \
	&& mkdir /tmp/tomcat/ \
	&& tar -C /tmp/tomcat/ --strip-components=1 -xf /tmp/tomcat.tar.gz \
	# Install Tomcat
	&& mkdir -p "${CATALINA_HOME:?}" \
	&& mkdir -p "${CATALINA_BASE:?}"/logs/ \
	&& mkdir -p "${CATALINA_BASE:?}"/temp/ \
	&& mkdir -p "${CATALINA_BASE:?}"/webapps/ \
	&& mkdir -p "${CATALINA_BASE:?}"/work/ \
	&& mv /tmp/tomcat/bin/ "${CATALINA_HOME:?}" \
	&& mv /tmp/tomcat/lib/ "${CATALINA_HOME:?}" \
	&& mv /tmp/tomcat/conf/ "${CATALINA_BASE:?}" \
	# Build and install Tomcat Native Library
	&& mkdir /tmp/tomcat-native/ \
	&& tar -C /tmp/tomcat-native/ --strip-components=1 -xf "${CATALINA_HOME:?}"/bin/tomcat-native.tar.gz \
	&& (cd /tmp/tomcat-native/native/ && ./configure --prefix="${CATALINA_HOME:?}" && make && make install) \
	# Hide version number
	&& mkdir -p "${CATALINA_HOME:?}"/lib/ \
	&& bsdtar -C "${CATALINA_HOME:?}"/lib/ -xf "${CATALINA_HOME:?}"/lib/catalina.jar org/apache/catalina/util/ServerInfo.properties \
	&& sed -i 's|^\(server\.info\)=.*$|\1=Apache Tomcat|g' "${CATALINA_HOME:?}"/lib/org/apache/catalina/util/ServerInfo.properties \
	# Set permissions
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -not -user biserver -exec chown -h biserver:biserver '{}' '+' \
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type d -not -perm 0755 -exec chmod 0755 '{}' '+' \
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type f -not -perm 0644 -exec chmod 0644 '{}' '+' \
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type f -not -perm 0755 -name '*.sh' -exec chmod 0755 '{}' '+' \
	# Cleanup
	&& apt-get purge -y ${BUILD_PKGS:?} \
	&& apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/* \
	&& find /tmp/ -mindepth 1 -delete

# Pentaho BI Server environment
ENV BISERVER_HOME="/var/lib/biserver"
ENV BISERVER_INITD="/etc/biserver.init.d"
ENV SOLUTIONS_DIRNAME="pentaho-solutions"
ENV DATA_DIRNAME="data"
ENV WEBAPP_PENTAHO_DIRNAME="pentaho"
ENV WEBAPP_PENTAHO_STYLE_DIRNAME="pentaho-style"

# Install Pentaho BI Server
ARG BISERVER_VERSION="9.0.0.0-423"
ARG BISERVER_BASE_URL="https://repo.stratebi.com/repository/pentaho-mvn/"
#ARG BISERVER_BASE_URL="https://nexus.pentaho.org/content/groups/omni/"
ARG BISERVER_SOLUTIONS_PKG_URL="${BISERVER_BASE_URL}/pentaho/pentaho-solutions/${BISERVER_VERSION}/pentaho-solutions-${BISERVER_VERSION}.zip"
ARG BISERVER_SOLUTIONS_PKG_CHECKSUM="58c637f3bd373a7504f8589653d43f16e00a0e2257739ff9d20a3db7468198fc"
ARG BISERVER_DATA_PKG_URL="${BISERVER_BASE_URL}/pentaho/pentaho-data/${BISERVER_VERSION}/pentaho-data-${BISERVER_VERSION}.zip"
ARG BISERVER_DATA_PKG_CHECKSUM="6907a2776b3e39bc543b4061a52b68c02b059ebda4b3caecb7cdcb88e0ba16ab"
ARG BISERVER_WAR_PKG_URL="${BISERVER_BASE_URL}/pentaho/pentaho-war/${BISERVER_VERSION}/pentaho-war-${BISERVER_VERSION}.war"
ARG BISERVER_WAR_PKG_CHECKSUM="e47c28331d77511fa5f53dab07efeaef692ea74df2f834dd53e2af9aa224f920"
ARG BISERVER_STYLE_PKG_URL="${BISERVER_BASE_URL}/pentaho/pentaho-style/${BISERVER_VERSION}/pentaho-style-${BISERVER_VERSION}.war"
ARG BISERVER_STYLE_PKG_CHECKSUM="c194d6ba60934f8543106bb2ef0df904f4fa357fc7dc610e9b264c6e76d4c4bb"
RUN printf '%s\n' 'Installing Pentaho BI Server...' \
	# Download Pentaho BI Server
	&& mkdir /tmp/biserver/ \
	### ./pentaho-solutions/
	&& curl -Lo /tmp/pentaho-solutions.zip "${BISERVER_SOLUTIONS_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_SOLUTIONS_PKG_CHECKSUM:?}" /tmp/pentaho-solutions.zip | sha256sum -c \
	&& bsdtar -C /tmp/biserver/ -xf /tmp/pentaho-solutions.zip \
	### ./data/
	&& curl -Lo /tmp/pentaho-data.zip "${BISERVER_DATA_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_DATA_PKG_CHECKSUM:?}" /tmp/pentaho-data.zip | sha256sum -c \
	&& bsdtar -C /tmp/biserver/ -xf /tmp/pentaho-data.zip \
	### ./tomcat/webapps/pentaho/
	&& curl -Lo /tmp/pentaho-war.war "${BISERVER_WAR_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_WAR_PKG_CHECKSUM:?}" /tmp/pentaho-war.war | sha256sum -c \
	&& mkdir /tmp/biserver/pentaho-war/ \
	&& bsdtar -C /tmp/biserver/pentaho-war/ -xf /tmp/pentaho-war.war \
	### ./tomcat/webapps/pentaho-style/
	&& curl -Lo /tmp/pentaho-style.war "${BISERVER_STYLE_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_STYLE_PKG_CHECKSUM:?}" /tmp/pentaho-style.war | sha256sum -c \
	&& mkdir /tmp/biserver/pentaho-style/ \
	&& bsdtar -C /tmp/biserver/pentaho-style/ -xf /tmp/pentaho-style.war \
	# Install Pentaho BI Server
	&& mkdir -p "${BISERVER_HOME:?}" \
	&& mv /tmp/biserver/pentaho-solutions/ "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" \
	&& mv /tmp/biserver/data/ "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" \
	&& mv /tmp/biserver/pentaho-war/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
	&& mv /tmp/biserver/pentaho-style/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
	# Set permissions
	&& find "${BISERVER_HOME:?}" -not -user biserver -exec chown -h biserver:biserver '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type d -not -perm 0755 -exec chmod 0755 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -not -perm 0644 -exec chmod 0644 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -not -perm 0755 -name '*.sh' -exec chmod 0755 '{}' '+' \
	# Cleanup
	&& find /tmp/ -mindepth 1 -delete

# Install H2 JDBC
ARG H2_JDBC_JAR_URL="https://repo1.maven.org/maven2/com/h2database/h2/1.2.131/h2-1.2.131.jar"
ARG H2_JDBC_JAR_CHECKSUM="c8debc05829db1db2e6b6507a3f0561e1f72bd966d36f322bdf294baca29ed22"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${H2_JDBC_JAR_URL:?}" && printf '%s  %s' "${H2_JDBC_JAR_CHECKSUM:?}" ./h2-*.jar | sha256sum -c

# Install HSQLDB JDBC
ARG HSQLDB_JDBC_JAR_URL="https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.3.2/hsqldb-2.3.2.jar"
ARG HSQLDB_JDBC_JAR_CHECKSUM="e743f27f9e846bf66fec2e26d574dc11f7d1a16530aed8bf687fe1786a7c2ec6"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${HSQLDB_JDBC_JAR_URL:?}" && printf '%s  %s' "${HSQLDB_JDBC_JAR_CHECKSUM:?}" ./hsqldb-*.jar | sha256sum -c

# Install Postgres JDBC
ARG POSTGRES_JDBC_JAR_URL="https://jdbc.postgresql.org/download/postgresql-42.2.11.jar"
ARG POSTGRES_JDBC_JAR_CHECKSUM="31e9f3dc586c07477235893279ee80036de377681badaa1f27db6b74ab2437f4"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${POSTGRES_JDBC_JAR_URL:?}" && printf '%s  %s' "${POSTGRES_JDBC_JAR_CHECKSUM:?}" ./postgresql-*.jar | sha256sum -c

# Install MySQL JDBC
ARG MYSQL_JDBC_JAR_URL="https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.48/mysql-connector-java-5.1.48.jar"
ARG MYSQL_JDBC_JAR_CHECKSUM="56e26caaa3821f5ae4af44f9c74f66cf8b84ea01516ad3803cbb0e9049b6eca8"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${MYSQL_JDBC_JAR_URL:?}" && printf '%s  %s' "${MYSQL_JDBC_JAR_CHECKSUM:?}" ./mysql-*.jar | sha256sum -c

# Install MSSQL JDBC
ARG MSSQL_JDBC_JAR_URL="https://github.com/microsoft/mssql-jdbc/releases/download/v8.2.1/mssql-jdbc-8.2.1.jre8.jar"
ARG MSSQL_JDBC_JAR_CHECKSUM="3dbe11015570a28569da590ab376c82f0e0bc0df9fd78a0e2aea8fbf2a77fb74"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${MSSQL_JDBC_JAR_URL:?}" && printf '%s  %s' "${MSSQL_JDBC_JAR_CHECKSUM:?}" ./mssql-*.jar | sha256sum -c

# Install Vertica JDCB
ARG VERTICA_JDBC_JAR_URL="https://www.vertica.com/client_drivers/9.3.x/9.3.1-0/vertica-jdbc-9.3.1-0.jar"
ARG VERTICA_JDBC_JAR_CHECKSUM="8dcbeb09dba23d8241d7e95707c1069ee52a3c8fd7a8c4e71751ebc6bb8f6d1c"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${VERTICA_JDBC_JAR_URL:?}" && printf '%s  %s' "${VERTICA_JDBC_JAR_CHECKSUM:?}" ./vertica-*.jar | sha256sum -c

# Other environment variables
ENV SERVICE_BISERVER_ENABLED=true
ENV SERVICE_SUPERCRONIC_ENABLED=true

# Copy Tomcat config
COPY --chown=biserver:biserver ./config/biserver/tomcat/conf/ "${CATALINA_BASE}"/conf/
COPY --chown=biserver:biserver ./config/biserver/tomcat/webapps/pentaho/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_DIRNAME}"/
COPY --chown=biserver:biserver ./config/biserver/tomcat/webapps/pentaho-style/ "${CATALINA_BASE}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME}"/
COPY --chown=biserver:biserver ./config/biserver/tomcat/webapps/ROOT/ "${CATALINA_BASE}"/webapps/ROOT/

# Copy Pentaho BI Server config
COPY --chown=biserver:biserver ./config/biserver/*.* "${BISERVER_HOME}"/
COPY --chown=biserver:biserver ./config/biserver/data/ "${BISERVER_HOME}"/"${DATA_DIRNAME}"/
COPY --chown=biserver:biserver ./config/biserver/pentaho-solutions/ "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/
COPY --chown=root:root ./config/biserver.init.d/ "${BISERVER_INITD}"/

# Copy crontab
COPY --chown=biserver:biserver ./config/crontab /home/biserver/.crontab

# Copy scripts
COPY --chown=root:root ./scripts/bin/ /usr/share/biserver/bin/

# Copy services
COPY --chown=biserver:biserver ./scripts/service/ /usr/share/biserver/service/

# Set sane permissions until solved upstream:
# https://gitlab.com/gitlab-org/gitlab-runner/issues/1736
RUN find "${BISERVER_HOME:?}" -type d -not -perm 0755 -exec chmod 0755 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -not -perm 0644 -exec chmod 0644 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -regex '.*\.sh\(\.erb\)?$' -exec chmod 0755 '{}' '+' \
	&& chmod 0755 -R /usr/share/biserver/bin/ /usr/share/biserver/service/ \
	&& chmod 0644 /home/biserver/.crontab

# Don't declare volumes, let the user decide
#VOLUME "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository/
#VOLUME "${BISERVER_HOME}"/"${DATA_DIRNAME}/hsqldb/"
#VOLUME "${CATALINA_BASE}"/logs/

# Switch to Pentaho BI Server directory
WORKDIR "${BISERVER_HOME}"

# Drop root privileges
USER biserver:biserver

# Start all services
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/share/biserver/bin/init.sh"]
