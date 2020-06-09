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
		libtcnative-1 \
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
ARG TINI_VERSION="0.19.0"
ARG TINI_BIN_URL="https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini-amd64"
ARG TINI_BIN_CHECKSUM="93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c"
RUN curl -Lo /usr/bin/tini "${TINI_BIN_URL:?}" \
	&& printf '%s  %s' "${TINI_BIN_CHECKSUM:?}" /usr/bin/tini | sha256sum -c \
	&& chown root:root /usr/bin/tini && chmod 0755 /usr/bin/tini

# Install Supercronic
ARG SUPERCRONIC_VERSION="0.1.9"
ARG SUPERCRONIC_BIN_URL="https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-amd64"
ARG SUPERCRONIC_BIN_CHECKSUM="9f6760d7b5cea5c698ea809598803c6ccca23cf5828fc55e79d1f1c3005d905f"
RUN curl -Lo /usr/bin/supercronic "${SUPERCRONIC_BIN_URL:?}" \
	&& printf '%s  %s' "${SUPERCRONIC_BIN_CHECKSUM:?}" /usr/bin/supercronic | sha256sum -c \
	&& chown root:root /usr/bin/supercronic && chmod 0755 /usr/bin/supercronic

# Install PostgreSQL client
RUN export DEBIAN_FRONTEND=noninteractive \
	&& printf '%s\n' "deb https://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
	&& curl -fsSL 'https://www.postgresql.org/media/keys/ACCC4CF8.asc' | apt-key add - \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends postgresql-client-12 \
	&& rm -rf /var/lib/apt/lists/*

# Install MySQL client
RUN export DEBIAN_FRONTEND=noninteractive \
	&& printf '%s\n' "deb https://repo.mysql.com/apt/ubuntu/ $(lsb_release -cs) mysql-5.7" > /etc/apt/sources.list.d/mysql.list \
	&& curl -fsSL 'https://repo.mysql.com/RPM-GPG-KEY-mysql' | apt-key add - \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends mysql-client \
	&& rm -rf /var/lib/apt/lists/*

# Create unprivileged user
ENV BIUSER_UID="1000"
ENV BIUSER_HOME="/home/biserver"
RUN useradd -u "${BIUSER_UID:?}" -g 0 -s "$(command -v bash)" -md "${BIUSER_HOME:?}" biserver

# Set locale
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
RUN printf '%s\n' "${LANG:?} UTF-8" > /etc/locale.gen \
	&& localedef -c -i "${LANG%%.*}" -f UTF-8 "${LANG:?}" ||:

# Set timezone
ENV TZ=UTC
RUN printf '%s\n' "${TZ:?}" > /etc/timezone \
	&& ln -snf "/usr/share/zoneinfo/${TZ:?}" /etc/localtime

# Set default Java
ENV JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
RUN update-java-alternatives --set java-1.8.0-openjdk-amd64

# Tomcat environment
ENV CATALINA_HOME="/var/lib/biserver/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV CATALINA_OPTS_JAVA_XMS="1024m"
ENV CATALINA_OPTS_JAVA_XMX="4096m"
ENV CATALINA_OPTS_EXTRA=

# Install Tomcat
ARG TOMCAT_VERSION="8.5.55"
ARG TOMCAT_PKG_LIN_URL="https://archive.apache.org/dist/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
ARG TOMCAT_PKG_WIN_URL="https://archive.apache.org/dist/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}-windows-x64.zip"
ARG TOMCAT_PKG_LIN_CHECKSUM="99aa551ac8d9f64383228a830961f642e5799ce58ad1b779935d569bd00b14b6"
ARG TOMCAT_PKG_WIN_CHECKSUM="e3b7d052eb0866b37528f822325a82adbe294f2c6f4c7595b636d3688383b32e"
RUN mkdir /tmp/tomcat/ \
	&& cd /tmp/tomcat/ \
	# Download Tomcat
	&& curl -Lo ./tomcat.tgz "${TOMCAT_PKG_LIN_URL:?}" \
	&& curl -Lo ./tomcat.zip "${TOMCAT_PKG_WIN_URL:?}" \
	&& printf '%s  %s' "${TOMCAT_PKG_LIN_CHECKSUM:?}" ./tomcat.tgz | sha256sum -c \
	&& printf '%s  %s' "${TOMCAT_PKG_WIN_CHECKSUM:?}" ./tomcat.zip | sha256sum -c \
	&& bsdtar -xkf ./tomcat.tgz --strip-components=1 \
	&& bsdtar -xkf ./tomcat.zip --strip-components=1 \
	# Install Tomcat
	&& mkdir -p "${CATALINA_HOME:?}" \
	&& mkdir -p "${CATALINA_BASE:?}"/logs/ \
	&& mkdir -p "${CATALINA_BASE:?}"/temp/ \
	&& mkdir -p "${CATALINA_BASE:?}"/webapps/ \
	&& mkdir -p "${CATALINA_BASE:?}"/work/ \
	&& mv ./bin/ "${CATALINA_HOME:?}" \
	&& mv ./lib/ "${CATALINA_HOME:?}" \
	&& mv ./conf/ "${CATALINA_BASE:?}" \
	# Hide version number
	&& mkdir -p "${CATALINA_HOME:?}"/lib/ \
	&& bsdtar -C "${CATALINA_HOME:?}"/lib/ -xf "${CATALINA_HOME:?}"/lib/catalina.jar org/apache/catalina/util/ServerInfo.properties \
	&& sed -i 's|^\(server\.info\)=.*$|\1=Apache Tomcat|g' "${CATALINA_HOME:?}"/lib/org/apache/catalina/util/ServerInfo.properties \
	# Set permissions
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -not -user biserver -exec chown -h biserver:root '{}' '+' \
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type d -not -perm 0775 -exec chmod 0775 '{}' '+' \
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type f -not -perm 0664 -exec chmod 0664 '{}' '+' \
	&& find "${CATALINA_HOME:?}" "${CATALINA_BASE:?}" -type f -not -perm 0775 -name '*.sh' -exec chmod 0775 '{}' '+' \
	# Cleanup
	&& rm -rf /tmp/tomcat/

# Pentaho BI Server environment
ENV BISERVER_HOME="/var/lib/biserver"
ENV BISERVER_PRIV_INITD="/etc/biserver.priv.init.d"
ENV BISERVER_INITD="/etc/biserver.init.d"
ENV SOLUTIONS_DIRNAME="pentaho-solutions"
ENV DATA_DIRNAME="data"
ENV WEBAPP_PENTAHO_DIRNAME="pentaho"
ENV WEBAPP_PENTAHO_STYLE_DIRNAME="pentaho-style"
ENV KETTLE_HOME="${BIUSER_HOME}"
ENV LOAD_SAMPLES="true"

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
RUN mkdir /tmp/biserver/ \
	&& cd /tmp/biserver/ \
	# Download pentaho-solutions
	&& curl -Lo ./pentaho-solutions.zip "${BISERVER_SOLUTIONS_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_SOLUTIONS_PKG_CHECKSUM:?}" ./pentaho-solutions.zip | sha256sum -c \
	&& mkdir ./pentaho-solutions/ \
	&& bsdtar -C ./pentaho-solutions/ -xf ./pentaho-solutions.zip --strip-components=1 \
	# Download pentaho-data
	&& curl -Lo ./pentaho-data.zip "${BISERVER_DATA_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_DATA_PKG_CHECKSUM:?}" ./pentaho-data.zip | sha256sum -c \
	&& mkdir ./pentaho-data/ \
	&& bsdtar -C ./pentaho-data/ -xf ./pentaho-data.zip --strip-components=1 \
	# Download pentaho-war
	&& curl -Lo ./pentaho-war.war "${BISERVER_WAR_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_WAR_PKG_CHECKSUM:?}" ./pentaho-war.war | sha256sum -c \
	&& mkdir ./pentaho-war/ \
	&& bsdtar -C ./pentaho-war/ -xf ./pentaho-war.war \
	# Download pentaho-style
	&& curl -Lo ./pentaho-style.war "${BISERVER_STYLE_PKG_URL:?}" \
	&& printf '%s  %s' "${BISERVER_STYLE_PKG_CHECKSUM:?}" ./pentaho-style.war | sha256sum -c \
	&& mkdir ./pentaho-style/ \
	&& bsdtar -C ./pentaho-style/ -xf ./pentaho-style.war \
	# Install Pentaho BI Server
	&& mkdir -p "${BISERVER_HOME:?}" \
	&& mv ./pentaho-solutions/ "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" \
	&& mv ./pentaho-data/ "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" \
	&& mv ./pentaho-war/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
	&& mv ./pentaho-style/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
	# Create HSQLDB archive
	&& (cd "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" && zip -r ./hsqldb.zip ./hsqldb/) \
	# Create repository directory
	&& mkdir -p "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/jackrabbit/repository/ \
	# Set permissions
	&& find "${BISERVER_HOME:?}" -not -user biserver -exec chown -h biserver:root '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type d -not -perm 0775 -exec chmod 0775 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -not -perm 0664 -exec chmod 0664 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -not -perm 0775 -name '*.sh' -exec chmod 0775 '{}' '+' \
	# Cleanup
	&& rm -rf /tmp/biserver/

# Install H2 JDBC
ARG H2_JDBC_JAR_URL="https://repo1.maven.org/maven2/com/h2database/h2/1.2.131/h2-1.2.131.jar"
ARG H2_JDBC_JAR_CHECKSUM="c8debc05829db1db2e6b6507a3f0561e1f72bd966d36f322bdf294baca29ed22"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${H2_JDBC_JAR_URL:?}" \
	&& printf '%s  %s' "${H2_JDBC_JAR_CHECKSUM:?}" ./h2-*.jar | sha256sum -c \
	&& chown biserver:root ./h2-*.jar && chmod 0664 ./h2-*.jar

# Install HSQLDB JDBC
ARG HSQLDB_JDBC_JAR_URL="https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.3.2/hsqldb-2.3.2.jar"
ARG HSQLDB_JDBC_JAR_CHECKSUM="e743f27f9e846bf66fec2e26d574dc11f7d1a16530aed8bf687fe1786a7c2ec6"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${HSQLDB_JDBC_JAR_URL:?}" \
	&& printf '%s  %s' "${HSQLDB_JDBC_JAR_CHECKSUM:?}" ./hsqldb-*.jar | sha256sum -c \
	&& chown biserver:root ./hsqldb-*.jar && chmod 0664 ./hsqldb-*.jar

# Install Postgres JDBC
ARG POSTGRES_JDBC_JAR_URL="https://jdbc.postgresql.org/download/postgresql-42.2.12.jar"
ARG POSTGRES_JDBC_JAR_CHECKSUM="80ce2909bcd572795d2129270fc3f0148e3c3dba847ae16ff18c55ef3578ec8b"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${POSTGRES_JDBC_JAR_URL:?}" \
	&& printf '%s  %s' "${POSTGRES_JDBC_JAR_CHECKSUM:?}" ./postgresql-*.jar | sha256sum -c \
	&& chown biserver:root ./postgresql-*.jar && chmod 0664 ./postgresql-*.jar

# Install MySQL JDBC
ARG MYSQL_JDBC_JAR_URL="https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.49/mysql-connector-java-5.1.49.jar"
ARG MYSQL_JDBC_JAR_CHECKSUM="5bba9ff50e5e637a0996a730619dee19ccae274883a4d28c890d945252bb0e12"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${MYSQL_JDBC_JAR_URL:?}" \
	&& printf '%s  %s' "${MYSQL_JDBC_JAR_CHECKSUM:?}" ./mysql-*.jar | sha256sum -c \
	&& chown biserver:root ./mysql-*.jar && chmod 0664 ./mysql-*.jar

# Install MSSQL JDBC
ARG MSSQL_JDBC_JAR_URL="https://github.com/microsoft/mssql-jdbc/releases/download/v8.2.2/mssql-jdbc-8.2.2.jre8.jar"
ARG MSSQL_JDBC_JAR_CHECKSUM="6b1e429ef52cd28bb0bc062a7a74b1fa3ac69f57941c87562ad9c1814bc50447"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${MSSQL_JDBC_JAR_URL:?}" \
	&& printf '%s  %s' "${MSSQL_JDBC_JAR_CHECKSUM:?}" ./mssql-*.jar | sha256sum -c \
	&& chown biserver:root ./mssql-*.jar && chmod 0664 ./mssql-*.jar

# Install Vertica JDBC
ARG VERTICA_JDBC_JAR_URL="https://www.vertica.com/client_drivers/10.0.x/10.0.0-0/vertica-jdbc-10.0.0-0.jar"
ARG VERTICA_JDBC_JAR_CHECKSUM="198cdbd203e038786cc0f61778a122286c8f3bae2cedbce56a453a5505fbca6d"
RUN cd "${CATALINA_BASE:?}"/lib/ && curl -LO "${VERTICA_JDBC_JAR_URL:?}" \
	&& printf '%s  %s' "${VERTICA_JDBC_JAR_CHECKSUM:?}" ./vertica-*.jar | sha256sum -c \
	&& chown biserver:root ./vertica-*.jar && chmod 0664 ./vertica-*.jar

# Other environment variables
ENV SERVICE_BISERVER_ENABLED="true"
ENV SERVICE_SUPERCRONIC_ENABLED="true"
ENV SVDIR="/usr/share/biserver/service/enabled"
ENV SVWAIT="30"

# Copy Pentaho BI Server config
COPY --chown=biserver:root ./config/biserver.priv.init.d/ "${BISERVER_PRIV_INITD}"/
COPY --chown=biserver:root ./config/biserver.init.d/ "${BISERVER_INITD}"/

# Copy crontab
COPY --chown=biserver:root ./config/crontab "${BIUSER_HOME}"/

# Copy scripts
COPY --chown=biserver:root ./scripts/bin/ /usr/share/biserver/bin/

# Copy services
COPY --chown=biserver:root ./scripts/service/ /usr/share/biserver/service/

# Don't declare volumes, let the user decide
#VOLUME "${BISERVER_HOME}"/"${DATA_DIRNAME}/hsqldb/"
#VOLUME "${BISERVER_HOME}"/"${SOLUTIONS_DIRNAME}"/system/jackrabbit/repository/
#VOLUME "${CATALINA_BASE}"/logs/

# Switch to Pentaho BI Server directory
WORKDIR "${BISERVER_HOME}"

# Drop root privileges
USER 1000:0

# Set correct permissions to support arbitrary user ids
RUN /usr/share/biserver/bin/update-permissions.sh

STOPSIGNAL SIGHUP
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/share/biserver/bin/init.sh"]
