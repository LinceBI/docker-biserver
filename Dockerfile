FROM docker.io/ubuntu:20.04

# Install system packages
RUN export DEBIAN_FRONTEND=noninteractive \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
		apt-transport-https \
		bash \
		bzip2 \
		ca-certificates \
		curl \
		diffutils \
		file \
		findutils \
		fontconfig \
		fonts-dejavu-core \
		fonts-liberation2 \
		fonts-noto-core \
		git \
		gnupg \
		gzip \
		jq \
		lftp \
		libarchive-tools \
		libtcnative-1 \
		locales \
		lsb-release \
		lzma \
		mime-support \
		nano \
		netcat-openbsd \
		openssh-client \
		openssl \
		patch \
		pwgen \
		rsync \
		ruby \
		runit \
		subversion \
		tar \
		tini \
		tzdata \
		unzip \
		uuid-runtime \
		xxd \
		xz-utils \
		zip \
	&& rm -rf /var/lib/apt/lists/*

# Install Zulu OpenJDK
RUN export DEBIAN_FRONTEND=noninteractive && ARCH="$(dpkg --print-architecture)" \
	&& apt-key adv --keyserver 'hkp://keyserver.ubuntu.com:80' --recv-keys 'B1998361219BD9C9' \
	&& printf '%s\n' "deb [arch=${ARCH:?}] https://repos.azul.com/zulu/deb/ stable main" > /etc/apt/sources.list.d/zulu-openjdk.list \
	&& apt-get update && apt-get install -y --no-install-recommends zulu8-jdk \
	&& rm -rf /var/lib/apt/lists/*

# Install PostgreSQL client
RUN export DEBIAN_FRONTEND=noninteractive && ARCH="$(dpkg --print-architecture)" && DISTRO="$(lsb_release -cs)" \
	&& apt-key adv --keyserver 'hkp://keyserver.ubuntu.com:80' --recv-keys '7FCC7D46ACCC4CF8' \
	&& printf '%s\n' "deb [arch=${ARCH:?}] https://apt.postgresql.org/pub/repos/apt/ ${DISTRO:?}-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
	&& apt-get update && apt-get install -y --no-install-recommends postgresql-client-13 \
	&& rm -rf /var/lib/apt/lists/*

# Install MySQL client
RUN export DEBIAN_FRONTEND=noninteractive && ARCH="$(dpkg --print-architecture)" && DISTRO="$(lsb_release -cs)" \
	&& apt-key adv --keyserver 'hkp://keyserver.ubuntu.com:80' --recv-keys '8C718D3B5072E1F5' \
	&& printf '%s\n' "deb [arch=${ARCH:?}] https://repo.mysql.com/apt/ubuntu/ ${DISTRO:?} mysql-8.0" > /etc/apt/sources.list.d/mysql.list \
	&& apt-get update && apt-get install -y --no-install-recommends mysql-client \
	&& rm -rf /var/lib/apt/lists/*

# Install Supercronic
ARG SUPERCRONIC_VERSION="0.1.12"
ARG SUPERCRONIC_URL="https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-amd64"
ARG SUPERCRONIC_CHECKSUM="8d3a575654a6c93524c410ae06f681a3507ca5913627fa92c7086fd140fa12ce"
RUN curl -Lo /usr/bin/supercronic "${SUPERCRONIC_URL:?}" \
	&& printf '%s  %s' "${SUPERCRONIC_CHECKSUM:?}" /usr/bin/supercronic | sha256sum -c \
	&& chown root:root /usr/bin/supercronic && chmod 0755 /usr/bin/supercronic

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
ENV JAVA_HOME="/usr/lib/jvm/zulu8-ca-amd64"
ENV JAVA_XMS="1024m" JAVA_XMX="4096m"
RUN update-java-alternatives --set zulu8-ca-amd64

# Tomcat environment
ENV CATALINA_HOME="/var/lib/biserver/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV CATALINA_OPTS_EXTRA=""

# Install Tomcat
ARG TOMCAT_VERSION="8.5.69"
ARG TOMCAT_LIN_URL="https://archive.apache.org/dist/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
ARG TOMCAT_LIN_CHECKSUM="cc9616eb29bf491839ce5c8a1c3e37cb710f6ec99aad5aefb7944b5184b13398"
ARG TOMCAT_WIN_URL="https://archive.apache.org/dist/tomcat/tomcat-8/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}-windows-x64.zip"
ARG TOMCAT_WIN_CHECKSUM="c2aaab8f39dc17234ecf8703fc63bd1ea1ffb3092f67c9bbe3342abb9caf053e"
RUN mkdir /tmp/tomcat/ \
	&& cd /tmp/tomcat/ \
	# Download Tomcat
	&& curl -Lo ./tomcat.tgz "${TOMCAT_LIN_URL:?}" \
	&& printf '%s  %s' "${TOMCAT_LIN_CHECKSUM:?}" ./tomcat.tgz | sha256sum -c \
	&& bsdtar -xkf ./tomcat.tgz --strip-components=1 \
	&& curl -Lo ./tomcat.zip "${TOMCAT_WIN_URL:?}" \
	&& printf '%s  %s' "${TOMCAT_WIN_CHECKSUM:?}" ./tomcat.zip | sha256sum -c \
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
ARG BISERVER_VERSION="9.1.0.0-324"
ARG BISERVER_BASE_URL="https://repo.stratebi.com/repository/pentaho-mvn/"
ARG BISERVER_SOLUTIONS_URL="${BISERVER_BASE_URL}/pentaho/pentaho-solutions/${BISERVER_VERSION}/pentaho-solutions-${BISERVER_VERSION}.zip"
ARG BISERVER_SOLUTIONS_CHECKSUM="683f405211a313a446bf2c9ecb3dbced2c6a04ead431da59de4988472bdf2ae2"
ARG BISERVER_DATA_URL="${BISERVER_BASE_URL}/pentaho/pentaho-data/${BISERVER_VERSION}/pentaho-data-${BISERVER_VERSION}.zip"
ARG BISERVER_DATA_CHECKSUM="babc4e9c6ffbab9b7886c5c0052cf0f13556c6e06b28363b0a787a399f92f33d"
ARG BISERVER_WAR_URL="${BISERVER_BASE_URL}/pentaho/pentaho-war/${BISERVER_VERSION}/pentaho-war-${BISERVER_VERSION}.war"
ARG BISERVER_WAR_CHECKSUM="952b18b2b9e9d75bdd0aade975319ba9b769cbf13d3e59f180d9fba7f57609d8"
ARG BISERVER_STYLE_URL="${BISERVER_BASE_URL}/pentaho/pentaho-style/${BISERVER_VERSION}/pentaho-style-${BISERVER_VERSION}.war"
ARG BISERVER_STYLE_CHECKSUM="89c75ca0f84a21b1da148870f823c4d98d8c6033bdabaadd15fe3a7707417453"
RUN mkdir /tmp/biserver/ \
	&& cd /tmp/biserver/ \
	# Download pentaho-solutions
	&& curl -Lo ./pentaho-solutions.zip "${BISERVER_SOLUTIONS_URL:?}" \
	&& printf '%s  %s' "${BISERVER_SOLUTIONS_CHECKSUM:?}" ./pentaho-solutions.zip | sha256sum -c \
	&& mkdir ./pentaho-solutions/ \
	&& bsdtar -C ./pentaho-solutions/ -xf ./pentaho-solutions.zip --strip-components=1 \
	# Download pentaho-data
	&& curl -Lo ./pentaho-data.zip "${BISERVER_DATA_URL:?}" \
	&& printf '%s  %s' "${BISERVER_DATA_CHECKSUM:?}" ./pentaho-data.zip | sha256sum -c \
	&& mkdir ./pentaho-data/ \
	&& bsdtar -C ./pentaho-data/ -xf ./pentaho-data.zip --strip-components=1 \
	# Download pentaho-war
	&& curl -Lo ./pentaho-war.war "${BISERVER_WAR_URL:?}" \
	&& printf '%s  %s' "${BISERVER_WAR_CHECKSUM:?}" ./pentaho-war.war | sha256sum -c \
	&& mkdir ./pentaho-war/ \
	&& bsdtar -C ./pentaho-war/ -xf ./pentaho-war.war \
	# Download pentaho-style
	&& curl -Lo ./pentaho-style.war "${BISERVER_STYLE_URL:?}" \
	&& printf '%s  %s' "${BISERVER_STYLE_CHECKSUM:?}" ./pentaho-style.war | sha256sum -c \
	&& mkdir ./pentaho-style/ \
	&& bsdtar -C ./pentaho-style/ -xf ./pentaho-style.war \
	# Install Pentaho BI Server
	&& mkdir -p "${BISERVER_HOME:?}" \
	&& mv ./pentaho-solutions/ "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}" \
	&& mv ./pentaho-data/ "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" \
	&& mv ./pentaho-war/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}" \
	&& mv ./pentaho-style/ "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_STYLE_DIRNAME:?}" \
	# Ensure that JPivot is removed (it's not maintained anymore and in 8.3+ it doesn't work anyway)
	&& rm -rf "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/pentaho-jpivot-plugin/ \
	# Create HSQLDB archive
	&& (cd "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}" && zip -r ./hsqldb.zip ./hsqldb/) \
	# Create repository directory
	&& mkdir -p "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/jackrabbit/repository/ \
	# Create init.d directories
	&& mkdir -p "${BISERVER_PRIV_INITD:?}" "${BISERVER_INITD:?}" \
	# Set permissions
	&& find "${BISERVER_HOME:?}" -not -user biserver -exec chown -h biserver:root '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type d -not -perm 0775 -exec chmod 0775 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -not -perm 0664 -exec chmod 0664 '{}' '+' \
	&& find "${BISERVER_HOME:?}" -type f -not -perm 0775 -name '*.sh' -exec chmod 0775 '{}' '+' \
	&& chmod 775 "${BISERVER_PRIV_INITD:?}" "${BISERVER_INITD:?}" \
	# Cleanup
	&& rm -rf /tmp/biserver/

# Install H2 JDBC
ARG H2_JDBC_URL="https://repo1.maven.org/maven2/com/h2database/h2/1.2.131/h2-1.2.131.jar"
ARG H2_JDBC_CHECKSUM="c8debc05829db1db2e6b6507a3f0561e1f72bd966d36f322bdf294baca29ed22"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${H2_JDBC_URL:?}" \
	&& printf '%s  %s' "${H2_JDBC_CHECKSUM:?}" ./h2-*.jar | sha256sum -c \
	&& chown biserver:root ./h2-*.jar && chmod 0664 ./h2-*.jar

# Install HSQLDB JDBC
ARG HSQLDB_JDBC_URL="https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.3.2/hsqldb-2.3.2.jar"
ARG HSQLDB_JDBC_CHECKSUM="e743f27f9e846bf66fec2e26d574dc11f7d1a16530aed8bf687fe1786a7c2ec6"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${HSQLDB_JDBC_URL:?}" \
	&& printf '%s  %s' "${HSQLDB_JDBC_CHECKSUM:?}" ./hsqldb-*.jar | sha256sum -c \
	&& chown biserver:root ./hsqldb-*.jar && chmod 0664 ./hsqldb-*.jar

# Install Postgres JDBC
ARG POSTGRES_JDBC_URL="https://repo1.maven.org/maven2/org/postgresql/postgresql/42.2.23/postgresql-42.2.23.jar"
ARG POSTGRES_JDBC_CHECKSUM="7a16267953ae981734febd0200cd86261ebb950a6a6a819467b8816b9bfcf6c7"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${POSTGRES_JDBC_URL:?}" \
	&& printf '%s  %s' "${POSTGRES_JDBC_CHECKSUM:?}" ./postgresql-*.jar | sha256sum -c \
	&& chown biserver:root ./postgresql-*.jar && chmod 0664 ./postgresql-*.jar

# Install MySQL JDBC
ARG MYSQL_JDBC_URL="https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.49/mysql-connector-java-5.1.49.jar"
ARG MYSQL_JDBC_CHECKSUM="5bba9ff50e5e637a0996a730619dee19ccae274883a4d28c890d945252bb0e12"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${MYSQL_JDBC_URL:?}" \
	&& printf '%s  %s' "${MYSQL_JDBC_CHECKSUM:?}" ./mysql-*.jar | sha256sum -c \
	&& chown biserver:root ./mysql-*.jar && chmod 0664 ./mysql-*.jar

# Install MSSQL JDBC
ARG MSSQL_JDBC_URL="https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/9.2.1.jre8/mssql-jdbc-9.2.1.jre8.jar"
ARG MSSQL_JDBC_CHECKSUM="14c178b55c227131b26c120ee7256b4bc5ed2dd497f66d85afdec3793a6e1817"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${MSSQL_JDBC_URL:?}" \
	&& printf '%s  %s' "${MSSQL_JDBC_CHECKSUM:?}" ./mssql-*.jar | sha256sum -c \
	&& chown biserver:root ./mssql-*.jar && chmod 0664 ./mssql-*.jar

# Install Vertica JDBC
ARG VERTICA_JDBC_URL="https://repo1.maven.org/maven2/com/vertica/jdbc/vertica-jdbc/10.1.1-0/vertica-jdbc-10.1.1-0.jar"
ARG VERTICA_JDBC_CHECKSUM="f3ecad3afccb67c26b75655db06f72d2cf380a74ee35ded4b041287d5e72fbaf"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${VERTICA_JDBC_URL:?}" \
	&& printf '%s  %s' "${VERTICA_JDBC_CHECKSUM:?}" ./vertica-*.jar | sha256sum -c \
	&& chown biserver:root ./vertica-*.jar && chmod 0664 ./vertica-*.jar

# Install CAS libraries
ARG CAS_CLIENT_CORE_URL="https://repo1.maven.org/maven2/org/jasig/cas/client/cas-client-core/3.6.2/cas-client-core-3.6.2.jar"
ARG CAS_CLIENT_CORE_CHECKSUM="4ac36bdfd2c80595ee08f1b84540368a7839acdecf3f8a8080879f8a3082bce5"
ARG SPRING_SECURITY_CAS_URL="https://repo1.maven.org/maven2/org/springframework/security/spring-security-cas/4.2.20.RELEASE/spring-security-cas-4.2.20.RELEASE.jar"
ARG SPRING_SECURITY_CAS_CHECKSUM="e19b4304a697960567eb30c6fb1b63ee4ce99cc80bbc0783bcdca8a8e8bf0866"
RUN cd "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF/lib/ \
	&& curl -LO "${CAS_CLIENT_CORE_URL:?}" \
	&& printf '%s  %s' "${CAS_CLIENT_CORE_CHECKSUM:?}" ./cas-client-core-*.jar | sha256sum -c \
	&& chown biserver:root ./cas-client-core-*.jar && chmod 0664 ./cas-client-core-*.jar \
	&& curl -LO "${SPRING_SECURITY_CAS_URL:?}" \
	&& printf '%s  %s' "${SPRING_SECURITY_CAS_CHECKSUM:?}" ./spring-security-cas-*.jar | sha256sum -c \
	&& chown biserver:root ./spring-security-cas-*.jar && chmod 0664 ./spring-security-cas-*.jar

# Clean up temp directory
RUN find /tmp/ -mindepth 1 -delete

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

# Switch to Pentaho BI Server directory
WORKDIR "${BISERVER_HOME}"

# Drop root privileges
USER 1000:0

# Set correct permissions to support arbitrary user ids
RUN /usr/share/biserver/bin/update-permissions.sh

STOPSIGNAL SIGHUP
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/share/biserver/bin/init.sh"]
