FROM docker.io/ubuntu:22.04

# Install system packages
RUN export DEBIAN_FRONTEND=noninteractive \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
		bash \
		bzip2 \
		ca-certificates \
		catatonit \
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
		mysql-client-8.0 \
		nano \
		netcat-openbsd \
		openssh-client \
		openssl \
		p11-kit \
		patch \
		postgresql-client-14 \
		pwgen \
		python-is-python3 \
		python3 \
		python3-pip \
		rsync \
		ruby \
		runit \
		subversion \
		tar \
		tzdata \
		unzip \
		uuid-runtime \
		xxd \
		xz-utils \
		zip \
	&& rm -rf /var/lib/apt/lists/*

# Install Zulu OpenJDK
RUN export DEBIAN_FRONTEND=noninteractive && ARCH="$(dpkg --print-architecture)" \
	&& curl --proto '=https' --tlsv1.3 -sSf 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB1998361219BD9C9' | gpg --dearmor -o /etc/apt/trusted.gpg.d/zulu-openjdk.gpg \
	&& printf '%s\n' "deb [signed-by=/etc/apt/trusted.gpg.d/zulu-openjdk.gpg, arch=${ARCH:?}] https://repos.azul.com/zulu/deb/ stable main" > /etc/apt/sources.list.d/zulu-openjdk.list \
	&& apt-get update && apt-get install -y --no-install-recommends zulu11-jdk \
	&& update-java-alternatives --set "$(basename /usr/lib/jvm/zulu11-ca-*)" \
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

# Java environment
ENV JAVA_HOME="/usr/lib/jvm/zulu11"
ENV JAVA_XMS="1024m" JAVA_XMX="4096m"
ENV JAVA_TRUSTSTORE_FILE="${BIUSER_HOME}/.java/cacerts"

# Tomcat environment
ENV CATALINA_HOME="/var/lib/biserver/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV TOMCAT_SHUTDOWN_PORT="8005"
ENV TOMCAT_AJP_PORT="8009"
ENV TOMCAT_HTTP_PORT="8080"

# Install Tomcat
ARG TOMCAT_VERSION="9.0.87"
ARG TOMCAT_LIN_URL="https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
ARG TOMCAT_LIN_CHECKSUM="da482fb9220086dbf371e180aa09c6402af8f048586734cdedd4a08c48d4ce02"
ARG TOMCAT_WIN_URL="https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}-windows-x64.zip"
ARG TOMCAT_WIN_CHECKSUM="851224c8d61ba0d0adfb9142df76c5f0c2b988b3543f3db60e925642475d042e"
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

# Install Pentaho BI Server
ARG BISERVER_VERSION="9.3.0.6-764"
ARG BISERVER_BASE_URL="https://repo.stratebi.com/repository/pentaho-mvn/"
ARG BISERVER_SOLUTIONS_URL="${BISERVER_BASE_URL}/pentaho/pentaho-solutions/${BISERVER_VERSION}/pentaho-solutions-${BISERVER_VERSION}.zip"
ARG BISERVER_SOLUTIONS_CHECKSUM="fcae4e298e610c3e71c98fba748c62ccc55be2df614a3b9bb25642a50ffa5fb9"
ARG BISERVER_DATA_URL="${BISERVER_BASE_URL}/pentaho/pentaho-data/${BISERVER_VERSION}/pentaho-data-${BISERVER_VERSION}.zip"
ARG BISERVER_DATA_CHECKSUM="fd9abb35e218016555d89e4dfaf79b080edd486ccec01e2ee77b6473ff1619f2"
ARG BISERVER_WAR_URL="${BISERVER_BASE_URL}/pentaho/pentaho-war/${BISERVER_VERSION}/pentaho-war-${BISERVER_VERSION}.war"
ARG BISERVER_WAR_CHECKSUM="8fd93a740a8b5ff9570b0b1133c0da28bce788a52064dc3018bc0f73090bc574"
ARG BISERVER_STYLE_URL="${BISERVER_BASE_URL}/pentaho/pentaho-style/${BISERVER_VERSION}/pentaho-style-${BISERVER_VERSION}.war"
ARG BISERVER_STYLE_CHECKSUM="0751778f5f0f24c79529f7c565187a8f45895748c417198039c931a6c31b3932"
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
	# Remove default SQL scripts
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/hsqldb/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/mysql/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/oracle10g/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/oracle12c/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/postgresql/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/sqlserver/ \
	# Remove libraries from data directory
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/lib/ \
	# Remove Hadoop libraries from Kettle
	&& rm -rf "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/plugins/pentaho-big-data-plugin/hadoop-configurations/* \
	&& rm -rf "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/plugins/pentaho-big-data-plugin/pentaho-mapreduce-libraries.zip \
	# Remove JPivot, it's not maintained anymore
	&& rm -rf "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/pentaho-jpivot-plugin/ \
	# Create repository directory
	&& mkdir -p "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/jackrabbit/repository/ \
	# Create HSQLDB directory
	&& mkdir -p "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/hsqldb/ \
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
ARG H2_JDBC_URL="https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar"
ARG H2_JDBC_CHECKSUM="b9d8f19358ada82a4f6eb5b174c6cfe320a375b5a9cb5a4fe456d623e6e55497"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& rm -f ./h2-*.jar \
	&& curl -LO "${H2_JDBC_URL:?}" \
	&& printf '%s  %s' "${H2_JDBC_CHECKSUM:?}" ./h2-*.jar | sha256sum -c \
	&& chown biserver:root ./h2-*.jar && chmod 0664 ./h2-*.jar

# Install HSQLDB JDBC
ARG HSQLDB_JDBC_URL="https://repo1.maven.org/maven2/org/hsqldb/hsqldb/2.7.2/hsqldb-2.7.2.jar"
ARG HSQLDB_JDBC_CHECKSUM="aa455133e664f6a7e6f30cd0cd4f8ad83dfbd94eb717c438548e446784614a92"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& rm -f ./hsqldb-*.jar \
	&& curl -LO "${HSQLDB_JDBC_URL:?}" \
	&& printf '%s  %s' "${HSQLDB_JDBC_CHECKSUM:?}" ./hsqldb-*.jar | sha256sum -c \
	&& chown biserver:root ./hsqldb-*.jar && chmod 0664 ./hsqldb-*.jar

# Install Postgres JDBC
ARG POSTGRES_JDBC_URL="https://repo1.maven.org/maven2/org/postgresql/postgresql/42.7.3/postgresql-42.7.3.jar"
ARG POSTGRES_JDBC_CHECKSUM="a2644cbfba1baa145ff7e8c8ef582a6eed7a7ec4ca792f7f054122bdec756268"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& rm -f ./postgresql-*.jar \
	&& curl -LO "${POSTGRES_JDBC_URL:?}" \
	&& printf '%s  %s' "${POSTGRES_JDBC_CHECKSUM:?}" ./postgresql-*.jar | sha256sum -c \
	&& chown biserver:root ./postgresql-*.jar && chmod 0664 ./postgresql-*.jar

# Install MySQL JDBC
ARG MYSQL_JDBC_URL="https://repo1.maven.org/maven2/mysql/mysql-connector-java/5.1.49/mysql-connector-java-5.1.49.jar"
ARG MYSQL_JDBC_CHECKSUM="5bba9ff50e5e637a0996a730619dee19ccae274883a4d28c890d945252bb0e12"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& rm -f ./mysql-connector-*.jar \
	&& curl -LO "${MYSQL_JDBC_URL:?}" \
	&& printf '%s  %s' "${MYSQL_JDBC_CHECKSUM:?}" ./mysql-connector-*.jar | sha256sum -c \
	&& chown biserver:root ./mysql-connector-*.jar && chmod 0664 ./mysql-connector-*.jar

# Install MSSQL JDBC
ARG MSSQL_JDBC_URL="https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/12.6.1.jre11/mssql-jdbc-12.6.1.jre11.jar"
ARG MSSQL_JDBC_CHECKSUM="3b1a70145dbaff98daa70022791e15becfb2b9534cc9e8cfaa1bdba6a3edeb8e"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& rm -f ./mssql-jdbc-*.jar \
	&& curl -LO "${MSSQL_JDBC_URL:?}" \
	&& printf '%s  %s' "${MSSQL_JDBC_CHECKSUM:?}" ./mssql-jdbc-*.jar | sha256sum -c \
	&& chown biserver:root ./mssql-jdbc-*.jar && chmod 0664 ./mssql-jdbc-*.jar

# Install Vertica JDBC
ARG VERTICA_JDBC_URL="https://repo1.maven.org/maven2/com/vertica/jdbc/vertica-jdbc/24.1.0-2/vertica-jdbc-24.1.0-2.jar"
ARG VERTICA_JDBC_CHECKSUM="0002312e36997821f221bcb29183bcbfe838be9447ed7842da45978ed77c7b7f"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& rm -f ./vertica-jdbc-*.jar \
	&& curl -LO "${VERTICA_JDBC_URL:?}" \
	&& printf '%s  %s' "${VERTICA_JDBC_CHECKSUM:?}" ./vertica-jdbc-*.jar | sha256sum -c \
	&& chown biserver:root ./vertica-jdbc-*.jar && chmod 0664 ./vertica-jdbc-*.jar

# Install ClickHouse JDBC
ARG CLICKHOUSE_JDBC_URL="https://repo1.maven.org/maven2/com/clickhouse/clickhouse-jdbc/0.6.0/clickhouse-jdbc-0.6.0-shaded.jar"
ARG CLICKHOUSE_JDBC_CHECKSUM="546a266c2abfd70ee23dcd1b748085310e3fd1cdb5bbe242d614f724391f6a35"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& rm -f ./clickhouse-jdbc-*.jar \
	&& curl -LO "${CLICKHOUSE_JDBC_URL:?}" \
	&& printf '%s  %s' "${CLICKHOUSE_JDBC_CHECKSUM:?}" ./clickhouse-jdbc-*.jar | sha256sum -c \
	&& chown biserver:root ./clickhouse-jdbc-*.jar && chmod 0664 ./clickhouse-jdbc-*.jar

# Install CAS libraries
ARG CAS_CLIENT_CORE_URL="https://repo1.maven.org/maven2/org/jasig/cas/client/cas-client-core/3.6.4/cas-client-core-3.6.4.jar"
ARG CAS_CLIENT_CORE_CHECKSUM="daab2af8636eac3939a8931469de7c1dea6ecb25516cea9a704a23c7ace48939"
ARG SPRING_SECURITY_CAS_URL="https://repo1.maven.org/maven2/org/springframework/security/spring-security-cas/5.8.7/spring-security-cas-5.8.7.jar"
ARG SPRING_SECURITY_CAS_CHECKSUM="b2f136e365431828bfb5e83d898f3677200e3006b129e1e565f03725eaeb3e45"
RUN cd "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF/lib/ \
	&& curl -LO "${CAS_CLIENT_CORE_URL:?}" \
	&& printf '%s  %s' "${CAS_CLIENT_CORE_CHECKSUM:?}" ./cas-client-core-*.jar | sha256sum -c \
	&& chown biserver:root ./cas-client-core-*.jar && chmod 0664 ./cas-client-core-*.jar \
	&& curl -LO "${SPRING_SECURITY_CAS_URL:?}" \
	&& printf '%s  %s' "${SPRING_SECURITY_CAS_CHECKSUM:?}" ./spring-security-cas-*.jar | sha256sum -c \
	&& chown biserver:root ./spring-security-cas-*.jar && chmod 0664 ./spring-security-cas-*.jar

# Add hook to update Pentaho BI Server truststore
RUN ln -s /usr/share/biserver/bin/jks-truststore-update.sh /etc/ca-certificates/update.d/biserver-jks-truststore
RUN find /etc/ssl/certs/ -type d -not -perm 0775 -exec chmod 0775 '{}' '+'

# Replace Apache Lucene/Solr with the system provided (which includes a fix for CVE-2017-12629)
RUN cd "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF/lib/ \
	&& export DEBIAN_FRONTEND=noninteractive && ARCH="$(dpkg --print-architecture)" \
	&& apt-get update && apt-get install -y --no-install-recommends liblucene3-java \
	&& rm -rf /var/lib/apt/lists/* \
	&& rm -v ./lucene*-core-3.6.*.jar \
	&& cp -v /usr/share/java/lucene*-core-3.6.*.jar ./ \
	&& chown biserver:root ./lucene*-core-*.jar && chmod 0664 ./lucene*-core-*.jar

# Remove vulnerable log4j classes (CVE-2021-4104, CVE-2021-44228 and CVE-2021-45046)
RUN find "${BISERVER_HOME:?}" -iname '*.jar' \
		-exec sh -euc 'unzip -l "${1:?}" | grep -qF "${2:?}" && zip -qd "${1:?}" "${2:?}" ||:' _ '{}' 'org/apache/log4j/net/JMSAppender.class' ';' \
		-exec sh -euc 'unzip -l "${1:?}" | grep -qF "${2:?}" && zip -qd "${1:?}" "${2:?}" ||:' _ '{}' 'org/apache/logging/log4j/core/lookup/JndiLookup.class' ';'

# Clean up temp directory
RUN find /tmp/ -mindepth 1 -delete

# Other environment variables
ENV SVDIR="/usr/share/biserver/service/"
ENV SVWAIT="30"

# Copy Pentaho BI Server config
COPY --chown=biserver:root ./config/biserver.priv.init.d/ "${BISERVER_PRIV_INITD}"/
COPY --chown=biserver:root ./config/biserver.init.d/ "${BISERVER_INITD}"/

# Copy scripts
COPY --chown=biserver:root ./scripts/bin/ /usr/share/biserver/bin/

# Copy services
COPY --chown=biserver:root ./scripts/service/ /usr/share/biserver/service/

# Drop root privileges
USER "${BIUSER_UID}:0"

# Switch to Pentaho BI Server directory
WORKDIR "${BISERVER_HOME}"

# Set correct permissions to support arbitrary user ids
RUN /usr/share/biserver/bin/update-permissions.sh

HEALTHCHECK --start-period=120s --interval=10s --timeout=5s --retries=3 CMD ["/usr/share/biserver/bin/healthcheck.sh"]

STOPSIGNAL SIGHUP
ENTRYPOINT ["/usr/bin/catatonit", "--"]
CMD ["/usr/share/biserver/bin/init.sh"]
