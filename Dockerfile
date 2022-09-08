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
		patch \
		postgresql-client-14 \
		pwgen \
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
	&& rm -rf /var/lib/apt/lists/*

# Install Supercronic
ARG SUPERCRONIC_VERSION="0.2.1"
ARG SUPERCRONIC_URL="https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-amd64"
ARG SUPERCRONIC_CHECKSUM="5eb5e2533fe75acffa63e437c0d8c4cb1f0c96891b84ae10ef4e53d602505f60"
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
ENV JAVA_HOME="/usr/lib/jvm/zulu11-ca-amd64"
ENV JAVA_XMS="1024m" JAVA_XMX="4096m"
RUN update-java-alternatives --set zulu11-ca-amd64

# Tomcat environment
ENV CATALINA_HOME="/var/lib/biserver/tomcat"
ENV CATALINA_BASE="${CATALINA_HOME}"
ENV CATALINA_OPTS_EXTRA=""
ENV TOMCAT_SHUTDOWN_PORT="8005"
ENV TOMCAT_AJP_PORT="8009"
ENV TOMCAT_HTTP_PORT="8080"

# Install Tomcat
ARG TOMCAT_VERSION="9.0.65"
ARG TOMCAT_LIN_URL="https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz"
ARG TOMCAT_LIN_CHECKSUM="e92330e6b0103eb0a5af1ec42f8c0aaaf0da712b7449b962e181a191e8f2264b"
ARG TOMCAT_WIN_URL="https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}-windows-x64.zip"
ARG TOMCAT_WIN_CHECKSUM="5ef8b27266b28114cf0b56b09cdb1c11034f21f7f6e737defb4da04c66b52036"
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

# Install Pentaho BI Server
ARG BISERVER_VERSION="9.3.0.1-552"
ARG BISERVER_BASE_URL="https://repo.stratebi.com/repository/pentaho-mvn/"
ARG BISERVER_SOLUTIONS_URL="${BISERVER_BASE_URL}/pentaho/pentaho-solutions/${BISERVER_VERSION}/pentaho-solutions-${BISERVER_VERSION}.zip"
ARG BISERVER_SOLUTIONS_CHECKSUM="fa2ee4d37df3a0ed7f22c0a92232a9782de3dfcf809be26424ee908a84abf55a"
ARG BISERVER_DATA_URL="${BISERVER_BASE_URL}/pentaho/pentaho-data/${BISERVER_VERSION}/pentaho-data-${BISERVER_VERSION}.zip"
ARG BISERVER_DATA_CHECKSUM="d3121573786c31def0acb2e401b4c21c678d71dc6eed80cbd3e91a0b1cb98057"
ARG BISERVER_WAR_URL="${BISERVER_BASE_URL}/pentaho/pentaho-war/${BISERVER_VERSION}/pentaho-war-${BISERVER_VERSION}.war"
ARG BISERVER_WAR_CHECKSUM="8ebc1fc300a8f88998c60bcee3c1f9f3aaa33e1b657ba0d01592af843fed0345"
ARG BISERVER_STYLE_URL="${BISERVER_BASE_URL}/pentaho/pentaho-style/${BISERVER_VERSION}/pentaho-style-${BISERVER_VERSION}.war"
ARG BISERVER_STYLE_CHECKSUM="6609600221a093a343c9b7780a5a2b3fe3b8b41ae787fdd0eea12e8d7f7e5a9a"
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
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/mysql/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/oracle10g/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/oracle12c/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/postgresql/ \
	&& rm -rf "${BISERVER_HOME:?}"/"${DATA_DIRNAME:?}"/sqlserver/ \
	# Remove Hadoop libraries from Kettle
	&& rm -rf "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/plugins/pentaho-big-data-plugin/hadoop-configurations/* \
	&& rm -rf "${BISERVER_HOME:?}"/"${SOLUTIONS_DIRNAME:?}"/system/kettle/plugins/pentaho-big-data-plugin/pentaho-mapreduce-libraries.zip \
	# Remove JPivot, it's not maintained anymore
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
ARG H2_JDBC_URL="https://repo1.maven.org/maven2/com/h2database/h2/2.1.210/h2-2.1.210.jar"
ARG H2_JDBC_CHECKSUM="edc57299926297fd9315e04de75f8538c4cb5fe97fd3da2a1e5cee6a4c98b5cd"
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
ARG POSTGRES_JDBC_URL="https://repo1.maven.org/maven2/org/postgresql/postgresql/42.4.1/postgresql-42.4.1.jar"
ARG POSTGRES_JDBC_CHECKSUM="fb931c3841fede01c89f8e61970554076a98046c2b87ae3eb303d1481047b951"
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
ARG MSSQL_JDBC_URL="https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/10.2.1.jre11/mssql-jdbc-10.2.1.jre11.jar"
ARG MSSQL_JDBC_CHECKSUM="055085d7f604307127ae71bc1ca824b79ca81e614537450c97e0c8d16b20dd50"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${MSSQL_JDBC_URL:?}" \
	&& printf '%s  %s' "${MSSQL_JDBC_CHECKSUM:?}" ./mssql-*.jar | sha256sum -c \
	&& chown biserver:root ./mssql-*.jar && chmod 0664 ./mssql-*.jar

# Install Vertica JDBC
ARG VERTICA_JDBC_URL="https://repo1.maven.org/maven2/com/vertica/jdbc/vertica-jdbc/12.0.0-0/vertica-jdbc-12.0.0-0.jar"
ARG VERTICA_JDBC_CHECKSUM="66dd3874eb53632da1c55447377e1a7d4265ea477bbe68e3f26ab4df089f8655"
RUN cd "${CATALINA_BASE:?}"/lib/ \
	&& curl -LO "${VERTICA_JDBC_URL:?}" \
	&& printf '%s  %s' "${VERTICA_JDBC_CHECKSUM:?}" ./vertica-*.jar | sha256sum -c \
	&& chown biserver:root ./vertica-*.jar && chmod 0664 ./vertica-*.jar

# Install CAS libraries
ARG CAS_CLIENT_CORE_URL="https://repo1.maven.org/maven2/org/jasig/cas/client/cas-client-core/3.6.4/cas-client-core-3.6.4.jar"
ARG CAS_CLIENT_CORE_CHECKSUM="daab2af8636eac3939a8931469de7c1dea6ecb25516cea9a704a23c7ace48939"
ARG SPRING_SECURITY_CAS_URL="https://repo1.maven.org/maven2/org/springframework/security/spring-security-cas/4.2.20.RELEASE/spring-security-cas-4.2.20.RELEASE.jar"
ARG SPRING_SECURITY_CAS_CHECKSUM="e19b4304a697960567eb30c6fb1b63ee4ce99cc80bbc0783bcdca8a8e8bf0866"
RUN cd "${CATALINA_BASE:?}"/webapps/"${WEBAPP_PENTAHO_DIRNAME:?}"/WEB-INF/lib/ \
	&& curl -LO "${CAS_CLIENT_CORE_URL:?}" \
	&& printf '%s  %s' "${CAS_CLIENT_CORE_CHECKSUM:?}" ./cas-client-core-*.jar | sha256sum -c \
	&& chown biserver:root ./cas-client-core-*.jar && chmod 0664 ./cas-client-core-*.jar \
	&& curl -LO "${SPRING_SECURITY_CAS_URL:?}" \
	&& printf '%s  %s' "${SPRING_SECURITY_CAS_CHECKSUM:?}" ./spring-security-cas-*.jar | sha256sum -c \
	&& chown biserver:root ./spring-security-cas-*.jar && chmod 0664 ./spring-security-cas-*.jar

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
ENV SERVICE_BISERVER_ENABLED="true"
ENV SERVICE_SUPERCRONIC_ENABLED="true"
ENV SVDIR="/usr/share/biserver/service/enabled"
ENV SVWAIT="30"

# Copy Pentaho BI Server config
COPY --chown=biserver:root ./config/biserver.priv.init.d/ "${BISERVER_PRIV_INITD}"/
COPY --chown=biserver:root ./config/biserver.init.d/ "${BISERVER_INITD}"/

# Copy crontab
COPY --chown=biserver:root ./config/crontab /etc/supercronic/crontab

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

HEALTHCHECK --start-period=120s --interval=10s --timeout=5s --retries=3 CMD ["/usr/share/biserver/bin/healthcheck.sh"]

STOPSIGNAL SIGHUP
ENTRYPOINT ["/usr/bin/catatonit", "--"]
CMD ["/usr/share/biserver/bin/init.sh"]
