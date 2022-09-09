# Pentaho BI Server en Docker

Imagen de Docker para Pentaho BI Server.

## Construcción de la imagen

La construcción de esta imagen sigue el procedimiento estándar de Docker con el comando `docker build`, no obstante, para facilitar el proceso se dispone de un [Makefile](https://en.wikipedia.org/wiki/Makefile) con las siguientes tareas:

  * **`make build-image`**: construye la imagen.
  * **`make save-image`**: exporta en el directorio `./dist/` un tarball de la imagen.
  * **`make save-standalone`**: exporta en el directorio `./dist/` un tarball de la instalación con una estructura similar a la que podemos encontrar en los ZIP de Pentaho BI Server en Sourceforge.
  * **`make all`**: ejecuta las tareas `save-image` y `save-standalone`.

## Argumentos del Dockerfile

  * **`BISERVER_VERSION`:** versión de Pentaho BI Server.  
    **Por defecto:** `8.3.0.28-1658`

  * **`BISERVER_MAVEN_REPO`:** repositorio de Maven del que se descargan las dependencias necesarias para la instalación de Pentaho BI Server.  
    **Por defecto:** `https://repo.stratebi.com/repository/pentaho-mvn/`

## Variables de entorno

<details>
  <summary>Servicios</summary>

> * **`SERVICE_BISERVER_ENABLED`:** habilita el servicio de Pentaho BI Server.  
>   **Por defecto:** `true`
>
> * **`SERVICE_SUPERCRONIC_ENABLED`:** habilita el servicio de Supercronic.  
>   **Por defecto:** `true`

</details>

<details>
  <summary>Java</summary>

> * **`JAVA_XMS`:** tamaño inicial del heap de Java.  
>   **Por defecto:** `1024m`
>
> * **`JAVA_XMX`:** tamaño máximo del heap de Java.  
>   **Por defecto:** `4096m`

</details>

<details>
  <summary>Tomcat</summary>

> * **`TOMCAT_HTTP_PORT`:** puerto en el que escuchará el conector HTTP de Tomcat.  
>   **Por defecto:** `8080`
>
> * **`TOMCAT_AJP_PORT`:** puerto en el que escuchará el conector AJP de Tomcat.  
>   **Por defecto:** `8009`
>
> * **`IS_PROXIED`:** establecer a `true` si Pentaho BI Server estará detrás de un proxy inverso.  
>   **Por defecto:** `false`
>
> * **`PROXY_SCHEME`:** protocolo del proxy inverso.  
>   **Por defecto:** `https`
>
> * **`PROXY_PORT`:** puerto del proxy inverso.  
>   **Por defecto:** `443`
>
> * **`FQSU_PROTOCOL`:** protocolo del Fully Qualified Server URL.  
>   **Por defecto:** `http`
>
> * **`FQSU_DOMAIN`:** dominio del Fully Qualified Server URL.  
>   **Por defecto:** `localhost`
>
> * **`FQSU_PORT`:** puerto del Fully Qualified Server URL.  
>   **Por defecto:** `${TOMCAT_HTTP_PORT}`

</details>

<details>
  <summary>Seguridad</summary>

> * **`DEFAULT_ADMIN_PASSWORD`:** contraseña por defecto del usuario administrador, si el valor de la variable está vacío se generará una contraseña aleatoria que será impresa por consola.  
>   **Por defecto:** *vacío*
>
> * **`DEFAULT_NON_ADMIN_PASSWORD`:** contraseña por defecto de los usuarios no administradores, si el valor de la variable está vacío se generará una contraseña aleatoria que será impresa por consola.  
>   **Por defecto:** `contraseña de admin`
>
> * **`SESSION_TIMEOUT`:** duración de sesión en minutos.  
>   **Por defecto:** `120`
>
> * **`SECURITY_PROVIDER`:** proveedor de seguridad general, admite los valores `jackrabbit`, `ldap` y `jdbc`.  
>   **Por defecto:** `jackrabbit`
>
> * **`SECURITY_ROLE_PROVIDER`:** proveedor de seguridad para roles, admite los valores `jackrabbit`, `ldap` y `jdbc`.  
>   **Por defecto:** `${SECURITY_PROVIDER}`
>
> * **`SECURITY_REQUEST_PARAMETER_AUTHENTICATION_ENABLED`:** habilita la autenticación por parámetros en la URL (`userid` y `password`).  
>   **Por defecto:** `false`
>
> <details>
>   <summary>LDAP</summary>
>
>>  * **`LDAP_CONTEXT_SOURCE_PROVIDER_URL`:** URL del servidor LDAP.  
>>    **Por defecto:** `ldap://localhost:389`
>>
>>  * **`LDAP_CONTEXT_SOURCE_USER_DN`:** DN de un usuario con permiso de lectura sobre el directorio.  
>>    **Por defecto:** `cn=admin,dc=example,dc=localdomain`
>>
>>  * **`LDAP_CONTEXT_SOURCE_PASSWORD`:** contraseña del usuario.  
>>    **Por defecto:** `password`
>>
>>  * **`LDAP_ALL_AUTHORITIES_SEARCH_SEARCH_BASE`:** localización base para la búsqueda de todos los roles.  
>>    **Por defecto:** `ou=groups,dc=example,dc=localdomain`
>>
>>  * **`LDAP_ALL_AUTHORITIES_SEARCH_SEARCH_FILTER`:** filtro para la búsqueda de todos los roles.  
>>    **Por defecto:** `(objectClass=groupOfUniqueNames)`
>>
>>  * **`LDAP_ALL_AUTHORITIES_SEARCH_SEARCH_SCOPE`:** alcance de la búsqueda, admite los valores `0` (`OBJECT_SCOPE`), `1` (`ONELEVEL_SCOPE`) y `2` (`SUBTREE_SCOPE`).  
>>    **Por defecto:** `2`
>>
>>  * **`LDAP_ALL_AUTHORITIES_SEARCH_ROLE_ATTRIBUTE`:** atributo del nombre del rol.  
>>    **Por defecto:** `cn`
>>
>>  * **`LDAP_ALL_USERNAMES_SEARCH_SEARCH_BASE`:** localización base para la búsqueda de todos los usuarios.  
>>    **Por defecto:** `ou=users,dc=example,dc=localdomain`
>>
>>  * **`LDAP_ALL_USERNAMES_SEARCH_SEARCH_FILTER`:** filtro para la búsqueda de todos los usuarios.  
>>    **Por defecto:** `(objectClass=inetOrgPerson)`
>>
>>  * **`LDAP_ALL_USERNAMES_SEARCH_SEARCH_SCOPE`:** alcance de la búsqueda, admite los valores `0` (`OBJECT_SCOPE`), `1` (`ONELEVEL_SCOPE`) y `2` (`SUBTREE_SCOPE`).  
>>    **Por defecto:** `2`
>>
>>  * **`LDAP_ALL_USERNAMES_SEARCH_USERNAME_ATTRIBUTE`:** atributo del nombre del usuario.  
>>    **Por defecto:** `cn`
>>
>>  * **`LDAP_USER_SEARCH_SEARCH_BASE`:** localización base para la búsqueda de usuarios.  
>>    **Por defecto:** `${LDAP_ALL_USERNAMES_SEARCH_SEARCH_BASE}`
>>
>>  * **`LDAP_USER_SEARCH_SEARCH_FILTER`:** filtro para la búsqueda de usuarios.  
>>    **Por defecto:** `(cn={0})`
>>
>>  * **`LDAP_POPULATOR_GROUP_SEARCH_BASE`:** localización base para la búsqueda de roles.  
>>    **Por defecto:** `${LDAP_ALL_AUTHORITIES_SEARCH_SEARCH_BASE}`
>>
>>  * **`LDAP_POPULATOR_GROUP_SEARCH_FILTER`:** filtro para la búsqueda de roles.  
>>    **Por defecto:** `(uniqueMember={0})`
>>
>>  * **`LDAP_POPULATOR_GROUP_ROLE_ATTRIBUTE`:** atributo del nombre del rol.  
>>    **Por defecto:** `${LDAP_ALL_AUTHORITIES_SEARCH_ROLE_ATTRIBUTE}`
>>
>>  * **`LDAP_POPULATOR_SEARCH_SUBTREE`:** indica si la búsqueda debe incluir los hijos del directorio.  
>>    **Por defecto:** `true`
>>
>>  * **`LDAP_POPULATOR_ROLE_PREFIX`:** prefijo para añadir al nombre de los roles.  
>>    **Por defecto:** *vacío*
>>
>>  * **`LDAP_POPULATOR_CONVERT_TO_UPPER_CASE`:** convertir roles a mayúscula.  
>>    **Por defecto:** `false`
>>
>>  * **`LDAP_ADMIN_ROLE`:** rol administrador.  
>>    **Por defecto:** `cn=Administrator,${LDAP_ALL_AUTHORITIES_SEARCH_SEARCH_BASE}`
>
> </details>
>
> <details>
>   <summary>JDBC</summary>
>
>>  * **`JDBCSEC_DATASOURCE_DRIVER_CLASSNAME`:** clase de Java del driver JDBC.  
>>    **Por defecto:** `org.postgresql.Driver`
>>
>>  * **`JDBCSEC_DATASOURCE_URL`:** URL de la conexión JDBC.  
>>    **Por defecto:** `jdbc:postgresql://localhost:5432/userdb`
>>
>>  * **`JDBCSEC_DATASOURCE_USER`:** usuario de la conexión JDBC.  
>>    **Por defecto:** `postgres`
>>
>>  * **`JDBCSEC_DATASOURCE_PASSWORD`:** contraseña de la conexión JDBC.  
>>    **Por defecto:** `postgres`
>>
>>  * **`JDBCSEC_DATASOURCE_POOL_VALIDATION_QUERY`:** consulta que se utilizará para validar las conexiones de la pool.  
>>    **Por defecto:** `SELECT 1`
>>
>>  * **`JDBCSEC_DATASOURCE_POOL_MAX_WAIT`:** tiempo máximo en milisegundos en los que la pool esperará para obtener una conexión antes de devolver una excepción.  
>>    **Por defecto:** `-1`
>>
>>  * **`JDBCSEC_DATASOURCE_POOL_MAX_ACTIVE`:** número máximo de conexiones activas en la pool.  
>>    **Por defecto:** `8`
>>
>>  * **`JDBCSEC_DATASOURCE_POOL_MAX_IDLE`:** número máximo de conexiones inactivas en la pool.  
>>    **Por defecto:** `4`
>>
>>  * **`JDBCSEC_DATASOURCE_POOL_MIN_IDLE`:** número mínimo de conexiones inactivas en la pool.  
>>    **Por defecto:** `0`
>>
>>  * **`JDBCSEC_AUTHORITIES_BY_USERNAME_QUERY`:** consulta que devuelve el usuario y los roles a los que pertenece.  
>>    **Por defecto:** `SELECT username, authority FROM granted_authorities WHERE username = ? ORDER BY authority`
>>
>>  * **`JDBCSEC_USERS_BY_USERNAME_QUERY`:** consulta que devuelve el usuario, la contraseña y si puede iniciar sesión.  
>>    **Por defecto:** `SELECT username, password, enabled FROM users WHERE username = ? ORDER BY username`
>>
>>  * **`JDBCSEC_ALL_AUTHORITIES_QUERY`:** consulta que devuelve todos los roles.  
>>    **Por defecto:** `SELECT authority FROM authorities ORDER BY authority`
>>
>>  * **`JDBCSEC_ALL_USERNAMES_QUERY`:** consulta que devuelve todos los usuarios.  
>>    **Por defecto:** `SELECT username FROM users ORDER BY username`
>>
>>  * **`JDBCSEC_ALL_USERNAMES_IN_ROLE_QUERY`:** consulta que devuelve todos los usuarios con un rol específico.  
>>    **Por defecto:** `SELECT username FROM granted_authorities WHERE authority = ? ORDER BY username`
>>
>>  * **`JDBCSEC_ADMIN_ROLE`:** rol administrador.  
>>    **Por defecto:** `Administrator`
>
>>  * **`JDBCSEC_PASSWORD_ENCODER_CLASS`:** clase codificadora de contraseñas.  
>>    **Por defecto:** `org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder`
>
> </details>
>
> <details>
>   <summary>Single Sign-On (CAS)</summary>
>
>>  * **`CAS_ENABLED`:** habilita CAS.  
>>    **Por defecto:** `false`
>>
>>  * **`CAS_URL`:** URL base de CAS.  
>>    **Por defecto:** `${FQSU_PROTOCOL}://${FQSU_DOMAIN}:${FQSU_PORT}/auth/realms/biserver/protocol/cas`
>>
>>  * **`CAS_TICKETVALIDATOR_URL`:** URL del validador de tickets de CAS.  
>>    **Por defecto:** `${CAS_URL}`
>>
>>  * **`CAS_LOGIN_URL`:** URL de inicio de sesión de CAS.  
>>    **Por defecto:** `${CAS_URL}/login`
>>
>>  * **`CAS_LOGOUT_URL`:** URL de cierre de sesión de CAS.  
>>    **Por defecto:** `${CAS_URL}/logout?service=${FQSU_PROTOCOL}://${FQSU_DOMAIN}:${FQSU_PORT}`
>>
>>  * **`CAS_PROVIDER_USERDETAILS`:** proveedor de la información del usuario, admite los valores `userDetailsService`, `ldapUserDetailsService` y `jdbcUserDetailsService`.  
>>    **Por defecto:** `userDetailsService`
>
> </details>

</details>

<details>
  <summary>Correo</summary>

> * **`MAIL_TRANSPORT_PROTOCOL`:** protocolo del servidor de correo.  
>   **Por defecto:** `smtp`
>
> * **`MAIL_SMTP_HOST`:** dirección del servidor de correo.  
>   **Por defecto:** `smtp.example.localdomain`
>
> * **`MAIL_SMTP_PORT`:** puerto del servidor de correo.  
>   **Por defecto:** `587`
>
> * **`MAIL_SMTP_AUTH`:** indica si el servidor de correo requiere autenticación.  
>   **Por defecto:** `true`
>
> * **`MAIL_SMTP_USER`:** usuario del servidor de correo.  
>   **Por defecto:** `user@example.localdomain`
>
> * **`MAIL_SMTP_PASSWORD`:** contraseña del servidor de correo.  
>   **Por defecto:** `password`
>
> * **`MAIL_SMTP_STARTTLS`:** habilita STARTTLS.  
>   **Por defecto:** `true`
>
> * **`MAIL_SMTP_SSL`:** habilita SSL.  
>   **Por defecto:** `true`
>
> * **`MAIL_SMTP_FROM_ADDRESS`:** dirección del campo `From` en los correos enviados.  
>   **Por defecto:** `${MAIL_SMTP_USER}`
>
> * **`MAIL_SMTP_FROM_NAME`:** nombre del campo `From` en los correos enviados.  
>   **Por defecto:** `BI Server`
>
> * **`MAIL_DEBUG`:** habilita el modo depuración.  
>   **Por defecto:** `false`

</details>

<details>
  <summary>Almacenamiento</summary>

> * **`STORAGE_TYPE`:** tipo de almacenamiento, admite los valores `local`, `postgres`, `mysql` o `cockroach`.  
>   **Por defecto:** `local`
>
> * **`LOAD_SAMPLES`:** cargar datos de ejemplo.  
>   **Por defecto:** `true`
>
> <details>
>   <summary>PostgreSQL</summary>
>
>>  * **`POSTGRES_HOST`:** host para la conexión con PostgreSQL.  
>>    **Por defecto:** `localhost`
>>
>>  * **`POSTGRES_PORT`:** puerto para la conexión con PostgreSQL.  
>>    **Por defecto:** `5432`
>>
>>  * **`POSTGRES_USER`:** usuario para la conexión con PostgreSQL.  
>>    **Por defecto:** `postgres`
>>
>>  * **`POSTGRES_PASSWORD`:** contraseña para la conexión con PostgreSQL.  
>>    **Por defecto:** `postgres`
>>
>>  * **`POSTGRES_DATABASE`:** nombre de la BBDD para la conexión con PostgreSQL.  
>>    **Por defecto:** `postgres`
>>
>>  * **`POSTGRES_JACKRABBIT_USER`:** nombre del usuario de Jackrabbit (se creará si no existe).  
>>    **Por defecto:** `jcr_user`
>>
>>  * **`POSTGRES_JACKRABBIT_PASSWORD`:** contraseña del usuario de Jackrabbit.  
>>    **Por defecto:** `jcr_password`
>>
>>  * **`POSTGRES_JACKRABBIT_DATABASE`:** nombre de la BBDD de Jackrabbit (se creará si no existe).  
>>    **Por defecto:** `jackrabbit`
>>
>>  * **`POSTGRES_HIBERNATE_USER`:** nombre del usuario de Hibernate (se creará si no existe).  
>>    **Por defecto:** `hibuser`
>>
>>  * **`POSTGRES_HIBERNATE_PASSWORD`:** contraseña del usuario de Hibernate.  
>>    **Por defecto:** `hibpassword`
>>
>>  * **`POSTGRES_HIBERNATE_DATABASE`:** nombre de la BBDD de Hibernate (se creará si no existe).  
>>    **Por defecto:** `hibernate`
>>
>>  * **`POSTGRES_QUARTZ_USER`:** nombre del usuario de Quartz (se creará si no existe).  
>>    **Por defecto:** `pentaho_user`
>>
>>  * **`POSTGRES_QUARTZ_PASSWORD`:** contraseña del usuario de Quartz.  
>>    **Por defecto:** `pentaho_password`
>>
>>  * **`POSTGRES_QUARTZ_DATABASE`:** nombre de la BBDD de Quartz (se creará si no existe).  
>>    **Por defecto:** `quartz`
>
> </details>
>
> <details>
>   <summary>MySQL</summary>
>
>>  * **`MYSQL_HOST`:** host para la conexión con MySQL.  
>>    **Por defecto:** `localhost`
>>
>>  * **`MYSQL_PORT`:** puerto para la conexión con MySQL.  
>>    **Por defecto:** `3306`
>>
>>  * **`MYSQL_USER`:** usuario para la conexión con MySQL.  
>>    **Por defecto:** `root`
>>
>>  * **`MYSQL_PASSWORD`:** contraseña para la conexión con MySQL.  
>>    **Por defecto:** `root`
>>
>>  * **`MYSQL_DATABASE`:** nombre de la BBDD para la conexión con MySQL.  
>>    **Por defecto:** `mysql`
>>
>>  * **`MYSQL_JACKRABBIT_USER`:** nombre del usuario de Jackrabbit (se creará si no existe).  
>>    **Por defecto:** `jcr_user`
>>
>>  * **`MYSQL_JACKRABBIT_PASSWORD`:** contraseña del usuario de Jackrabbit.  
>>    **Por defecto:** `jcr_password`
>>
>>  * **`MYSQL_JACKRABBIT_DATABASE`:** nombre de la BBDD de Jackrabbit (se creará si no existe).  
>>    **Por defecto:** `jackrabbit`
>>
>>  * **`MYSQL_HIBERNATE_USER`:** nombre del usuario de Hibernate (se creará si no existe).  
>>    **Por defecto:** `hibuser`
>>
>>  * **`MYSQL_HIBERNATE_PASSWORD`:** contraseña del usuario de Hibernate.  
>>    **Por defecto:** `hibpassword`
>>
>>  * **`MYSQL_HIBERNATE_DATABASE`:** nombre de la BBDD de Hibernate (se creará si no existe).  
>>    **Por defecto:** `hibernate`
>>
>>  * **`MYSQL_QUARTZ_USER`:** nombre del usuario de Quartz (se creará si no existe).  
>>    **Por defecto:** `pentaho_user`
>>
>>  * **`MYSQL_QUARTZ_PASSWORD`:** contraseña del usuario de Quartz.  
>>    **Por defecto:** `pentaho_password`
>>
>>  * **`MYSQL_QUARTZ_DATABASE`:** nombre de la BBDD de Quartz (se creará si no existe).  
>>    **Por defecto:** `quartz`
>
> </details>

</details>

<details>
  <summary>Otros</summary>

> * **`FILE_UPLOAD_DEFAULTS_MAX_FILE_LIMIT`:** tamaño máximo de archivo en bytes permitido para subir al servidor.  
>   **Por defecto:** `128000000`
>
> * **`FILE_UPLOAD_DEFAULTS_MAX_FOLDER_LIMIT`:** tamaño máximo de directorio en bytes permitido para subir al servidor.  
>   **Por defecto:** `512000000`

</details>

## Instalación de plugins y ejecución de scripts personalizados

Es posible instalar plugins o ejecutar scripts personalizados antes de iniciar Tomcat por primera vez. Los archivos o directorios situados en el directorio `./config/biserver.init.d/` son tratados de diferentes maneras.

 * **Archivos `*.sh` y `*.run`:** son ejecutados desde el directorio de trabajo `${BISERVER_HOME}`. Tendrán disponibles todas las variables de entorno anteriormente documentadas.
 * **Archivos `*.jar`:** son copiados a `${CATALINA_BASE}/lib/`.
 * **Archivos `*.tar`, `*.tar.gz`, `*.tgz`, `*.tar.bz2`, `*.tbz2`, `*.tar.xz`, `*.txz`, `*.zip`, `*.kar`:**
   * **`*.__root__.*`**: son extraídos en `${BISERVER_HOME}`.
   * **`*.__webapp_pentaho__.*`**: son extraídos en `${CATALINA_BASE}/webapps/${WEBAPP_PENTAHO_DIRNAME}`.
   * **`*.__webapp_pentaho_style__.*`**: son extraídos en `${CATALINA_BASE}/webapps/${WEBAPP_PENTAHO_STYLE_DIRNAME}`.
   * **`*.__pentaho_solutions__.*`**: son extraídos en `${BISERVER_HOME}/${SOLUTIONS_DIRNAME}`.
   * **`*.__data__.*`**: son extraídos en `${BISERVER_HOME}/${DATA_DIRNAME}`.
   * **`*.__plugin__.*`**: son extraídos en `${BISERVER_HOME}/${SOLUTIONS_DIRNAME}/system/`.
   * **Todos los demás**: se autodetectará si tratarse como `*.__root__.*` o `*.__plugin__.*`.
 * **Directorios:**
   * **`*.__root__`**: son copiados en `${BISERVER_HOME}`.
   * **`*.__webapp_pentaho__`**: son copiados en `${CATALINA_BASE}/webapps/${WEBAPP_PENTAHO_DIRNAME}`.
   * **`*.__webapp_pentaho_style__`**: son copiados en `${CATALINA_BASE}/webapps/${WEBAPP_PENTAHO_STYLE_DIRNAME}`.
   * **`*.__pentaho_solutions__`**: son copiados en `${BISERVER_HOME}/${SOLUTIONS_DIRNAME}`.
   * **`*.__data__`**: son copiados en `${BISERVER_HOME}/${DATA_DIRNAME}`.
   * **`*.__plugin__`**: son copiados en `${BISERVER_HOME}/${SOLUTIONS_DIRNAME}/system/`.
   * **Todos los demás**: se autodetectará si tratarse como `*.__root__` o `*.__plugin__`.

Para añadir estos archivos a una imagen ya construida, se debe montar en el contenedor el directorio `/etc/biserver.init.d/`.

```sh
docker run \
  # ...
  --mount type=bind,src='/ruta/a/mis/plugins/',dst='/etc/biserver.init.d/',ro \
  # ...
```

## Ejemplos de despliegue

El ejemplo más simple es el despliegue de un contenedor con almacenamiento local.

```sh
docker run --detach \
  --name biserver \
  --publish '8080:8080/tcp' \
  --mount type=volume,src=biserver-jackrabbit,dst=/var/lib/biserver/pentaho-solutions/system/jackrabbit/repository/ \
  --mount type=volume,src=biserver-hsqldb,dst=/var/lib/biserver/data/hsqldb/ \
  --mount type=volume,src=biserver-logs,dst=/var/lib/biserver/tomcat/logs/ \
  repo.stratebi.com/lincebi/biserver:8.3.0.28-1658
```

Para despliegues más complejos, en el directorio `./examples/` se encuentran varios scripts en shell con otros casos comunes.
