# Ejemplos de despliegue

## `./run.sh`

Despliega un contenedor Pentaho BI Server con almacenamiento local.

## `./run_with_postgres.sh`

Crea una red y despliega asociados a ella un contenedor Pentaho BI Server y otro Postgres donde se almacenan los datos de Jackrabbit, Quartz e
Hibernate.

## `./run_with_mysql.sh`

Crea una red y despliega asociados a ella un contenedor Pentaho BI Server y otro MySQL donde se almacenan los datos de Jackrabbit, Quartz e
Hibernate.

## `./run_cluster_with_postgres.sh`

Crea una red y despliega asociados a ella dos contenedores Pentaho BI Server configurados en modo cluster, los cuales almacenan los datos en un
contenedor Postgres.

## `./export_with_postgres.sh`

Envía a STDOUT un tarball de un Pentaho BI Server ya configurado para almacenar los datos en PostgreSQL.

## `./export_with_mysql.sh`

Envía a STDOUT un tarball de un Pentaho BI Server ya configurado para almacenar los datos en MySQL.
