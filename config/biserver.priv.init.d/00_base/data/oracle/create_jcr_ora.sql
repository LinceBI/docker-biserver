CREATE USER jcr_user IDENTIFIED BY "jcr_password" QUOTA UNLIMITED ON USERS;
GRANT CREATE SESSION, CREATE PROCEDURE, CREATE TABLE, CREATE TRIGGER, CREATE SEQUENCE TO jcr_user;

CONNECT jcr_user/jcr_password;
COMMIT;
