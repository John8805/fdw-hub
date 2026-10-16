FROM postgres:17
# 官方映像檔內建 postgres_fdw；另外加裝 mysql_fdw 以連接 MariaDB / MySQL
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-${PG_MAJOR}-mysql-fdw \
 && rm -rf /var/lib/apt/lists/*
