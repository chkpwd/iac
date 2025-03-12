CREATE DATABASE immich;
\c immich
BEGIN;
ALTER DATABASE immich OWNER TO immich;
CREATE EXTENSION IF NOT EXISTS vectors;
CREATE EXTENSION IF NOT EXISTS earthdistance CASCADE;
ALTER DATABASE immich SET search_path TO "$user", public, vectors;
GRANT USAGE ON SCHEMA vectors TO immich;
GRANT SELECT ON TABLE pg_vector_index_stat to immich;
COMMIT;
