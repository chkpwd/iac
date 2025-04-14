CREATE DATABASE immich;
\c immich
BEGIN;
ALTER DATABASE immich OWNER TO immich;
CREATE EXTENSION IF NOT EXISTS earthdistance CASCADE; -- installs dependencies (i.e. cube)
CREATE EXTENSION IF NOT EXISTS vectors;
ALTER DATABASE immich SET search_path TO "$user", public, vectors;
ALTER SCHEMA vectors OWNER TO immich;
COMMIT;
