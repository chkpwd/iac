-- Bootstrap PostGIS extensions for dawarich.
\c dawarich
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;
CREATE EXTENSION IF NOT EXISTS hstore;
