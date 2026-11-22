# Ingestion & Normalization Module

## Purpose
Collects raw logs from targets (OWASP Juice Shop, DVWA, system/auth logs), parses them, normalizes them into a unified schema (ECS/OCSF-inspired), and loads them into DuckDB.

## Implementation Status (Milestone 1)
- [x] Raw log collectors (Docker json-file / combined web access logs / SSH auth logs).
- [x] Schema normalizer with standard ECS/OCSF fields and deterministic `event_id` content hashing (`schema.py`).
- [x] DuckDB database loader & analytical store with true deduplication tracking (`duckdb_store.py`).
- [x] Malformed log and out-of-order event break-it tests (`tests/test_ingestion_break_it.py`).
