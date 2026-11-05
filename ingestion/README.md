# Ingestion & Normalization Module

## Purpose
Collects raw logs from targets (OWASP Juice Shop, DVWA, system/auth logs), parses them, normalizes them into a unified schema (ECS/OCSF-inspired), and loads them into DuckDB.

## Roadmap (Milestone 1)
- [ ] Raw log collectors (Docker json-file / access logs).
- [ ] Schema normalizer with standard fields (`@timestamp`, `source.ip`, `http.request.url`, etc.).
- [ ] DuckDB database loader & indexing script.
- [ ] Malformed log break-it tests.
