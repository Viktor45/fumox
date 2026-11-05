---
name: "\U0001F41E Bug Report"
about: Create a report to help us improve the project
title: "\U0001F41E [BUG] - <brief description>"
labels: bug
assignees: Viktor45
---

**Describe the bug**  
A clear and concise description of what the bug is.

**To Reproduce**  
- The run command or the HTTP endpoint that triggers it (e.g. `docker run ...`, `curl -v http://127.0.0.1:8080/...`):
- The relevant config fragment, with every secret masked (see below):
- The steps to reproduce, in order:
- The actual result and the expected result:

**Commit / version**  
The image tag or digest, or the commit the binary was built from.

**Configuration / profile**  
The config sections in effect for the run (`[server]`, `[probe]`, ...), secrets masked.

**GeoIP database version (date)**  
The file name or build date of the GeoIP database in use.

**Dependency versions**  
Anything the reproduction depends on: Rust toolchain, container/Podman version, OS, etc.

**Screenshots**  
If applicable, add screenshots to help explain your problem.

**Additional context**  
Any other context: operating system, logs, network conditions, etc.

**Logs**  
Paste the relevant log lines here, or point at where they can be found. Raise the log level for the run that misbehaves — `[log].server` / `[log].probe` (or `RUST_LOG`) — and quote only the lines around the failure.

**Performance data (if relevant)**  
- Commit / version measured:
- Number of subscriptions and proxies:
- Number of sources fetched concurrently:
- Request rate / concurrency:
- Latency p50 / p95 / p99:
- CPU / RAM:
- The timeouts in effect and the exact error text:

Strip tokens, keys and private URLs from anything quoted above.

**Do not paste secrets**  
This is a public issue tracker. Replace every token, key, password and subscription URL with a placeholder (`<token>`, `https://example.com/sub/…`), and remove the `Authorization` header and the `[admin].token` value. Never post a live subscription URL or a config file with a real secret in it.
