---
name: "\U0001F4A1 Feature Request"
about: Suggest an idea for this project
title: "\U0001F4A1 [ENHANCEMENT] - <brief title>"
labels: enhancement
assignees: Viktor45
---

**Is your feature request related to a problem? Please describe.**  
A clear and concise description of the problem. For example: "I'm frustrated when [...]"

**Describe the solution you'd like**  
A clear and concise description of what you want to happen.

Expected load and limits (fill in what the feature must hold up under):
- Number of sources/subscriptions and proxies:
- Required refresh frequency (subscription fetches and probe runs):
- Acceptable latency (request handling and probe rounds):
- Acceptable CPU/RAM consumption:
- Timeout and retry constraints:

**Impact / Compatibility**  
- Does it change the format of the served subscription? If yes, how:
- Does it affect existing configurations or integrations (config keys, CLI flags, HTTP endpoints)? Which:
- Is a migration required for current deployments? If yes, what does it involve:
- The version you expect this to land in:

**Describe alternatives you've considered**  
A description of any alternative solutions or workarounds you've already tried or evaluated.

**Additional context**  
Any additional context: use cases, links to similar projects, screenshots, etc.

**Do not paste secrets**  
This is a public issue tracker. Replace every token, key, password and subscription URL with a placeholder (`<token>`, `https://example.com/sub/…`), and remove the `Authorization` header and the `[admin].token` value. Never post a live subscription URL or a config file with a real secret in it.
