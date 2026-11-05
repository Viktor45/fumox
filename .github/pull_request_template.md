## Description of Changes

<!-- Describe the changes made and the purpose behind them -->

## Type of Changes

<!-- Check all that apply -->

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation improvement
- [ ] Performance optimization
- [ ] Other: <!-- specify type -->

## Performance data (performance PRs only)

<!-- Required when the type above includes "Performance optimization", delete the section otherwise: the before/after numbers, the command that measured them and the environment (machine, build profile, dataset size) -->

- Before (latency / throughput / RSS):
- After (latency / throughput / RSS):
- Measurement command:
- Environment:

## Related Issues

<!-- Reference related issue numbers, if any -->

Fixes #<number> (if applicable)

## Breaking changes / Migration

<!-- "None" is the default. Otherwise list every renamed env variable or CLI flag and every change to the format of the served subscription, together with the migration steps. -->

None

## Checklist

<!-- Run locally before opening the PR: cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked; ops scripts are covered by bash scripts/tests/*.test.sh -->

- [ ] I have performed a self-code review of my changes
- [ ] I have updated the documentation accordingly (where applicable)
- [ ] I added or updated automated tests covering the change (or explained why a test is not needed)
- [ ] I have tested the proposed changes locally or in another verified environment (performance PRs: benchmark results attached)
- [ ] I verified that no secrets/tokens leak into logs, errors or responses, and that external input is validated (SSRF/injection)
