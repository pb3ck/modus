# Changelog

All notable changes to Modus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 0.1.0. Pre-0.1.0 versions are not stable; the CLI
surface, action vocabulary, and corpus interface may change without
notice.

## [Unreleased]

### Added

- Initial repository skeleton: README, ROADMAP, LICENSE, CONTRIBUTING,
  SECURITY, CHANGELOG, AUTHORS.
- Python package layout under `src/modus/`.
- `pyproject.toml` with `uv`-managed dependencies.
- Documentation scaffolding under `docs/`.
- First architectural decision record:
  [`docs/adr/0001-typed-action-vocabulary.md`](./docs/adr/0001-typed-action-vocabulary.md).
- `.github/` workflows for lint and test on push.
- `.gitignore` covering Python, editor, and OS artifacts.
