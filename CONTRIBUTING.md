# Contributing to tamandua-server

This component is part of the Tamandua EDR platform. For the canonical
contribution guide — code of conduct, contribution tracks, and community
norms — see the community repository:

  https://github.com/treant-lab/tamandua-community

Please also read this component's [README](./README.md) for details.

## Component build & test

```bash
mix deps.get
mix compile
mix test
mix format --check-formatted
mix dialyzer
```

## Before opening a PR

- The canonical build/test gate is Linux (the Elixir stack incl. bcrypt is not built on Windows hosts).
- A Rust toolchain is required to compile the bundled NIF.
- Keep changes scoped; avoid unrelated refactors.
- Do not commit secrets or large binaries.
- Do not fabricate or overstate results; preserve benchmark caveats verbatim.
