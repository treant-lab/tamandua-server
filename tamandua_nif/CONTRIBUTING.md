# Contributing to tamandua-nif (ships inside tamandua-server)

This component is part of the Tamandua EDR platform. For the canonical
contribution guide — code of conduct, contribution tracks, and community
norms — see the community repository:

  https://github.com/treant-lab/tamandua-community

Please also read this component's [README](./README.md) for details.

## Component build & test

```bash
mix deps.get
mix compile
```

## Before opening a PR

- Requires a Rust toolchain (compiled via rustler). The canonical gate is Linux.
- Keep changes scoped; avoid unrelated refactors.
- Do not commit secrets or large binaries.
- Do not fabricate or overstate results; preserve benchmark caveats verbatim.
