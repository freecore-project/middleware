# middleware

[FreeCORE](https://freecore.org) carries the TrueNAS CORE 13.3 system forward as an
independently maintained operating system on FreeBSD. TrueNAS CORE 13.3 systems
upgrade straight to FreeCORE 15.0 in place, then continue on the project’s
update train.

Not affiliated with or endorsed by iXsystems, Inc.

## What this repository is

`middleware` forked from [`truenas/middleware`](https://github.com/truenas/middleware) at:

| | |
|---|---|
| **Base commit** | `2147134704a9fa615dd223bc55ed352285da31ce` |
| **Base** | truenas/13.3-u1-stable @ 2024-08-07 |
| **Licence** | LGPL-3.0 — unchanged from upstream |

## How to read the history

Upstream history is preserved verbatim below the base commit: original commits,
original authors, original dates. Everything FreeCORE changed sits above it.

```sh
git log --oneline 2147134704a9..HEAD      # the entire FreeCORE delta
git diff 2147134704a9..HEAD               # ...as one diff
```

The FreeCORE commits are a compact **release history**, generated from the
reviewed source-state difference rather than copied from the development
repositories. Private commit subjects, issue references, dates, and intermediate
churn are not mirrored here. Only tagged release commits are states that were
built and tested.

## Releases

Tags mark states that were actually built, installed and validated.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go to
security@freecore.org, not to the issue tracker — see [SECURITY.md](SECURITY.md).

## Licence and attribution

See [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md). Nothing here is
relicensed; upstream copyright notices and licence texts are preserved.
