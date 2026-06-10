# Contributing

SimEnclave is PR-driven. Everything lands through a pull request that a maintainer reviews. Nothing goes straight to `main`.

## The basics

- Branch off `main`, and keep the branch focused on one thing.
- Conventional commits, lowercase subject after the type and scope. The allowed types and scopes are in `.commitlintrc.json`, and the commit-msg hook checks them, so a bad message won't commit.
- Small PRs. If a reviewer can't hold the whole change in their head, split it.
- CI has to be green before merge: lint, build, and the relevant tests.

## Hooks

Run `pnpm install` and `lefthook install` once. After that, formatting and the commit-message check run on commit, and the heavier checks run on push. If a hook blocks you and you genuinely need around it, that's a conversation with a maintainer, not a quiet `--no-verify`.

## Building

Filled in as the milestones land. The shape: the helper is a Swift app built with XcodeGen, the interposer is C built with clang for the Simulator slice, and the JS side is a pnpm workspace.

## Where the design lives

The decisions and the architecture live in the `nirapod-arch` repo, not here. If a change would alter the mechanism, the protocol, or the security model, it needs a design change there first. Code follows the design, not the other way around.
