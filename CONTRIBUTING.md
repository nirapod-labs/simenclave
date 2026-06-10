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

## Design before code

The mechanism, the protocol, and the security model are settled. A change to any of them is a design discussion first, and the code follows. Not the other way around.
