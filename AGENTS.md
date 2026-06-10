# SimEnclave (AGENTS.md)

This repo is governed by Nirapod's constitution. The AI is the senior engineer; the human is the operator and final approver. Durable truth lives in the repos.

## Hard rules

- SimEnclave is a development tool. It must never become a production signing path or touch a real user's keys or funds. The fence, an env-var-only load asserted absent from release builds, is the proof, and it isn't optional.
- Prove security claims in code, with the parity and fence tests. No aspirational security in comments.
- Boring, audited primitives. SimEnclave adds no cryptography; it calls Apple's Security framework and the platform Secure Enclave.
- PR-driven. Branch, open a PR, let CI run, let the operator approve. Never self-merge.

## Where the design lives

The decision is FOUNDATION-ADR-001 and the architecture is the SimEnclave doc, both in the `nirapod-arch` repo. Read them before changing the mechanism.
