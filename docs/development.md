# Development

SimEnclave is Swift (the helper and the shared packages), C (the interposer and the wire codec), and a small JS workspace (lint and hooks). Three build tools, each doing what it is best at, with one command surface over them:

- **SwiftPM** builds the Swift packages.
- **CMake** builds the native C: the interposer for both the macOS host and the iOS-simulator slices, the C codec, and Dobby (the hook backend), which CMake fetches and pins itself.
- **The Makefile** is the front door. It holds no build flags; it delegates to cmake, swift, and biome.

## Prerequisites

- macOS on Apple Silicon. The Mac needs a real Secure Enclave; the Simulator has none, which is the whole reason this tool exists.
- The Xcode in `.xcode-version`. Point the active developer directory at it once: `sudo xcode-select -s /Applications/Xcode.app`. The Makefile also forces this for its own commands, since the Command Line Tools ship no iOS SDKs.
- Homebrew. `brew bundle` installs the rest from the `Brewfile`: cmake, llvm (clang-format, clang-tidy, clangd), swiftlint, swiftformat, node, pnpm, lefthook.

## One-command setup

```sh
make bootstrap
```

That runs `brew bundle`, `pnpm install`, installs the git hooks, and configures both CMake build trees, which fetches and builds Dobby. A fresh clone is ready after this.

## The make targets

| Target | What it does |
| --- | --- |
| `make build` | the native slices (cmake) and the Swift packages |
| `make test` | the C tests (ctest), the Swift tests, and mechanism C |
| `make mechanism-c` | host proof: the hooks route to the helper and the signature verifies |
| `make mechanism-d` | simulator proof (the M0 bar): an in-simulator signature verifies |
| `make lint` | biome, swiftlint, clang-tidy |
| `make format` | biome, swiftformat, clang-format |
| `make clean` | remove the build trees |

The Secure Enclave tests skip where there is no SEP, so the suite runs anywhere and actually exercises hardware on an Apple Silicon Mac.

## VSCode

Open `simenclave.code-workspace` and accept the recommended extensions (`.vscode/extensions.json`): the Swift extension, clangd, CMake Tools, and biome.

- **Swift** IntelliSense comes from the Swift extension, which loads each of the three packages.
- **C** IntelliSense comes from clangd. It reads the compile database CMake writes for the simulator slice (`build-sim/compile_commands.json`, pointed at by `.clangd`), so run `make build` once, then reload the window.
- Format-on-save is wired per language: clang-format for C, biome for JSON and JS, the Swift extension for Swift.
- `cmd+shift+b` runs `make build`; `.vscode/tasks.json` has the rest.

The Microsoft C/C++ extension is listed under `unwantedRecommendations`, because its IntelliSense fights clangd. Use clangd.

## Where Dobby comes from

The interposer's hook backend is Dobby, pinned in the root `CMakeLists.txt` and fetched by CMake's FetchContent into each build tree. There is no separate vendoring step and nothing to commit.

## Conventions

PR-driven, conventional commits (`.commitlintrc.json`), and the formatters above, all enforced by the lefthook hooks. See [CONTRIBUTING.md](../CONTRIBUTING.md).
