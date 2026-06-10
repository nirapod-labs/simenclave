# Developer dependencies for SimEnclave. `brew bundle` installs them; `make
# bootstrap` then adds the pnpm packages and the git hooks. Xcode itself is not a
# formula: install the version in .xcode-version from the App Store or via the
# xcodes CLI below.

# Native build and lint toolchain
brew "cmake"        # the native C build system (the interposer and Dobby)
brew "llvm"         # clang-format, clang-tidy, and clangd for the C side
brew "swiftlint"    # Swift linting, reads .swiftlint.yml
brew "swiftformat"  # Swift formatting, reads .swiftformat
brew "doxygen"      # the C API documentation gate (make docs, reads Doxyfile)

# JavaScript workspace
brew "node"
brew "pnpm"

# Git hooks and the toolchain pin
brew "lefthook"     # the commit-message and formatting hooks (lefthook.yml)
brew "xcodes"       # installs and selects the Xcode in .xcode-version

# Forward tools, used from M1 and M5
brew "xcodegen"     # generates the helper .app project from project.yml (M1)
brew "create-dmg"   # packages the notarized helper for distribution (M5)
