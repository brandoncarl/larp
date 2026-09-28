# Homebrew tap release

LARP's formula belongs in a separate `brandoncarl/homebrew-tap` repository as `Formula/larp.rb`. This directory holds its source template; the release archive checksum must come from the published tag.

1. Commit and push a release whose `Cargo.toml` version is `0.1.0`, then create and push tag `v0.1.0`. Do not move the tag after publishing the formula.
2. Download `https://github.com/brandoncarl/larp/archive/refs/tags/v0.1.0.tar.gz` and calculate its SHA-256 with `shasum -a 256`.
3. From this repository, render the formula into the tap checkout:

   ```sh
   mkdir -p /path/to/homebrew-tap/Formula
   sh scripts/render-homebrew-formula.sh 0.1.0 ACTUAL_SHA256 > /path/to/homebrew-tap/Formula/larp.rb
   ```

4. Tap the local checkout, audit the formula, and install it from source:

   ```sh
   brew tap brandoncarl/tap /path/to/homebrew-tap
   brew audit --new --formula brandoncarl/tap/larp
   HOMEBREW_NO_INSTALL_FROM_API=1 brew install --build-from-source brandoncarl/tap/larp
   larp help
   ```

   A pre-existing manual `larp` symlink in Homebrew's `bin` may conflict with linking; remove that symlink after checking where it points. Then commit and push `Formula/larp.rb` to `brandoncarl/homebrew-tap`.
5. Users can install with `brew install brandoncarl/tap/larp`. The formula builds from the tagged source and installs only the executable and documentation. Users install the 1Password CLI and enable 1Password MCP separately.

Homebrew does not create user configuration during installation. LARP creates `~/.config/larp/` when first used and checks that it is private to the current user. `larp start` creates its private runtime socket under `/private/tmp/larp-<uid>/`. Upgrading the Homebrew formula does not remove either directory. Restart the running LARP server and reconnect long-lived MCP bridges after an upgrade.
