# Homebrew tap release

LARP's formula belongs in the public [brandoncarl/homebrew-tap](https://github.com/brandoncarl/homebrew-tap) repository as `Formula/larp.rb`. Use a separate local checkout of that repository. This directory holds the formula template; its checksum must come from the published release archive.

1. Push the release commit on `main`, then create and push tag `v0.1.1` for the `0.1.1` version in `Cargo.toml`. Do not move the tag after publishing the formula.
2. Download the published source archive and calculate its SHA-256:

   ```sh
   curl -fL -o larp-v0.1.1.tar.gz https://github.com/brandoncarl/larp/archive/refs/tags/v0.1.1.tar.gz
   shasum -a 256 larp-v0.1.1.tar.gz
   ```
3. From this repository, set `TAP_DIR` to the absolute path of the tap checkout and render the formula:

   ```sh
   TAP_DIR=/absolute/path/to/homebrew-tap
   mkdir -p "$TAP_DIR/Formula"
   sh scripts/render-homebrew-formula.sh 0.1.1 ACTUAL_SHA256 > "$TAP_DIR/Formula/larp.rb"
   ```

4. Tap the local checkout, audit the formula, and install it from source:

   ```sh
   brew tap brandoncarl/tap "$TAP_DIR"
   brew audit --new --formula brandoncarl/tap/larp
   HOMEBREW_NO_INSTALL_FROM_API=1 brew install --build-from-source brandoncarl/tap/larp
   larp help
   ```

   A pre-existing manual `larp` symlink in Homebrew's `bin` may conflict with linking; remove that symlink after checking where it points. Then commit and push `Formula/larp.rb` to `brandoncarl/homebrew-tap`.
5. Users can install with `brew install brandoncarl/tap/larp`. The formula builds from the tagged source and installs only the executable and documentation. Users install the 1Password CLI and enable 1Password MCP separately.

Homebrew does not create user configuration during installation. LARP creates `~/.config/larp/` when first used and checks that it is private to the current user. `larp start` creates its private runtime socket under `/private/tmp/larp-<uid>/`. Upgrading the Homebrew formula does not remove either directory. Restart the running LARP server and reconnect long-lived MCP bridges after an upgrade.
