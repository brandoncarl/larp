# Homebrew release

The public [brandoncarl/homebrew-tap](https://github.com/brandoncarl/homebrew-tap) installs prebuilt LARP archives. It does not build Rust code on the user's machine or install Rust or LLVM.

1. Commit and push the source release, then push the matching `v0.1.4` tag. The [release workflow](../../.github/workflows/release.yml) builds and tests native arm64 and Intel binaries on separate macOS runners and publishes both archives with `SHA256SUMS` on the GitHub Release. Do not move a published tag.
2. Download both release archives and check their SHA-256 digests against the release's `SHA256SUMS`. Check that each archive contains `larp`, `README.md`, `QUICKSTART.md`, and `LICENSE`.
3. From the LARP source checkout, render the formula into a separate local checkout of `brandoncarl/homebrew-tap`:

   ```sh
   TAP_DIR=/absolute/path/to/homebrew-tap
   sh scripts/render-homebrew-formula.sh 0.1.4 ARM64_SHA256 INTEL_SHA256 > "$TAP_DIR/Formula/larp.rb"
   ```

4. Audit and test the formula. Install or upgrade it from the local tap checkout, then confirm `brew deps --include-build brandoncarl/tap/larp` has no dependencies. The formula must fetch the matching release archive and install its binary without running Cargo.
5. Commit and push `Formula/larp.rb` in the tap. Users install with `brew install brandoncarl/tap/larp` and upgrade with `brew upgrade brandoncarl/tap/larp`.

The formula installs the executable and documentation only. Users install the 1Password CLI and enable 1Password MCP separately. Homebrew does not create user configuration during installation: LARP creates its private `~/.config/larp/` directory when first used. Restart a running LARP server and reconnect MCP clients after upgrading.
