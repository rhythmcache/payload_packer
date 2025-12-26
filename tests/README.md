## Testing & Validation

This directory contains an end-to-end proof-of-concept test script (`test.sh`) for `payload_packer`.

The script is intended to run on **Linux x86_64** and assumes the following tools are installed:
- Rust and Cargo
- `wget`
- `bc`

For other platforms or environments, the script can be adapted accordingly.

## What the Test Does

The test script performs the following steps:

- Downloads official Google AOSP OTA packages
- Extracts partition images using [`payload_dumper`](https://github.com/rhythmcache/payload-dumper-rust)
- Generates **full** and **incremental (delta)** OTA payloads using `payload_packer`
- Re-extracts the generated payloads
- Verifies correctness by comparing **SHA-256 hashes** of the original and extracted images

## Validation Guarantees

A successful test run confirms that:

- Full payloads reproduce target images **bit-for-bit**
- Incremental (delta) payloads correctly reconstruct target images when applied over source images
- All extracted partition hashes match the originals exactly
