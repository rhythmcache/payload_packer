# payload_packer

- CLI utility to pack Android device partitions as payload.bin.
---
- This tool is experimental.



# Usage
```
Usage: payload_packer [OPTIONS] [IMAGES_DIR]

Arguments:
  [IMAGES_DIR]
          Directory containing image files to pack

Options:
      --out <OUT>
          Path to the output payload.bin file (default: output/payload.bin)
      --images-path <IMAGES_PATH>
          Specific image paths (can be used instead of or together with images_dir)
      --images <IMAGES>
          Comma-separated list of partition names to include (default: all) [default: ]
      --method <METHOD>
          Compression method to use (xz, zstd, or bz2) [default: xz] [possible values: xz, zstd, bz2]
      --threads <THREADS>
          Number of threads to use for parallel processing
      --block-size <BLOCK_SIZE>
          Block size in bytes [default: 4096]
      --skip-prop
          Skip creation of payload_properties.txt file
      --chunk-size <CHUNK_SIZE>
          Target chunk size per operation in bytes (default: 2MB = 2097152) [default: 2097152]
  -h, --help
          Print help
  -V, --version
          Print version
```

-  Pack multiple partitions into a payload.bin

-  Supports XZ, Zstd and bz2

-  Multi-threaded compression


| Feature           | **XZ**                            | **Zstandard (zstd)**                |
|------------------|-----------------------------------|-------------------------------------|
| Compression Ratio| Higher                            | Slightly lower                      |
| Speed            | Slower (high compression time)    | Much faster (both compress & decompress) |



## Note:
**This tool does not verify whether input `.img` files are valid Android partition images.**  
It will pack any files with a `.img` extension.

## Build
- Install Cargo & Rust Compiler

```
cargo install payload_packer
```
- [Download prebuilt Binaries](https://github.com/rhythmcache/payload_packer/releases)


#### Dependencies :
- [Cargo.toml](./Cargo.toml)
- [update_metadata.proto](https://android.googlesource.com/platform/system/update_engine/+/HEAD/update_metadata.proto)



