# payload_packer

- CLI utility to pack Android device partitions as payload.bin.
---
⚠️ This tool is experimental.



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
          Comma-separated list of partition names to include (default: all)
      --method <METHOD>
          Compression method to use (xz or zstd) [default: xz] [possible values: xz, zstd]
      --threads <THREADS>
          Number of threads to use for parallel processing
      --block-size <BLOCK_SIZE>
          Block size in bytes [default: 4096]
      --skip-prop
          Skip creation of payload_properties.txt file
  -h, --help
          Print help
  -V, --version
          Print version
```

- ✅ Pack multiple partitions into a payload.bin

- ✅ Supports XZ and Zstd

- ✅ Multi-threaded compression


| Feature           | **XZ**                            | **Zstandard (zstd)**                |
|------------------|-----------------------------------|-------------------------------------|
| Compression Ratio| Higher                            | Slightly lower                      |
| Speed            | Slower (high compression time)    | Much faster (both compress & decompress) |


## Build
- Install cargo & rust compiler
```
git clone --depth 1 https://github.com/rhythmcache/payload_packer && cd payload_packer
cargo build --release
```



#### Dependencies :
- [Cargo.toml](./Cargo.toml)
- [update_metadata.proto](https://android.googlesource.com/platform/system/update_engine/+/HEAD/update_metadata.proto)



