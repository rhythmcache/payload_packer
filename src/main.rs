use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use byteorder::{BigEndian, WriteBytesExt};
use clap::Parser;
use digest::Digest;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use payload_dumper::structs::*;
use payload_dumper::utils::{format_elapsed_time, format_size};
use prost::Message;
use rayon::prelude::*;
use sha2::Sha256;
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const PAYLOAD_MAGIC: &[u8] = b"CrAU";
const PAYLOAD_VERSION: u64 = 2;
// const MMAP_THRESHOLD: u64 = 400 * 1024 * 1024;

#[derive(Parser, Clone)]
#[command(
    version,
    about = "A standalone tool for generating full and incremental Android OTA payloads for A/B devices."
)]
#[command(next_line_help = true)]
struct Args {
    #[arg(
        short = 'o',
        long = "output",
        help = "Path to the output payload.bin file (default: output/payload.bin)"
    )]
    output: Option<PathBuf>,

    #[arg(
        short = 't',
        long = "target-dir",
        help = "Directory containing target (new) .img files"
    )]
    target_dir: Option<PathBuf>,

    #[arg(
        long = "target-image",
        help = "Individual target image file (can be specified multiple times)",
        action = clap::ArgAction::Append
    )]
    target_images: Vec<PathBuf>,

    #[arg(
        long = "delta",
        help = "Generate a delta (differential) payload instead of full payload"
    )]
    delta: bool,

    #[arg(
        short = 's',
        long = "source-dir",
        help = "Directory containing source (old) .img files (required for delta payloads)",
        required_if_eq("delta", "true")
    )]
    source_dir: Option<PathBuf>,

    #[arg(
        long = "source-image",
        help = "Individual source image file (can be specified multiple times)",
        action = clap::ArgAction::Append
    )]
    source_images: Vec<PathBuf>,

    #[arg(
        short = 'p',
        long = "partitions",
        help = "Comma-separated list of partition names to include (e.g., system,vendor,boot)",
        value_delimiter = ','
    )]
    partition_filter: Vec<String>,

    #[arg(
        short = 'm',
        long = "method",
        default_value = "xz",
        value_parser = ["xz", "zstd", "bz2"],
        help = "Compression method: xz (LZMA2), zstd (Zstandard), or bz2 (bzip2)"
    )]
    compression_method: String,

    #[arg(
        short = 'l',
        long = "level",
        help = "Compression level (xz: 0-9, zstd: 1-22, bz2: 1-9)"
    )]
    compression_level: Option<i32>,

    #[arg(
        long = "threads",
        help = "Number of threads for parallel processing (default: CPU cores)"
    )]
    threads: Option<usize>,

    #[arg(
        short = 'b',
        long = "block-size",
        default_value = "4096",
        help = "Block size in bytes"
    )]
    block_size: u32,

    #[arg(
        long = "skip-properties",
        help = "Skip creation of payload_properties.txt file"
    )]
    skip_properties: bool,

    #[arg(
        short = 'c',
        long = "chunk-size",
        default_value = "2097152",
        help = "Target chunk size per operation in bytes (default: 2MB)"
    )]
    chunk_size: u64,

    #[arg(
        long = "mmap-threshold",
        default_value = "419430400",
        help = "File size threshold for using memory mapping (default: 400MB)"
    )]
    mmap_threshold: u64,
}

#[derive(Clone)]
struct ImageInfo {
    path: PathBuf,
    name: String,
    size: u64,
    hash: Vec<u8>,
}

struct DeltaImagePair {
    source: ImageInfo,
    target: ImageInfo,
}

struct TempFileManager {
    temp_dir: TempDir,
    file_counter: std::sync::atomic::AtomicUsize,
}

impl TempFileManager {
    fn new() -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix("payload_builder_")
            .tempdir()
            .context("Failed to create temporary directory")?;

        Ok(Self {
            temp_dir,
            file_counter: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn create_temp_file(&self, data: &[u8]) -> Result<PathBuf> {
        let file_id = self
            .file_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let temp_path = self.temp_dir.path().join(format!("chunk_{}", file_id));
        fs::write(&temp_path, data)
            .with_context(|| format!("Failed to write temporary file: {:?}", temp_path))?;
        Ok(temp_path)
    }
}

enum FileReader {
    Mmap(Mmap),
    Buffered(BufReader<File>),
}

impl FileReader {
    fn new(path: &Path, mmap_threshold: u64) -> Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();

        if size > mmap_threshold {
            let mmap = unsafe { Mmap::map(&file)? };
            Ok(FileReader::Mmap(mmap))
        } else {
            Ok(FileReader::Buffered(BufReader::new(file)))
        }
    }

    fn read_chunk(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        match self {
            FileReader::Mmap(mmap) => {
                let end = (offset as usize + size).min(mmap.len());
                Ok(mmap[offset as usize..end].to_vec())
            }
            FileReader::Buffered(reader) => {
                reader.seek(SeekFrom::Start(offset))?;
                let mut buffer = vec![0u8; size];
                let bytes_read = reader.read(&mut buffer)?;
                buffer.truncate(bytes_read);
                Ok(buffer)
            }
        }
    }
}

thread_local! {
    static XZ_ENCODER_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4 * 1024 * 1024));
    static BZ2_ENCODER_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4 * 1024 * 1024));
    static ZSTD_ENCODER_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4 * 1024 * 1024));
}

fn calculate_hash(reader: &mut FileReader) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    match reader {
        FileReader::Mmap(mmap) => {
            hasher.update(&mmap);
        }
        FileReader::Buffered(buf_reader) => {
            buf_reader.seek(SeekFrom::Start(0))?;
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let bytes_read = buf_reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
        }
    }
    Ok(hasher.finalize().to_vec())
}

fn calculate_hash_from_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn get_compression_level(method: &str, user_level: Option<i32>) -> i32 {
    if let Some(level) = user_level {
        return level;
    }

    match method {
        "xz" => 9,
        "zstd" => 22,
        "bz2" | "bzip2" => 9,
        _ => 9,
    }
}

fn compress_data(data: &[u8], compression_method: &str, level: i32) -> Result<Vec<u8>> {
    match compression_method {
        "xz" => {
            use liblzma::write::XzEncoder;
            let level = level.clamp(0, 9) as u32;

            XZ_ENCODER_BUFFER.with(|buffer| {
                let mut buf = buffer.borrow_mut();
                buf.clear();

                let mut encoder = XzEncoder::new(&mut *buf, level);
                encoder
                    .write_all(data)
                    .context("Failed to write to XZ encoder")?;
                encoder
                    .finish()
                    .context("Failed to finish XZ compression")?;

                Ok(std::mem::take(&mut *buf))
            })
        }
        "bz2" | "bzip2" => {
            use bzip2::Compression;
            use bzip2::write::BzEncoder;
            let level = level.clamp(1, 9) as u32;
            let compression = Compression::new(level);

            BZ2_ENCODER_BUFFER.with(|buffer| {
                let mut buf = buffer.borrow_mut();
                buf.clear();

                let mut encoder = BzEncoder::new(&mut *buf, compression);
                encoder
                    .write_all(data)
                    .context("Failed to write to BZ2 encoder")?;
                encoder
                    .finish()
                    .context("Failed to finish BZ2 compression")?;

                Ok(std::mem::take(&mut *buf))
            })
        }
        "zstd" => {
            let level = level.clamp(1, 22);

            ZSTD_ENCODER_BUFFER.with(|buffer| {
                let mut buf = buffer.borrow_mut();
                buf.clear();

                let mut encoder = zstd::Encoder::new(&mut *buf, level)
                    .context("Failed to create Zstd encoder")?;
                encoder
                    .write_all(data)
                    .context("Failed to write to Zstd encoder")?;
                encoder
                    .finish()
                    .context("Failed to finish Zstd compression")?;

                Ok(std::mem::take(&mut *buf))
            })
        }
        _ => Err(anyhow!(
            "Unsupported compression method: {}",
            compression_method
        )),
    }
}

fn get_operation_type(compression_method: &str) -> install_operation::Type {
    match compression_method {
        "xz" => install_operation::Type::ReplaceXz,
        "bz2" | "bzip2" => install_operation::Type::ReplaceBz,
        "zstd" => install_operation::Type::Zstd,
        _ => install_operation::Type::Replace,
    }
}

fn is_zero_block(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

fn blocks_equal(block1: &[u8], block2: &[u8]) -> bool {
    block1 == block2
}

fn create_delta_operations(
    source_path: &Path,
    target_path: &Path,
    source_size: u64,
    target_size: u64,
    _source_hash: &[u8],
    block_size: u32,
    compression_method: &str,
    compression_level: i32,
    target_chunk_size: u64,
    temp_manager: &TempFileManager,
    mmap_threshold: u64,
) -> Result<Vec<(InstallOperation, PathBuf, u64)>> {
    let mut operations = Vec::new();

    let chunk_size =
        ((target_chunk_size + block_size as u64 - 1) / block_size as u64) * block_size as u64;

    let mut source_reader = FileReader::new(source_path, mmap_threshold)?;
    let mut target_reader = FileReader::new(target_path, mmap_threshold)?;

    let mut target_offset = 0u64;
    let mut current_block = 0u64;

    while target_offset < target_size {
        let remaining = target_size - target_offset;
        let this_chunk_size = remaining.min(chunk_size);

        let mut target_chunk = target_reader.read_chunk(target_offset, this_chunk_size as usize)?;

        let aligned_size =
            ((this_chunk_size + block_size as u64 - 1) / block_size as u64) * block_size as u64;
        if aligned_size as usize > target_chunk.len() {
            target_chunk.resize(aligned_size as usize, 0);
        }

        let num_blocks = aligned_size / block_size as u64;

        if is_zero_block(&target_chunk) {
            let operation = InstallOperation {
                r#type: install_operation::Type::Zero as i32,
                data_offset: None,
                data_length: None,
                src_extents: Vec::new(),
                src_length: None,
                dst_extents: vec![Extent {
                    start_block: Some(current_block),
                    num_blocks: Some(num_blocks),
                }],
                dst_length: Some(aligned_size),
                data_sha256_hash: None,
                src_sha256_hash: None,
            };

            operations.push((operation, PathBuf::new(), 0));
        } else if target_offset < source_size {
            let source_chunk_size = (source_size - target_offset).min(this_chunk_size);
            let mut source_chunk =
                source_reader.read_chunk(target_offset, source_chunk_size as usize)?;

            source_chunk.resize(aligned_size as usize, 0);

            if blocks_equal(&source_chunk, &target_chunk) {
                let src_hash = calculate_hash_from_data(&source_chunk);

                let operation = InstallOperation {
                    r#type: install_operation::Type::SourceCopy as i32,
                    data_offset: None,
                    data_length: None,
                    src_extents: vec![Extent {
                        start_block: Some(current_block),
                        num_blocks: Some(num_blocks),
                    }],
                    src_length: Some(aligned_size),
                    dst_extents: vec![Extent {
                        start_block: Some(current_block),
                        num_blocks: Some(num_blocks),
                    }],
                    dst_length: Some(aligned_size),
                    data_sha256_hash: None,
                    src_sha256_hash: Some(src_hash),
                };

                operations.push((operation, PathBuf::new(), 0));
            } else {
                let mut patch_data = Vec::new();
                bsdiff_android::diff(&source_chunk, &target_chunk, &mut patch_data)
                    .context("Failed to generate bsdiff patch")?;

                let use_bsdiff = patch_data.len() < (aligned_size as usize * 3 / 4);

                if use_bsdiff {
                    let patch_hash = calculate_hash_from_data(&patch_data);
                    let src_hash = calculate_hash_from_data(&source_chunk);
                    let temp_path = temp_manager.create_temp_file(&patch_data)?;

                    let operation = InstallOperation {
                        r#type: install_operation::Type::SourceBsdiff as i32,
                        data_offset: Some(0),
                        data_length: Some(patch_data.len() as u64),
                        src_extents: vec![Extent {
                            start_block: Some(current_block),
                            num_blocks: Some(num_blocks),
                        }],
                        src_length: Some(aligned_size),
                        dst_extents: vec![Extent {
                            start_block: Some(current_block),
                            num_blocks: Some(num_blocks),
                        }],
                        dst_length: Some(aligned_size),
                        data_sha256_hash: Some(patch_hash),
                        src_sha256_hash: Some(src_hash),
                    };

                    operations.push((operation, temp_path, patch_data.len() as u64));
                } else {
                    let compressed_target =
                        compress_data(&target_chunk, compression_method, compression_level)?;
                    let hash = calculate_hash_from_data(&compressed_target);
                    let temp_path = temp_manager.create_temp_file(&compressed_target)?;

                    let operation = InstallOperation {
                        r#type: get_operation_type(compression_method) as i32,
                        data_offset: Some(0),
                        data_length: Some(compressed_target.len() as u64),
                        src_extents: Vec::new(),
                        src_length: None,
                        dst_extents: vec![Extent {
                            start_block: Some(current_block),
                            num_blocks: Some(num_blocks),
                        }],
                        dst_length: Some(aligned_size),
                        data_sha256_hash: Some(hash),
                        src_sha256_hash: None,
                    };

                    operations.push((operation, temp_path, compressed_target.len() as u64));
                }
            }
        } else {
            let compressed_target =
                compress_data(&target_chunk, compression_method, compression_level)?;
            let hash = calculate_hash_from_data(&compressed_target);
            let temp_path = temp_manager.create_temp_file(&compressed_target)?;

            let operation = InstallOperation {
                r#type: get_operation_type(compression_method) as i32,
                data_offset: Some(0),
                data_length: Some(compressed_target.len() as u64),
                src_extents: Vec::new(),
                src_length: None,
                dst_extents: vec![Extent {
                    start_block: Some(current_block),
                    num_blocks: Some(num_blocks),
                }],
                dst_length: Some(aligned_size),
                data_sha256_hash: Some(hash),
                src_sha256_hash: None,
            };

            operations.push((operation, temp_path, compressed_target.len() as u64));
        }

        target_offset += this_chunk_size;
        current_block += num_blocks;
    }

    Ok(operations)
}

fn create_full_operations(
    image_path: &Path,
    image_size: u64,
    block_size: u32,
    compression_method: &str,
    compression_level: i32,
    target_chunk_size: u64,
    temp_manager: &TempFileManager,
    mmap_threshold: u64,
) -> Result<Vec<(InstallOperation, PathBuf, u64)>> {
    let mut operations = Vec::new();

    let chunk_size =
        ((target_chunk_size + block_size as u64 - 1) / block_size as u64) * block_size as u64;

    let mut reader = FileReader::new(image_path, mmap_threshold)?;
    let mut offset = 0u64;
    let mut current_block = 0u64;

    while offset < image_size {
        let remaining = image_size - offset;
        let this_chunk_size = remaining.min(chunk_size);

        let mut chunk_data = reader.read_chunk(offset, this_chunk_size as usize)?;

        let aligned_size =
            ((this_chunk_size + block_size as u64 - 1) / block_size as u64) * block_size as u64;
        if aligned_size as usize > chunk_data.len() {
            chunk_data.resize(aligned_size as usize, 0);
        }

        let compressed_data = compress_data(&chunk_data, compression_method, compression_level)?;
        let hash = calculate_hash_from_data(&compressed_data);
        let temp_file_path = temp_manager.create_temp_file(&compressed_data)?;

        let compressed_size = compressed_data.len() as u64;
        let num_blocks = aligned_size / block_size as u64;

        let operation = InstallOperation {
            r#type: get_operation_type(compression_method) as i32,
            data_offset: Some(0),
            data_length: Some(compressed_size),
            src_extents: Vec::new(),
            src_length: None,
            dst_extents: vec![Extent {
                start_block: Some(current_block),
                num_blocks: Some(num_blocks),
            }],
            dst_length: Some(aligned_size),
            data_sha256_hash: Some(hash),
            src_sha256_hash: None,
        };

        operations.push((operation, temp_file_path, compressed_size));

        offset += this_chunk_size;
        current_block += num_blocks;
    }

    Ok(operations)
}

fn find_image_files(
    dir: Option<&PathBuf>,
    individual_images: &[PathBuf],
    partition_filter: &[String],
    label: &str,
    mmap_threshold: u64,
) -> Result<Vec<ImageInfo>> {
    let mut image_paths = Vec::new();
    let mut seen_names = AHashSet::new();
    let filter_set: AHashSet<String> = partition_filter.iter().cloned().collect();

    if let Some(images_dir) = dir {
        if !images_dir.exists() || !images_dir.is_dir() {
            return Err(anyhow!(
                "{} directory does not exist: {}",
                label,
                images_dir.display()
            ));
        }

        for entry in fs::read_dir(images_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "img") {
                let name = path
                    .file_stem()
                    .ok_or_else(|| anyhow!("Invalid filename: {}", path.display()))?
                    .to_string_lossy()
                    .to_string();

                if !filter_set.is_empty() && !filter_set.contains(&name) {
                    continue;
                }

                if seen_names.insert(name.clone()) {
                    image_paths.push((path, name));
                }
            }
        }
    }

    for path in individual_images {
        if !path.exists() || !path.is_file() {
            return Err(anyhow!("Image file does not exist: {}", path.display()));
        }

        let name = path
            .file_stem()
            .ok_or_else(|| anyhow!("Invalid filename: {}", path.display()))?
            .to_string_lossy()
            .to_string();

        if !filter_set.is_empty() && !filter_set.contains(&name) {
            continue;
        }

        if seen_names.insert(name.clone()) {
            image_paths.push((path.clone(), name));
        }
    }

    if image_paths.is_empty() {
        return Err(anyhow!("No {} image files found", label));
    }

    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new_spinner());
    main_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    main_pb.enable_steady_tick(Duration::from_millis(100));
    main_pb.set_message(format!(
        "Processing {} {} image files...",
        image_paths.len(),
        label
    ));

    let progress_map: AHashMap<String, ProgressBar> = image_paths
        .iter()
        .map(|(_, name)| {
            let pb = multi_progress.add(ProgressBar::new_spinner());
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap(),
            );
            pb.enable_steady_tick(Duration::from_millis(100));
            pb.set_message(format!("Queuing {}", name));
            (name.clone(), pb)
        })
        .collect();

    let image_infos: Vec<_> = image_paths
        .par_iter()
        .map(|(path, name)| {
            let pb = progress_map.get(name);

            if let Some(pb) = &pb {
                pb.set_message(format!("Processing {}", name));
            }

            let size = fs::metadata(path)?.len();
            let mut reader = FileReader::new(path, mmap_threshold)?;
            let hash = calculate_hash(&mut reader)?;

            if let Some(pb) = pb {
                pb.finish_with_message(format!(
                    "[OK] {} ({}, {} bytes)",
                    name,
                    format_size(size),
                    size
                ));
            }

            Ok(ImageInfo {
                path: path.clone(),
                name: name.clone(),
                size,
                hash,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    main_pb.finish_with_message(format!(
        "Processed {} {} image files",
        image_infos.len(),
        label
    ));

    Ok(image_infos)
}

fn match_delta_pairs(
    source_images: Vec<ImageInfo>,
    target_images: Vec<ImageInfo>,
) -> Result<Vec<DeltaImagePair>> {
    let mut pairs = Vec::new();
    let source_map: AHashMap<String, ImageInfo> = source_images
        .into_iter()
        .map(|img| (img.name.clone(), img))
        .collect();

    for target in target_images {
        if let Some(source) = source_map.get(&target.name) {
            pairs.push(DeltaImagePair {
                source: source.clone(),
                target,
            });
        } else {
            return Err(anyhow!(
                "No matching source image found for target partition: {}",
                target.name
            ));
        }
    }

    Ok(pairs)
}

fn create_payload_properties(
    payload_path: &Path,
    manifest_data: &[u8],
    manifest_size: u64,
    mmap_threshold: u64,
) -> Result<()> {
    let properties_path = payload_path.with_file_name("payload_properties.txt");
    let mut file = File::create(&properties_path)?;

    let file_size = fs::metadata(payload_path)?.len();
    let mut reader = FileReader::new(payload_path, mmap_threshold)?;
    let file_hash = calculate_hash(&mut reader)?;

    let metadata_hash = calculate_hash_from_data(manifest_data);

    writeln!(file, "FILE_HASH={}", STANDARD.encode(&file_hash))?;
    writeln!(file, "FILE_SIZE={}", file_size)?;
    writeln!(file, "METADATA_HASH={}", STANDARD.encode(&metadata_hash))?;
    writeln!(file, "METADATA_SIZE={}", manifest_size)?;

    println!("Created payload properties: {}", properties_path.display());
    Ok(())
}

fn create_full_partition_update(
    image_info: &ImageInfo,
    args: &Args,
    temp_manager: &TempFileManager,
    multi_progress: &MultiProgress,
) -> Result<(PartitionUpdate, Vec<PathBuf>, u64)> {
    let compression_level = get_compression_level(&args.compression_method, args.compression_level);

    let expected_ops = (image_info.size + args.chunk_size - 1) / args.chunk_size;
    let pb = multi_progress.add(ProgressBar::new_spinner());
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message(format!(
        "Creating full update for {} (~{} ops @ {})",
        image_info.name,
        expected_ops,
        format_size(args.chunk_size)
    ));

    let operations_data = create_full_operations(
        &image_info.path,
        image_info.size,
        args.block_size,
        &args.compression_method,
        compression_level,
        args.chunk_size,
        temp_manager,
        args.mmap_threshold,
    )?;

    let mut install_ops = Vec::new();
    let mut temp_paths = Vec::new();
    let mut total_compressed = 0u64;

    for (op, path, size) in operations_data {
        install_ops.push(op);
        if !path.as_os_str().is_empty() {
            temp_paths.push(path);
        }
        total_compressed += size;
    }

    let partition_info = PartitionInfo {
        size: Some(image_info.size),
        hash: Some(image_info.hash.clone()),
    };

    let partition_update = PartitionUpdate {
        partition_name: image_info.name.clone(),
        run_postinstall: None,
        postinstall_path: None,
        filesystem_type: None,
        new_partition_signature: Vec::new(),
        old_partition_info: None,
        new_partition_info: Some(partition_info),
        operations: install_ops,
        postinstall_optional: None,
        hash_tree_data_extent: None,
        hash_tree_extent: None,
        hash_tree_algorithm: None,
        hash_tree_salt: None,
        fec_data_extent: None,
        fec_extent: None,
        fec_roots: None,
        version: None,
        merge_operations: Vec::new(),
        estimate_cow_size: None,
        estimate_op_count_max: None,
    };

    pb.finish_with_message(format!(
        "[OK] {} ({} ops, {} -> {}, {:.1}% compression)",
        image_info.name,
        partition_update.operations.len(),
        format_size(image_info.size),
        format_size(total_compressed),
        (total_compressed as f64 / image_info.size as f64) * 100.0
    ));

    Ok((partition_update, temp_paths, total_compressed))
}

fn create_delta_partition_update(
    pair: &DeltaImagePair,
    args: &Args,
    temp_manager: &TempFileManager,
    multi_progress: &MultiProgress,
) -> Result<(PartitionUpdate, Vec<PathBuf>, u64)> {
    let compression_level = get_compression_level(&args.compression_method, args.compression_level);

    let expected_ops = (pair.target.size + args.chunk_size - 1) / args.chunk_size;
    let pb = multi_progress.add(ProgressBar::new_spinner());
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message(format!(
        "Creating delta update for {} (~{} ops @ {})",
        pair.target.name,
        expected_ops,
        format_size(args.chunk_size)
    ));

    let operations_data = create_delta_operations(
        &pair.source.path,
        &pair.target.path,
        pair.source.size,
        pair.target.size,
        &pair.source.hash,
        args.block_size,
        &args.compression_method,
        compression_level,
        args.chunk_size,
        temp_manager,
        args.mmap_threshold,
    )?;

    let mut install_ops = Vec::new();
    let mut temp_paths = Vec::new();
    let mut total_compressed = 0u64;

    for (op, path, size) in operations_data {
        install_ops.push(op);
        if !path.as_os_str().is_empty() {
            temp_paths.push(path);
        }
        total_compressed += size;
    }

    let old_partition_info = PartitionInfo {
        size: Some(pair.source.size),
        hash: Some(pair.source.hash.clone()),
    };

    let new_partition_info = PartitionInfo {
        size: Some(pair.target.size),
        hash: Some(pair.target.hash.clone()),
    };

    let partition_update = PartitionUpdate {
        partition_name: pair.target.name.clone(),
        run_postinstall: None,
        postinstall_path: None,
        filesystem_type: None,
        new_partition_signature: Vec::new(),
        old_partition_info: Some(old_partition_info),
        new_partition_info: Some(new_partition_info),
        operations: install_ops,
        postinstall_optional: None,
        hash_tree_data_extent: None,
        hash_tree_extent: None,
        hash_tree_algorithm: None,
        hash_tree_salt: None,
        fec_data_extent: None,
        fec_extent: None,
        fec_roots: None,
        version: None,
        merge_operations: Vec::new(),
        estimate_cow_size: None,
        estimate_op_count_max: None,
    };

    pb.finish_with_message(format!(
        "[OK] {} ({} ops, {} -> {}, {:.1}% of target)",
        pair.target.name,
        partition_update.operations.len(),
        format_size(pair.target.size),
        format_size(total_compressed),
        (total_compressed as f64 / pair.target.size as f64) * 100.0
    ));

    Ok((partition_update, temp_paths, total_compressed))
}

fn pack_payload(args: &Args) -> Result<()> {
    let start_time = Instant::now();
    let temp_manager = TempFileManager::new()?;
    let multi_progress = MultiProgress::new();

    let compression_level = get_compression_level(&args.compression_method, args.compression_level);

    let main_pb = multi_progress.add(ProgressBar::new_spinner());
    main_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    main_pb.enable_steady_tick(Duration::from_millis(100));

    println!("\n========================================");
    println!("Android Payload Generator");
    println!("========================================");
    println!("Mode: {}", if args.delta { "DELTA" } else { "FULL" });
    println!("Memory-map threshold: {}", format_size(args.mmap_threshold));
    if args.delta {
        println!(
            "Compression: {} (level {}) for REPLACE ops",
            args.compression_method, compression_level
        );
        println!("             BZ2 for BSDIFF ops");
    } else {
        println!(
            "Compression: {} (level {})",
            args.compression_method, compression_level
        );
    }

    println!("Block size: {} bytes", args.block_size);
    println!("Chunk size: {}", format_size(args.chunk_size));
    println!("========================================\n");

    main_pb.set_message("Loading target images...");

    let target_images = find_image_files(
        args.target_dir.as_ref(),
        &args.target_images,
        &args.partition_filter,
        "target",
        args.mmap_threshold,
    )?;

    if target_images.is_empty() {
        return Err(anyhow!("No target images found"));
    }

    let mut partition_updates = Vec::new();
    let mut all_temp_files = Vec::new();
    let mut total_compressed_size = 0u64;

    if args.delta {
        main_pb.set_message("Loading source images...");

        let source_images = find_image_files(
            args.source_dir.as_ref(),
            &args.source_images,
            &args.partition_filter,
            "source",
            args.mmap_threshold,
        )?;

        if source_images.is_empty() {
            return Err(anyhow!("No source images found for delta payload"));
        }

        main_pb.set_message("Matching source and target partitions...");
        let delta_pairs = match_delta_pairs(source_images, target_images)?;
        println!("Matched {} partition pairs\n", delta_pairs.len());

        main_pb.set_message("Creating delta operations...");

        let results: Vec<_> = delta_pairs
            .par_iter()
            .map(|pair| create_delta_partition_update(pair, args, &temp_manager, &multi_progress))
            .collect::<Result<Vec<_>>>()?;

        for (update, temp_paths, compressed_size) in results {
            partition_updates.push(update);
            all_temp_files.extend(temp_paths);
            total_compressed_size += compressed_size;
        }
    } else {
        main_pb.set_message("Creating full operations...");

        let results: Vec<_> = target_images
            .par_iter()
            .map(|image_info| {
                create_full_partition_update(image_info, args, &temp_manager, &multi_progress)
            })
            .collect::<Result<Vec<_>>>()?;

        for (update, temp_paths, compressed_size) in results {
            partition_updates.push(update);
            all_temp_files.extend(temp_paths);
            total_compressed_size += compressed_size;
        }
    }

    main_pb.set_message("Building manifest...");

    let dynamic_partition_metadata = if !partition_updates.is_empty() {
        let partition_names = partition_updates
            .iter()
            .map(|update| update.partition_name.clone())
            .collect();

        Some(DynamicPartitionMetadata {
            groups: vec![DynamicPartitionGroup {
                name: "default".to_string(),
                size: None,
                partition_names,
            }],
            snapshot_enabled: Some(true),
            vabc_enabled: Some(true),
            vabc_compression_param: Some(args.compression_method.clone()),
            cow_version: Some(2),
            vabc_feature_set: Some(VabcFeatureSet {
                threaded: Some(true),
                batch_writes: Some(true),
            }),
            compression_factor: None,
        })
    } else {
        None
    };

    let manifest = DeltaArchiveManifest {
        block_size: Some(args.block_size),
        signatures_offset: None,
        signatures_size: None,
        minor_version: Some(0),
        partitions: partition_updates,
        max_timestamp: None,
        dynamic_partition_metadata,
        partial_update: Some(!args.delta),
        apex_info: Vec::new(),
        security_patch_level: None,
    };

    main_pb.set_message("Updating operation offsets...");
    let mut current_offset = 0u64;
    let mut file_idx = 0;
    let mut manifest_with_offsets = manifest.clone();

    for partition in &mut manifest_with_offsets.partitions {
        for op in &mut partition.operations {
            if op.data_length.is_some() && op.data_length.unwrap() > 0 {
                op.data_offset = Some(current_offset);
                let file_size = fs::metadata(&all_temp_files[file_idx])?.len();
                current_offset += file_size;
                file_idx += 1;
            }
        }
    }

    let final_manifest = manifest_with_offsets.encode_to_vec();

    main_pb.set_message("Writing payload file...");
    let output_path = args.output.as_ref().unwrap();
    let output_file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;
    let mut writer = BufWriter::new(output_file);

    writer.write_all(PAYLOAD_MAGIC)?;
    writer.write_u64::<BigEndian>(PAYLOAD_VERSION)?;
    writer.write_u64::<BigEndian>(final_manifest.len() as u64)?;
    writer.write_u32::<BigEndian>(0)?;
    writer.write_all(&final_manifest)?;

    let write_pb = multi_progress.add(ProgressBar::new(all_temp_files.len() as u64));
    write_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/white}] {pos}/{len} blobs - {msg}")
            .unwrap()
            .progress_chars("=>-")
    );
    write_pb.set_message("Writing data blobs");

    for (i, temp_path) in all_temp_files.iter().enumerate() {
        let mut reader = BufReader::new(File::open(temp_path)?);
        std::io::copy(&mut reader, &mut writer)
            .with_context(|| format!("Failed to write blob {}/{}", i + 1, all_temp_files.len()))?;
        write_pb.set_position((i + 1) as u64);
    }

    write_pb.finish_with_message("All blobs written");
    writer.flush()?;

    let elapsed_time = format_elapsed_time(start_time.elapsed());
    let output_size = fs::metadata(output_path)?.len();

    let total_input_size: u64 = manifest
        .partitions
        .iter()
        .filter_map(|p| p.new_partition_info.as_ref())
        .filter_map(|info| info.size)
        .sum();

    let total_ops: usize = manifest.partitions.iter().map(|p| p.operations.len()).sum();

    let mut op_type_counts: AHashMap<String, usize> = AHashMap::new();
    if args.delta {
        for partition in &manifest.partitions {
            for op in &partition.operations {
                let op_type_name = match install_operation::Type::try_from(op.r#type) {
                    Ok(install_operation::Type::Zero) => "ZERO",
                    Ok(install_operation::Type::SourceCopy) => "SOURCE_COPY",
                    Ok(install_operation::Type::SourceBsdiff) => "SOURCE_BSDIFF",
                    Ok(install_operation::Type::ReplaceXz) => "REPLACE_XZ",
                    Ok(install_operation::Type::ReplaceBz) => "REPLACE_BZ",
                    Ok(install_operation::Type::Zstd) => "REPLACE_ZSTD",
                    _ => "OTHER",
                };
                *op_type_counts.entry(op_type_name.to_string()).or_insert(0) += 1;
            }
        }
    }

    main_pb.finish_with_message("Payload creation complete!");

    println!("\n========================================");
    println!("Payload Generation Summary");
    println!("========================================");
    println!(
        "Mode: {}",
        if args.delta {
            "DELTA (Differential)"
        } else {
            "FULL"
        }
    );
    println!("Completed in: {}", elapsed_time);
    println!("Output file: {}", output_path.display());
    println!(
        "Output size: {} ({} bytes)",
        format_size(output_size),
        output_size
    );

    if args.delta {
        println!(
            "Payload size vs target: {:.2}%",
            (output_size as f64 / total_input_size as f64) * 100.0
        );
        println!(
            "Space saved: {}",
            format_size(total_input_size.saturating_sub(output_size))
        );
    } else {
        println!(
            "Compression ratio: {:.2}%",
            (output_size as f64 / total_input_size as f64) * 100.0
        );
    }

    println!(
        "Total input size: {} ({} bytes)",
        format_size(total_input_size),
        total_input_size
    );
    println!(
        "Total compressed size: {}",
        format_size(total_compressed_size)
    );

    if args.delta {
        println!(
            "Compression: {} (level {}) for REPLACE ops, BZ2 for BSDIFF ops",
            args.compression_method, compression_level
        );
    } else {
        println!(
            "Compression method: {} (level {})",
            args.compression_method, compression_level
        );
    }

    println!("Block size: {} bytes", args.block_size);
    println!("Chunk size: {}", format_size(args.chunk_size));
    println!("Total operations: {}", total_ops);
    println!("Partitions: {}", manifest.partitions.len());

    if args.delta && !op_type_counts.is_empty() {
        println!("\nOperation type breakdown:");
        let mut sorted_ops: Vec<_> = op_type_counts.iter().collect();
        sorted_ops.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

        for (op_type, count) in sorted_ops {
            let compression_info = match op_type.as_str() {
                "SOURCE_BSDIFF" => " (uses internal BZ2)",
                "REPLACE_XZ" => &format!(" (uses {})", args.compression_method),
                "REPLACE_BZ" => " (uses BZ2)",
                "REPLACE_ZSTD" => " (uses ZSTD)",
                _ => "",
            };
            println!(
                "  {}{}: {} ({:.1}%)",
                op_type,
                compression_info,
                count,
                (*count as f64 / total_ops as f64) * 100.0
            );
        }
    }

    println!("========================================");

    if !args.skip_properties {
        create_payload_properties(
            output_path,
            &final_manifest,
            final_manifest.len() as u64,
            args.mmap_threshold,
        )?;
    }

    Ok(())
}

fn get_output_path(args: &Args) -> PathBuf {
    match &args.output {
        Some(path) => {
            if path.is_dir() {
                path.join("payload.bin")
            } else {
                path.clone()
            }
        }
        None => {
            let output_dir = PathBuf::from("output");
            output_dir.join("payload.bin")
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.target_dir.is_none() && args.target_images.is_empty() {
        return Err(anyhow!(
            "No target images specified. Use --target-dir or --target-image.\nRun with --help for more information."
        ));
    }

    if args.delta {
        if args.source_dir.is_none() && args.source_images.is_empty() {
            return Err(anyhow!(
                "Delta mode requires source images. Use --source-dir or --source-image.\nRun with --help for more information."
            ));
        }
    }

    if let Some(level) = args.compression_level {
        let valid = match args.compression_method.as_str() {
            "xz" => (0..=9).contains(&level),
            "zstd" => (1..=22).contains(&level),
            "bz2" | "bzip2" => (1..=9).contains(&level),
            _ => true,
        };

        if !valid {
            let range = match args.compression_method.as_str() {
                "xz" => "0-9",
                "zstd" => "1-22",
                "bz2" | "bzip2" => "1-9",
                _ => "unknown",
            };
            return Err(anyhow!(
                "Invalid compression level {} for method '{}'. Valid range: {}",
                level,
                args.compression_method,
                range
            ));
        }
    }

    let thread_count = args.threads.unwrap_or_else(num_cpus::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global()
        .context("Failed to initialize thread pool")?;

    println!("Using {} threads for parallel processing", thread_count);

    let output_path = get_output_path(&args);

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory: {}", parent.display()))?;
    }

    let mut modified_args = args.clone();
    modified_args.output = Some(output_path);

    pack_payload(&modified_args)?;

    Ok(())
}
