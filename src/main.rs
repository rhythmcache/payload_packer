use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use byteorder::{BigEndian, WriteBytesExt};
use clap::Parser;
use digest::Digest;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use prost::Message;
use rayon::prelude::*;
use sha2::Sha256;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

include!("proto/update_metadata.rs");

const PAYLOAD_MAGIC: &[u8] = b"CrAU";

const PAYLOAD_VERSION: u64 = 2;

#[derive(Parser, Clone)]
#[command(version, about = "A tool to pack Android OTA payload files")]
#[command(next_line_help = true)]
struct Args {
    #[arg(
        long = "out",
        help = "Path to the output payload.bin file (default: output/payload.bin)"
    )]
    out: Option<PathBuf>,

    #[arg(help = "Directory containing image files to pack")]
    images_dir: Option<PathBuf>,

    #[arg(
        long,
        help = "Specific image paths (can be used instead of or together with images_dir)"
    )]
    images_path: Vec<PathBuf>,

    #[arg(
        long,
        default_value = "",
        help = "Comma-separated list of partition names to include (default: all)"
    )]
    images: String,

    #[arg(
        long,
        default_value = "xz",
        value_parser = ["xz", "zstd"],
        help = "Compression method to use (xz or zstd)"
    )]
    method: String,

    #[arg(long, help = "Number of threads to use for parallel processing")]
    threads: Option<usize>,

    #[arg(long, help = "Block size in bytes", default_value = "4096")]
    block_size: u32,

    #[arg(long, help = "Skip creation of payload_properties.txt file")]
    skip_prop: bool,
}

struct ImageInfo {
    path: PathBuf,
    name: String,
    size: u64,
    hash: Vec<u8>,
}

fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} bytes", size)
    }
}

fn format_elapsed_time(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    let millis = duration.subsec_millis();

    if hours > 0 {
        format!("{}h {}m {}.{:03}s", hours, mins, secs, millis)
    } else if mins > 0 {
        format!("{}m {}.{:03}s", mins, secs, millis)
    } else {
        format!("{}.{:03}s", secs, millis)
    }
}

fn calculate_hash(file_path: &Path) -> Result<Vec<u8>> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().to_vec())
}

fn find_image_files(args: &Args) -> Result<Vec<ImageInfo>> {
    let mut image_paths = Vec::new();
    let mut seen_names = HashSet::new();
    let selected_images = if args.images.is_empty() {
        HashSet::new()
    } else {
        args.images.split(',').collect::<HashSet<_>>()
    };
    if let Some(images_dir) = &args.images_dir {
        if !images_dir.exists() || !images_dir.is_dir() {
            return Err(anyhow!(
                "Images directory does not exist or is not a directory"
            ));
        }

        for entry in fs::read_dir(images_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "img") {
                let name = path
                    .file_stem()
                    .ok_or_else(|| anyhow!("Invalid filename"))?
                    .to_string_lossy()
                    .to_string();

                if !selected_images.is_empty() && !selected_images.contains(&name as &str) {
                    continue;
                }

                if seen_names.insert(name.clone()) {
                    image_paths.push((path, name));
                }
            }
        }
    }
    for path in &args.images_path {
        if !path.exists() || !path.is_file() {
            return Err(anyhow!("Image file does not exist: {:?}", path));
        }

        let name = path
            .file_stem()
            .ok_or_else(|| anyhow!("Invalid filename for {:?}", path))?
            .to_string_lossy()
            .to_string();

        if !selected_images.is_empty() && !selected_images.contains(&name as &str) {
            continue;
        }

        if seen_names.insert(name.clone()) {
            image_paths.push((path.clone(), name));
        }
    }

    if image_paths.is_empty() {
        return Err(anyhow!("No image files found"));
    }
    let thread_count = args.threads.unwrap_or_else(num_cpus::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global()?;

    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new_spinner());
    main_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    main_pb.enable_steady_tick(Duration::from_millis(100));
    main_pb.set_message(format!("Processing {} image files...", image_paths.len()));

    let progress_bars: Vec<_> = image_paths
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
            let pb = progress_bars
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, pb)| pb.clone());

            if let Some(pb) = &pb {
                pb.set_message(format!("Processing {}", name));
            }

            let file_size = fs::metadata(path)
                .map(|m| m.len())
                .with_context(|| format!("Failed to get metadata for {}", path.display()));

            let hash_result = calculate_hash(path)
                .with_context(|| format!("Failed to calculate hash for {}", path.display()));

            if let (Ok(size), Ok(hash)) = (file_size, hash_result) {
                if let Some(pb) = pb {
                    pb.finish_with_message(format!(
                        "✓ {} ({} - {} bytes)",
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
            } else {
                if let Some(pb) = pb {
                    pb.finish_with_message(format!("✕ Failed to process {}", name));
                }

                Err(anyhow!("Failed to process image: {}", name))
            }
        })
        .collect::<Result<Vec<_>>>()?;

    main_pb.finish_with_message(format!("Processed {} image files", image_infos.len()));

    Ok(image_infos)
}

fn create_payload_properties(
    payload_path: &Path,
    manifest_data: &[u8],
    manifest_size: u64,
) -> Result<()> {
    let properties_path = payload_path.with_file_name("payload_properties.txt");
    let mut file = File::create(&properties_path)?;

    let file_hash = calculate_hash(payload_path)?;
    let file_size = fs::metadata(payload_path)?.len();

    let metadata_hash = {
        let mut hasher = Sha256::new();
        hasher.update(manifest_data);
        hasher.finalize().to_vec()
    };

    // Write properties to file
    writeln!(file, "FILE_HASH={}", STANDARD.encode(&file_hash))?;
    writeln!(file, "FILE_SIZE={}", file_size)?;
    writeln!(file, "METADATA_HASH={}", STANDARD.encode(&metadata_hash))?;
    writeln!(file, "METADATA_SIZE={}", manifest_size)?;

    println!(
        "Created payload properties file: {}",
        properties_path.display()
    );
    Ok(())
}

fn create_install_operation(
    image_path: &Path,
    image_size: u64,
    block_size: u32,
    compression_method: &str,
) -> Result<(InstallOperation, PathBuf, u64)> {
    let temp_dir = tempfile::Builder::new()
        .prefix("payload_builder_")
        .tempdir()?;
    let temp_file_path = temp_dir.path().join("compressed_data");
    let file = File::create(&temp_file_path)?;
    let mut writer = BufWriter::new(file);

    let operation_type = match compression_method {
        "xz" => {
            let mut encoder = lzma::LzmaWriter::new_compressor(&mut writer, 9)?;
            const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
            let mut buffer = vec![0; CHUNK_SIZE];
            let mut reader = BufReader::new(File::open(image_path)?);

            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                encoder.write_all(&buffer[..bytes_read])?;
            }
            encoder.finish()?;
            install_operation::Type::ReplaceXz
        }
        "zstd" => {
            let mut encoder = zstd::Encoder::new(&mut writer, 19)?;
            const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
            let mut buffer = vec![0; CHUNK_SIZE];
            let mut reader = BufReader::new(File::open(image_path)?);

            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                encoder.write_all(&buffer[..bytes_read])?;
            }
            encoder.finish()?;
            install_operation::Type::Zstd
        }
        _ => {
            return Err(anyhow!(
                "Unsupported compression method: {}",
                compression_method
            ));
        }
    };

    writer.flush()?;
    let compressed_size = fs::metadata(&temp_file_path)?.len();
    let hash = calculate_hash(&temp_file_path)?;
    let num_blocks = (image_size + block_size as u64 - 1) / block_size as u64;
    let dst_extent = Extent {
        start_block: Some(0),
        num_blocks: Some(num_blocks),
    };
    let operation = InstallOperation {
        r#type: operation_type as i32,
        data_offset: Some(0),
        data_length: Some(compressed_size),
        src_extents: Vec::new(),
        src_length: None,
        dst_extents: vec![dst_extent],
        dst_length: Some(image_size),
        data_sha256_hash: Some(hash),
        src_sha256_hash: None,
    };
    let temp_file_path = temp_file_path.to_path_buf();
    std::mem::forget(temp_dir);

    Ok((operation, temp_file_path, compressed_size))
}

fn create_partition_update(
    image_info: &ImageInfo,
    block_size: u32,
    compression_method: &str,
    multi_progress: &MultiProgress,
) -> Result<(PartitionUpdate, PathBuf, u64)> {
    let pb = multi_progress.add(ProgressBar::new_spinner());
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message(format!("Processing {}", image_info.name));

    let (install_op, temp_file_path, compressed_size) = create_install_operation(
        &image_info.path,
        image_info.size,
        block_size,
        compression_method,
    )?;

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
        operations: vec![install_op],
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
        "✓ {} ({} -> {} - {:.1}%)",
        image_info.name,
        format_size(image_info.size),
        format_size(compressed_size),
        (compressed_size as f64 / image_info.size as f64) * 100.0
    ));

    Ok((partition_update, temp_file_path, compressed_size))
}

fn pack_payload(args: &Args, image_infos: &[ImageInfo]) -> Result<()> {
    let start_time = Instant::now();
    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new_spinner());
    main_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    main_pb.enable_steady_tick(Duration::from_millis(100));
    main_pb.set_message("Creating manifest...");

    let results: Vec<_> = image_infos
        .par_iter()
        .map(|image_info| {
            create_partition_update(image_info, args.block_size, &args.method, &multi_progress)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut partition_updates = Vec::new();
    let mut temp_files = Vec::new();
    let mut total_compressed_size = 0u64;

    for (update, temp_path, size) in results {
        partition_updates.push(update);
        temp_files.push(temp_path);
        total_compressed_size += size;
    }
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
            vabc_compression_param: Some(args.method.clone()),
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
        partial_update: Some(false),
        apex_info: Vec::new(),
        security_patch_level: None,
    };

    let mut current_offset = 0u64;
    let mut manifest_with_offsets = manifest.clone();

    for (i, partition) in manifest_with_offsets.partitions.iter_mut().enumerate() {
        if partition.operations.is_empty() {
            continue;
        }

        let op = &mut partition.operations[0];
        op.data_offset = Some(current_offset);
        let file_size = fs::metadata(&temp_files[i])?.len();
        current_offset += file_size;
    }

    let final_manifest = manifest_with_offsets.encode_to_vec();

    main_pb.set_message("Writing payload file...");
    let output_file = File::create(args.out.as_ref().unwrap())?;
    let mut writer = BufWriter::new(output_file);
    writer.write_all(PAYLOAD_MAGIC)?;
    writer.write_u64::<BigEndian>(PAYLOAD_VERSION)?;
    writer.write_u64::<BigEndian>(final_manifest.len() as u64)?;
    writer.write_u32::<BigEndian>(0)?;
    writer.write_all(&final_manifest)?;

    for (i, temp_path) in temp_files.iter().enumerate() {
        let partition_name = &manifest.partitions[i].partition_name;
        let file_size = fs::metadata(temp_path)?.len();

        let progress_bar = multi_progress.add(ProgressBar::new(file_size));
        progress_bar.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/white}] {bytes}/{total_bytes} ({bytes_per_sec}) - {msg}")
            .unwrap()
            .progress_chars("▰▱"));
        progress_bar.enable_steady_tick(Duration::from_millis(100));
        progress_bar.set_message(format!("Writing {}", partition_name));

        let mut reader = BufReader::new(File::open(temp_path)?);
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
        let mut buffer = vec![0; CHUNK_SIZE];
        let mut bytes_written = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            writer.write_all(&buffer[..bytes_read])?;
            bytes_written += bytes_read as u64;
            progress_bar.set_position(bytes_written);
        }

        progress_bar.finish_with_message(format!("✓ {} written", partition_name));
        fs::remove_file(temp_path)?;
    }

    writer.flush()?;
    let elapsed_time = format_elapsed_time(start_time.elapsed());
    main_pb.finish_with_message(format!("Payload created successfully in {}", elapsed_time));

    let output_size = fs::metadata(args.out.as_ref().unwrap())?.len();
    let total_input_size: u64 = image_infos.iter().map(|info| info.size).sum();

    println!("\nPayload creation completed in {}", elapsed_time);
    println!("Output file: {}", args.out.as_ref().unwrap().display());
    println!(
        "Output size: {} ({})",
        format_size(output_size),
        output_size
    );
    println!("Total compressed size: {}", total_compressed_size);
    println!(
        "Total input size: {} ({})",
        format_size(total_input_size),
        total_input_size
    );
    println!(
        "Compression ratio: {:.2}%",
        (output_size as f64 / total_input_size as f64) * 100.0
    );
    println!("Compression method: {}", args.method);

    if !args.skip_prop {
        create_payload_properties(
            args.out.as_ref().unwrap(),
            &final_manifest,
            final_manifest.len() as u64,
        )?;
    }

    Ok(())
}

fn get_output_path(args: &Args) -> PathBuf {
    match &args.out {
        Some(path) => {
            if path.is_dir() {
                path.join("payload.bin")
            } else {
                path.clone()
            }
        }
        None => {
            let output_dir = PathBuf::from("output");
            if !output_dir.exists() {
                fs::create_dir_all(&output_dir).expect("Failed to create output directory");
            }
            output_dir.join("payload.bin")
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.images_dir.is_none() && args.images_path.is_empty() {
        return Err(anyhow!("Invalid arguments : See --help for usage"));
    }

    let output_path = get_output_path(&args);

    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let image_infos = find_image_files(&args)?;
    if image_infos.is_empty() {
        return Err(anyhow!("No image files found to pack"));
    }

    let mut modified_args = args.clone();
    modified_args.out = Some(output_path);

    pack_payload(&modified_args, &image_infos)?;
    Ok(())
}
