use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct ExtentInfo {
    pub start_block: u64,
    pub num_blocks: u64,
}

#[derive(Serialize, Deserialize)]
pub struct PartitionInfoDetails {
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SignatureInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>, // hex encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpadded_signature_size: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct InstallOperationInfo {
    pub operation_type: String,
    pub operation_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_length_readable: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub src_extents: Vec<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dst_extents: Vec<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_sha256_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_sha256_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OperationTypeStats {
    pub operation_type: String,
    pub count: usize,
    pub total_data_size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct MergeOperationInfo {
    pub operation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_extent: Option<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_extent: Option<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_offset: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct PartitionMetadata {
    pub partition_name: String,
    pub size_in_blocks: u64,
    pub size_in_bytes: u64,
    pub size_readable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub start_offset: u64,
    pub end_offset: u64,
    pub data_offset: u64,
    pub partition_type: String,
    pub operations_count: usize,
    pub compression_type: String,
    pub encryption: String,
    pub block_size: u64,
    pub total_blocks: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_postinstall: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postinstall_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postinstall_optional: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_tree_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    // detailed partition info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_partition_info: Option<PartitionInfoDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_tree_salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_tree_data_extent: Option<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_tree_extent: Option<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec_data_extent: Option<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec_extent: Option<ExtentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec_roots: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate_cow_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate_cow_size_readable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate_op_count_max: Option<u64>,

    // complete operations list with all details
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<InstallOperationInfo>,

    // merge operations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merge_operations: Vec<MergeOperationInfo>,
    pub merge_operations_count: usize,

    // signatures
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_partition_signatures: Vec<SignatureInfo>,
    pub signature_count: usize,

    // statistics
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_type_stats: Vec<OperationTypeStats>,
    pub total_data_size: u64,
    pub total_data_size_readable: String,
    pub num_src_extents: usize,
    pub num_dst_extents: usize,
}

#[derive(Serialize, Deserialize)]
pub struct DynamicPartitionGroupInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_readable: Option<String>,
    #[serde(default)]
    pub partition_names: Vec<String>,
    pub partition_count: usize,
}

#[derive(Serialize, Deserialize)]
pub struct VabcFeatureSetInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threaded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_writes: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct DynamicPartitionInfo {
    #[serde(default)]
    pub groups: Vec<DynamicPartitionGroupInfo>,
    pub groups_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vabc_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vabc_compression_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cow_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vabc_feature_set: Option<VabcFeatureSetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_factor: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct ApexInfoMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_compressed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompressed_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompressed_size_readable: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PayloadMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_patch_level: Option<String>,
    pub block_size: u32,
    pub minor_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_partition_metadata: Option<DynamicPartitionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_update: Option<bool>,
    #[serde(default)]
    pub apex_info: Vec<ApexInfoMetadata>,
    pub apex_info_count: usize,
    #[serde(default)]
    pub partitions: Vec<PartitionMetadata>,
    pub partitions_count: usize,

    // manifest-level fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures_size: Option<u64>,

    // computed statistics
    pub total_payload_size: u64,
    pub total_payload_size_readable: String,
    pub total_operations_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub global_operation_stats: Vec<OperationTypeStats>,
}
