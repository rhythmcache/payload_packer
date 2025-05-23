// @generated
// This file is @generated by prost-build.
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct Extent {
    #[prost(uint64, optional, tag="1")]
    pub start_block: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="2")]
    pub num_blocks: ::core::option::Option<u64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signatures {
    #[prost(message, repeated, tag="1")]
    pub signatures: ::prost::alloc::vec::Vec<signatures::Signature>,
}
/// Nested message and enum types in `Signatures`.
pub mod signatures {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Signature {
        #[deprecated]
        #[prost(uint32, optional, tag="1")]
        pub version: ::core::option::Option<u32>,
        #[prost(bytes="vec", optional, tag="2")]
        pub data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
        #[prost(fixed32, optional, tag="3")]
        pub unpadded_signature_size: ::core::option::Option<u32>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PartitionInfo {
    #[prost(uint64, optional, tag="1")]
    pub size: ::core::option::Option<u64>,
    #[prost(bytes="vec", optional, tag="2")]
    pub hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstallOperation {
    #[prost(enumeration="install_operation::Type", required, tag="1")]
    pub r#type: i32,
    #[prost(uint64, optional, tag="2")]
    pub data_offset: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="3")]
    pub data_length: ::core::option::Option<u64>,
    #[prost(message, repeated, tag="4")]
    pub src_extents: ::prost::alloc::vec::Vec<Extent>,
    #[prost(uint64, optional, tag="5")]
    pub src_length: ::core::option::Option<u64>,
    #[prost(message, repeated, tag="6")]
    pub dst_extents: ::prost::alloc::vec::Vec<Extent>,
    #[prost(uint64, optional, tag="7")]
    pub dst_length: ::core::option::Option<u64>,
    #[prost(bytes="vec", optional, tag="8")]
    pub data_sha256_hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="9")]
    pub src_sha256_hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Nested message and enum types in `InstallOperation`.
pub mod install_operation {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Replace = 0,
        ReplaceBz = 1,
        Move = 2,
        Bsdiff = 3,
        SourceCopy = 4,
        SourceBsdiff = 5,
        ReplaceXz = 8,
        Zero = 6,
        Discard = 7,
        BrotliBsdiff = 10,
        Puffdiff = 9,
        Zucchini = 11,
        Lz4diffBsdiff = 12,
        Lz4diffPuffdiff = 13,
        Zstd = 14,
    }
    impl Type {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Self::Replace => "REPLACE",
                Self::ReplaceBz => "REPLACE_BZ",
                Self::Move => "MOVE",
                Self::Bsdiff => "BSDIFF",
                Self::SourceCopy => "SOURCE_COPY",
                Self::SourceBsdiff => "SOURCE_BSDIFF",
                Self::ReplaceXz => "REPLACE_XZ",
                Self::Zero => "ZERO",
                Self::Discard => "DISCARD",
                Self::BrotliBsdiff => "BROTLI_BSDIFF",
                Self::Puffdiff => "PUFFDIFF",
                Self::Zucchini => "ZUCCHINI",
                Self::Lz4diffBsdiff => "LZ4DIFF_BSDIFF",
                Self::Lz4diffPuffdiff => "LZ4DIFF_PUFFDIFF",
                Self::Zstd => "ZSTD",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "REPLACE" => Some(Self::Replace),
                "REPLACE_BZ" => Some(Self::ReplaceBz),
                "MOVE" => Some(Self::Move),
                "BSDIFF" => Some(Self::Bsdiff),
                "SOURCE_COPY" => Some(Self::SourceCopy),
                "SOURCE_BSDIFF" => Some(Self::SourceBsdiff),
                "REPLACE_XZ" => Some(Self::ReplaceXz),
                "ZERO" => Some(Self::Zero),
                "DISCARD" => Some(Self::Discard),
                "BROTLI_BSDIFF" => Some(Self::BrotliBsdiff),
                "PUFFDIFF" => Some(Self::Puffdiff),
                "ZUCCHINI" => Some(Self::Zucchini),
                "LZ4DIFF_BSDIFF" => Some(Self::Lz4diffBsdiff),
                "LZ4DIFF_PUFFDIFF" => Some(Self::Lz4diffPuffdiff),
                "ZSTD" => Some(Self::Zstd),
                _ => None,
            }
        }
    }
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct CowMergeOperation {
    #[prost(enumeration="cow_merge_operation::Type", optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(message, optional, tag="2")]
    pub src_extent: ::core::option::Option<Extent>,
    #[prost(message, optional, tag="3")]
    pub dst_extent: ::core::option::Option<Extent>,
    #[prost(uint32, optional, tag="4")]
    pub src_offset: ::core::option::Option<u32>,
}
/// Nested message and enum types in `CowMergeOperation`.
pub mod cow_merge_operation {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        CowCopy = 0,
        CowXor = 1,
        CowReplace = 2,
    }
    impl Type {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Self::CowCopy => "COW_COPY",
                Self::CowXor => "COW_XOR",
                Self::CowReplace => "COW_REPLACE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "COW_COPY" => Some(Self::CowCopy),
                "COW_XOR" => Some(Self::CowXor),
                "COW_REPLACE" => Some(Self::CowReplace),
                _ => None,
            }
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PartitionUpdate {
    #[prost(string, required, tag="1")]
    pub partition_name: ::prost::alloc::string::String,
    #[prost(bool, optional, tag="2")]
    pub run_postinstall: ::core::option::Option<bool>,
    #[prost(string, optional, tag="3")]
    pub postinstall_path: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub filesystem_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="5")]
    pub new_partition_signature: ::prost::alloc::vec::Vec<signatures::Signature>,
    #[prost(message, optional, tag="6")]
    pub old_partition_info: ::core::option::Option<PartitionInfo>,
    #[prost(message, optional, tag="7")]
    pub new_partition_info: ::core::option::Option<PartitionInfo>,
    #[prost(message, repeated, tag="8")]
    pub operations: ::prost::alloc::vec::Vec<InstallOperation>,
    #[prost(bool, optional, tag="9")]
    pub postinstall_optional: ::core::option::Option<bool>,
    #[prost(message, optional, tag="10")]
    pub hash_tree_data_extent: ::core::option::Option<Extent>,
    #[prost(message, optional, tag="11")]
    pub hash_tree_extent: ::core::option::Option<Extent>,
    #[prost(string, optional, tag="12")]
    pub hash_tree_algorithm: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bytes="vec", optional, tag="13")]
    pub hash_tree_salt: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, optional, tag="14")]
    pub fec_data_extent: ::core::option::Option<Extent>,
    #[prost(message, optional, tag="15")]
    pub fec_extent: ::core::option::Option<Extent>,
    #[prost(uint32, optional, tag="16", default="2")]
    pub fec_roots: ::core::option::Option<u32>,
    #[prost(string, optional, tag="17")]
    pub version: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="18")]
    pub merge_operations: ::prost::alloc::vec::Vec<CowMergeOperation>,
    #[prost(uint64, optional, tag="19")]
    pub estimate_cow_size: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="20")]
    pub estimate_op_count_max: ::core::option::Option<u64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DynamicPartitionGroup {
    #[prost(string, required, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(uint64, optional, tag="2")]
    pub size: ::core::option::Option<u64>,
    #[prost(string, repeated, tag="3")]
    pub partition_names: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct VabcFeatureSet {
    #[prost(bool, optional, tag="1")]
    pub threaded: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="2")]
    pub batch_writes: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DynamicPartitionMetadata {
    #[prost(message, repeated, tag="1")]
    pub groups: ::prost::alloc::vec::Vec<DynamicPartitionGroup>,
    #[prost(bool, optional, tag="2")]
    pub snapshot_enabled: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="3")]
    pub vabc_enabled: ::core::option::Option<bool>,
    #[prost(string, optional, tag="4")]
    pub vabc_compression_param: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint32, optional, tag="5")]
    pub cow_version: ::core::option::Option<u32>,
    #[prost(message, optional, tag="6")]
    pub vabc_feature_set: ::core::option::Option<VabcFeatureSet>,
    #[prost(uint64, optional, tag="7")]
    pub compression_factor: ::core::option::Option<u64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApexInfo {
    #[prost(string, optional, tag="1")]
    pub package_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="2")]
    pub version: ::core::option::Option<i64>,
    #[prost(bool, optional, tag="3")]
    pub is_compressed: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="4")]
    pub decompressed_size: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApexMetadata {
    #[prost(message, repeated, tag="1")]
    pub apex_info: ::prost::alloc::vec::Vec<ApexInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeltaArchiveManifest {
    #[prost(uint32, optional, tag="3", default="4096")]
    pub block_size: ::core::option::Option<u32>,
    #[prost(uint64, optional, tag="4")]
    pub signatures_offset: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="5")]
    pub signatures_size: ::core::option::Option<u64>,
    #[prost(uint32, optional, tag="12", default="0")]
    pub minor_version: ::core::option::Option<u32>,
    #[prost(message, repeated, tag="13")]
    pub partitions: ::prost::alloc::vec::Vec<PartitionUpdate>,
    #[prost(int64, optional, tag="14")]
    pub max_timestamp: ::core::option::Option<i64>,
    #[prost(message, optional, tag="15")]
    pub dynamic_partition_metadata: ::core::option::Option<DynamicPartitionMetadata>,
    #[prost(bool, optional, tag="16")]
    pub partial_update: ::core::option::Option<bool>,
    #[prost(message, repeated, tag="17")]
    pub apex_info: ::prost::alloc::vec::Vec<ApexInfo>,
    #[prost(string, optional, tag="18")]
    pub security_patch_level: ::core::option::Option<::prost::alloc::string::String>,
}
// @@protoc_insertion_point(module)
