#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# TEST URLS
OLD_OTA_URL="https://dl.google.com/dl/android/aosp/rango-ota-bd3a.250808.001-f5927106.zip"
NEW_OTA_URL="https://dl.google.com/dl/android/aosp/rango-ota-bd3a.251005.003-ca14833b.zip"
DUMPER_URL="https://github.com/rhythmcache/payload-dumper-rust/releases/download/payload-dumper-rust-v0.8.2/payload_dumper-linux-x86_64.zip"

# Test partitions
PARTITIONS="boot,vendor_boot"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="$SCRIPT_DIR/test_run_$(date +%s)"
DUMPER_DIR="$TEST_DIR/dumper"
OLD_IMAGES_DIR="$TEST_DIR/old_images"
NEW_IMAGES_DIR="$TEST_DIR/new_images"
FULL_PAYLOAD_DIR="$TEST_DIR/full_payload"
FULL_EXTRACTED_DIR="$TEST_DIR/full_extracted"
DELTA_PAYLOAD_DIR="$TEST_DIR/delta_payload"
DELTA_EXTRACTED_DIR="$TEST_DIR/delta_extracted"

# Binary paths
PACKER_BIN="$ROOT_DIR/target/release/payload_packer"
DUMPER_BIN="$DUMPER_DIR/payload_dumper"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Payload Packer Proof of Concept Tests${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Create test directory structure
mkdir -p "$TEST_DIR"
mkdir -p "$DUMPER_DIR"
mkdir -p "$OLD_IMAGES_DIR"
mkdir -p "$NEW_IMAGES_DIR"
mkdir -p "$FULL_PAYLOAD_DIR"
mkdir -p "$FULL_EXTRACTED_DIR"
mkdir -p "$DELTA_PAYLOAD_DIR"
mkdir -p "$DELTA_EXTRACTED_DIR"

# Function to calculate SHA256 hash
calculate_hash() {
    sha256sum "$1" | awk '{print $1}'
}

# Function to compare hashes
compare_hashes() {
    local file1="$1"
    local file2="$2"
    local name="$3"
    
    local hash1=$(calculate_hash "$file1")
    local hash2=$(calculate_hash "$file2")
    
    echo -e "${YELLOW}Comparing $name:${NC}"
    echo "  Original: $hash1"
    echo "  Extracted: $hash2"
    
    if [ "$hash1" == "$hash2" ]; then
        echo -e "${GREEN}  [OK] Hash match!${NC}\n"
        return 0
    else
        echo -e "${RED}  [FAIL] Hash mismatch!${NC}\n"
        return 1
    fi
}

# Build payload_packer
echo -e "${BLUE}Step 1: Building payload_packer...${NC}"
cd "$ROOT_DIR"
cargo build --release
if [ ! -f "$PACKER_BIN" ]; then
    echo -e "${RED}Failed to build payload_packer${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Build successful${NC}\n"

# Download and extract payload_dumper
echo -e "${BLUE}Step 2: Downloading payload_dumper...${NC}"
cd "$DUMPER_DIR"
wget -q --show-progress "$DUMPER_URL" -O dumper.zip
unzip -q dumper.zip
chmod +x payload_dumper
if [ ! -f "$DUMPER_BIN" ]; then
    echo -e "${RED}Failed to download payload_dumper${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Dumper ready${NC}\n"

# Extract old (source) images
echo -e "${BLUE}Step 3: Extracting old images from source OTA...${NC}"
"$DUMPER_BIN" "$OLD_OTA_URL" -o "$OLD_IMAGES_DIR" -i "$PARTITIONS"
echo -e "${GREEN}[OK] Old images extracted${NC}\n"

# Extract new (target) images
echo -e "${BLUE}Step 4: Extracting new images from target OTA...${NC}"
"$DUMPER_BIN" "$NEW_OTA_URL" -o "$NEW_IMAGES_DIR" -i "$PARTITIONS"
echo -e "${GREEN}[OK] New images extracted${NC}\n"

# Calculate and store original hashes
echo -e "${BLUE}Step 5: Calculating original image hashes...${NC}"
declare -A ORIGINAL_HASHES
for partition in ${PARTITIONS//,/ }; do
    img_file="$NEW_IMAGES_DIR/${partition}.img"
    if [ -f "$img_file" ]; then
        hash=$(calculate_hash "$img_file")
        ORIGINAL_HASHES[$partition]=$hash
        echo "  $partition: $hash"
    else
        echo -e "${RED}Missing $partition.img${NC}"
        exit 1
    fi
done
echo -e "${GREEN}[OK] Original hashes stored${NC}\n"

# Test FULL payload generation and extraction
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test 1: FULL Payload${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${BLUE}Step 6a: Creating FULL payload...${NC}"
"$PACKER_BIN" \
    --target-dir "$NEW_IMAGES_DIR" \
    --partitions "$PARTITIONS" \
    --output "$FULL_PAYLOAD_DIR/payload.bin" \
    --method xz \
    --level 9
echo -e "${GREEN}[OK] Full payload created${NC}\n"

echo -e "${BLUE}Step 6b: Extracting from FULL payload...${NC}"
"$DUMPER_BIN" "$FULL_PAYLOAD_DIR/payload.bin" -o "$FULL_EXTRACTED_DIR" -i "$PARTITIONS"
echo -e "${GREEN}[OK] Full payload extracted${NC}\n"

echo -e "${BLUE}Step 6c: Verifying FULL payload hashes...${NC}"
FULL_TEST_PASSED=true
for partition in ${PARTITIONS//,/ }; do
    original="$NEW_IMAGES_DIR/${partition}.img"
    extracted="$FULL_EXTRACTED_DIR/${partition}.img"
    if ! compare_hashes "$original" "$extracted" "$partition (FULL)"; then
        FULL_TEST_PASSED=false
    fi
done

if [ "$FULL_TEST_PASSED" = true ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}[OK] FULL PAYLOAD TEST PASSED${NC}"
    echo -e "${GREEN}========================================${NC}\n"
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}[FAIL] FULL PAYLOAD TEST FAILED${NC}"
    echo -e "${RED}========================================${NC}\n"
    exit 1
fi

# Test DELTA (incremental) payload generation and extraction
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test 2: DELTA (Incremental) Payload${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${BLUE}Step 7a: Creating DELTA payload...${NC}"
"$PACKER_BIN" \
    --delta \
    --source-dir "$OLD_IMAGES_DIR" \
    --target-dir "$NEW_IMAGES_DIR" \
    --partitions "$PARTITIONS" \
    --output "$DELTA_PAYLOAD_DIR/payload.bin" \
    --method xz \
    --level 9
echo -e "${GREEN}[OK] Delta payload created${NC}\n"

echo -e "${BLUE}Step 7b: Extracting from DELTA payload (with source images)...${NC}"
"$DUMPER_BIN" "$DELTA_PAYLOAD_DIR/payload.bin" \
    --source-dir "$OLD_IMAGES_DIR" \
    -o "$DELTA_EXTRACTED_DIR" \
    -i "$PARTITIONS"
echo -e "${GREEN}[OK] Delta payload extracted${NC}\n"

echo -e "${BLUE}Step 7c: Verifying DELTA payload hashes...${NC}"
DELTA_TEST_PASSED=true
for partition in ${PARTITIONS//,/ }; do
    original="$NEW_IMAGES_DIR/${partition}.img"
    extracted="$DELTA_EXTRACTED_DIR/${partition}.img"
    if ! compare_hashes "$original" "$extracted" "$partition (DELTA)"; then
        DELTA_TEST_PASSED=false
    fi
done

if [ "$DELTA_TEST_PASSED" = true ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}[OK] DELTA PAYLOAD TEST PASSED${NC}"
    echo -e "${GREEN}========================================${NC}\n"
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}[FAIL] DELTA PAYLOAD TEST FAILED${NC}"
    echo -e "${RED}========================================${NC}\n"
    exit 1
fi

# Final summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}ALL TESTS PASSED!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Proof of concept successful:${NC}"
echo -e "${GREEN}  [OK] Full payload generation and extraction${NC}"
echo -e "${GREEN}  [OK] Delta payload generation and extraction${NC}"
echo -e "${GREEN}  [OK] All partition hashes match${NC}\n"

# Payload size comparison
FULL_SIZE=$(stat -f%z "$FULL_PAYLOAD_DIR/payload.bin" 2>/dev/null || stat -c%s "$FULL_PAYLOAD_DIR/payload.bin")
DELTA_SIZE=$(stat -f%z "$DELTA_PAYLOAD_DIR/payload.bin" 2>/dev/null || stat -c%s "$DELTA_PAYLOAD_DIR/payload.bin")
FULL_SIZE_MB=$(echo "scale=2; $FULL_SIZE / 1024 / 1024" | bc)
DELTA_SIZE_MB=$(echo "scale=2; $DELTA_SIZE / 1024 / 1024" | bc)
SAVINGS=$(echo "scale=1; (1 - $DELTA_SIZE / $FULL_SIZE) * 100" | bc)

echo -e "${BLUE}Payload Size Comparison:${NC}"
echo "  Full payload:  ${FULL_SIZE_MB} MB"
echo "  Delta payload: ${DELTA_SIZE_MB} MB"
echo "  Space saved:   ${SAVINGS}%"
echo ""

echo -e "${YELLOW}Test artifacts saved in: $TEST_DIR${NC}"
echo -e "${YELLOW}To cleanup, run: rm -rf $TEST_DIR${NC}"
