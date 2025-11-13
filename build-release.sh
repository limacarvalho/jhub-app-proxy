#!/bin/bash
set -e

# Release build script for jhub-app-proxy
# Builds binaries for multiple platforms and creates checksums

BINARY_NAME="jhub-app-proxy"
VERSION="v0.2.2-rc6-sdscustom"
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS="-ldflags \"-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}\""
DIST_DIR="dist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  JHub App Proxy Release Builder${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Version: ${VERSION}"
echo "Build Time: ${BUILD_TIME}"
echo ""

# Clean previous builds
echo -e "${BLUE}[1/4]${NC} Cleaning previous builds..."
rm -rf ${DIST_DIR}
mkdir -p ${DIST_DIR}
rm -f ${BINARY_NAME}
echo -e "${GREEN}✓${NC} Cleaned"
echo ""

# Platforms to build for
# Format: "OS/ARCH"
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

echo -e "${BLUE}[2/4]${NC} Building binaries for multiple platforms..."
echo ""

for PLATFORM in "${PLATFORMS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$PLATFORM"

    OUTPUT_NAME="${BINARY_NAME}_${GOOS}_${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    echo -e "  Building for ${GOOS}/${GOARCH}..."

    # Build
    GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
        -o ${DIST_DIR}/${OUTPUT_NAME} \
        ./cmd/jhub-app-proxy

    # Create tar.gz archive (except for Windows)
    if [ "$GOOS" != "windows" ]; then
        ARCHIVE_NAME="${BINARY_NAME}_${VERSION}_${GOOS}_${GOARCH}.tar.gz"

        # Create archive with binary inside
        tar -czf ${DIST_DIR}/${ARCHIVE_NAME} -C ${DIST_DIR} ${OUTPUT_NAME}

        # Remove the standalone binary, keep only the archive
        rm ${DIST_DIR}/${OUTPUT_NAME}

        echo -e "  ${GREEN}✓${NC} Created ${ARCHIVE_NAME}"
    else
        # For Windows, create a zip
        ARCHIVE_NAME="${BINARY_NAME}_${VERSION}_${GOOS}_${GOARCH}.zip"
        (cd ${DIST_DIR} && zip -q ${ARCHIVE_NAME} ${OUTPUT_NAME})
        rm ${DIST_DIR}/${OUTPUT_NAME}
        echo -e "  ${GREEN}✓${NC} Created ${ARCHIVE_NAME}"
    fi
done

echo ""
echo -e "${BLUE}[3/4]${NC} Generating checksums..."

# Generate checksums
CHECKSUMS_FILE="${DIST_DIR}/${BINARY_NAME}_${VERSION}_checksums.txt"
(cd ${DIST_DIR} && sha256sum * 2>/dev/null || shasum -a 256 * 2>/dev/null) | grep -v checksums.txt > ${CHECKSUMS_FILE} || true

echo -e "${GREEN}✓${NC} Created checksums file: ${CHECKSUMS_FILE}"
echo ""

echo -e "${BLUE}[4/4]${NC} Listing release artifacts..."
echo ""
ls -lh ${DIST_DIR}
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Release artifacts are in: ${DIST_DIR}/"
echo ""
echo "Files created:"
for file in ${DIST_DIR}/*; do
    echo "  - $(basename $file)"
done
echo ""
echo "Next steps:"
echo "  1. Test the binaries"
echo "  2. Create a GitHub release with tag: ${VERSION}"
echo "  3. Upload all files from ${DIST_DIR}/ to the release"
echo ""
