#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EMP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
THIRD_PARTY="$EMP_DIR/third_party"
INSTALL_PREFIX="$THIRD_PARTY/install"
SRC_DIR="$THIRD_PARTY/src"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "=== Invisibook 2PC: Installing emp-toolkit dependencies ==="
echo "Install prefix: $INSTALL_PREFIX"
echo "Parallel jobs:  $NPROC"

mkdir -p "$SRC_DIR" "$INSTALL_PREFIX"

# ---------- System dependency check ----------
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: $1 not found. Please install it first."
        echo "  macOS:  brew install $2"
        echo "  Ubuntu: sudo apt-get install $3"
        exit 1
    fi
}

check_dep cmake cmake cmake
check_dep git git git
check_dep pkg-config pkg-config pkg-config

# Check OpenSSL
if ! pkg-config --exists openssl 2>/dev/null; then
    if [ -d "/opt/homebrew/opt/openssl" ]; then
        export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
        export OPENSSL_ROOT_DIR="/opt/homebrew/opt/openssl"
    elif [ -d "/usr/local/opt/openssl" ]; then
        export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
        export OPENSSL_ROOT_DIR="/usr/local/opt/openssl"
    else
        echo "ERROR: OpenSSL not found."
        echo "  macOS:  brew install openssl"
        echo "  Ubuntu: sudo apt-get install libssl-dev"
        exit 1
    fi
fi

# ---------- Build helper ----------
build_emp_lib() {
    local name="$1"
    local repo="https://github.com/emp-toolkit/${name}.git"

    echo ""
    echo "--- Building $name ---"

    if [ ! -d "$SRC_DIR/$name" ]; then
        git clone --depth 1 "$repo" "$SRC_DIR/$name"
    else
        echo "$name source already exists, skipping clone."
    fi

    mkdir -p "$SRC_DIR/$name/build"
    cd "$SRC_DIR/$name/build"

    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
        -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX" \
        ${OPENSSL_ROOT_DIR:+-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR"}

    make -j"$NPROC"
    make install

    echo "--- $name installed ---"
}

# ---------- Build in dependency order ----------
build_emp_lib emp-tool
build_emp_lib emp-ot
build_emp_lib emp-ag2pc

echo ""
echo "=== All emp-toolkit dependencies installed to $INSTALL_PREFIX ==="
echo ""
echo "To use in CMake, add:"
echo "  list(APPEND CMAKE_PREFIX_PATH \"$INSTALL_PREFIX\")"
