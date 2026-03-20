#!/usr/bin/env bash

# GoDNSHole Build Script

OS=${OS:-$(go env GOOS)}
ARCH=${ARCH:-$(go env GOARCH)}
OUTPUT_DIR="build"

function print_usage() {
    echo "Usage: $0 {build|clean|install}"
    echo "Environment variables:"
    echo "  OS       (default: $OS)"
    echo "  ARCH     (default: $ARCH)"
    exit 1
}

function build() {
    echo "Building for OS=$OS ARCH=$ARCH..."
    mkdir -p $OUTPUT_DIR
    
    # Build components
    for dir in cmd/*; do
        if [ -d "$dir" ]; then
            component=$(basename "$dir")
            # Build sub-components if any (client/server)
            for subdir in "$dir"/*; do
                if [ -d "$subdir" ]; then
                    subcomponent=$(basename "$subdir")
                    bin_name="${component}-${subcomponent}"
                    if [ "$OS" = "windows" ]; then
                        bin_name="${bin_name}.exe"
                    fi
                    echo "  -> Compiling $bin_name"
                    GOOS=$OS GOARCH=$ARCH go build -o "$OUTPUT_DIR/$bin_name" "./$subdir"
                fi
            done
            # Build top level if main.go exists
            if [ -f "$dir/main.go" ]; then
                bin_name="${component}"
                if [ "$OS" = "windows" ]; then
                    bin_name="${bin_name}.exe"
                fi
                echo "  -> Compiling $bin_name"
                GOOS=$OS GOARCH=$ARCH go build -o "$OUTPUT_DIR/$bin_name" "./$dir"
            fi
        fi
    done
    
    # Build any direct GoDNSHole components in root
    echo "Build complete."
}

function clean() {
    echo "Cleaning build directory..."
    rm -rf $OUTPUT_DIR
    echo "Clean complete."
}

function install_bins() {
    echo "Installing to GOPATH/bin..."
    go install ./cmd/...
    echo "Install complete."
}

if [ $# -eq 0 ]; then
    print_usage
fi

case "$1" in
    build)
        build
        ;;
    clean)
        clean
        ;;
    install)
        install_bins
        ;;
    *)
        print_usage
        ;;
esac
