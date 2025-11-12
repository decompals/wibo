# Build stage
FROM alpine:latest AS build

# Install dependencies
RUN apk add --no-cache \
    bash \
    binutils \
    clang \
    clang-dev \
    cmake \
    coreutils \
    git \
    linux-headers \
    lld \
    llvm-dev \
    make \
    mingw-w64-binutils \
    mingw-w64-gcc \
    ninja \
    python3

# Copy source files
WORKDIR /wibo
COPY . /wibo

# Target platform (automatically set by Docker buildx)
ARG TARGETPLATFORM

# Build type (release, debug)
ARG BUILD_TYPE=release

# Enable link-time optimization (LTO) (AUTO, ON, OFF)
ARG ENABLE_LTO=AUTO

# Version string (if not provided, defaults to "unknown")
ARG WIBO_VERSION

# Build static binary
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
        PRESET="${BUILD_TYPE}64-clang"; \
        TOOLCHAIN="/wibo/cmake/toolchains/x86_64-alpine-linux-musl.cmake"; \
    elif [ "$TARGETPLATFORM" = "linux/386" ]; then \
        PRESET="${BUILD_TYPE}-clang"; \
        TOOLCHAIN="/wibo/cmake/toolchains/i586-alpine-linux-musl.cmake"; \
    else \
        echo "Error: Unsupported platform '$TARGETPLATFORM'. Supported platforms: linux/amd64, linux/386" >&2; \
        exit 1; \
    fi; \
    echo "Building for $TARGETPLATFORM with preset $PRESET" \
    && cmake -S /wibo -B /wibo/build --preset "$PRESET" \
        -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
        -DWIBO_ENABLE_LTO:STRING="$ENABLE_LTO" \
        -DWIBO_VERSION:STRING="$WIBO_VERSION" \
    && cmake --build /wibo/build --verbose \
    && ( [ "$BUILD_TYPE" != "release"* ] || strip -g /wibo/build/wibo )

# Export binary (usage: docker build --target export --output build .)
FROM scratch AS export

COPY --from=build /wibo/build/wibo .

# Runnable container
FROM alpine:latest

COPY --from=build /wibo/build/wibo /usr/local/bin/wibo
CMD ["/usr/local/bin/wibo"]
