# Build stage
FROM --platform=linux/i386 alpine:latest AS build

# Install dependencies
RUN apk add --no-cache \
    bash \
    binutils \
    cmake \
    coreutils \
    g++ \
    git \
    linux-headers \
    make \
    mingw-w64-binutils \
    mingw-w64-gcc \
    ninja

# Copy source files
WORKDIR /wibo
COPY . /wibo

# Build type (Release, Debug, RelWithDebInfo, MinSizeRel)
ARG BUILD_TYPE=Release

# Enable link-time optimization (LTO) (AUTO, ON, OFF)
ARG ENABLE_LTO=AUTO

# Version string (if not provided, defaults to "unknown")
ARG WIBO_VERSION

# Build static binary
RUN cmake -S /wibo -B /wibo/build -G Ninja \
        -DCMAKE_BUILD_TYPE:STRING="$BUILD_TYPE" \
        -DCMAKE_C_FLAGS:STRING="-static" \
        -DCMAKE_CXX_FLAGS:STRING="-static" \
        -DMI_LIBC_MUSL:BOOL=ON \
        -DWIBO_ENABLE_LIBURING:BOOL=ON \
        -DWIBO_ENABLE_LTO:STRING="$ENABLE_LTO" \
        -DWIBO_VERSION:STRING="$WIBO_VERSION" \
    && cmake --build /wibo/build --verbose \
    && ( [ "$BUILD_TYPE" != "Release" ] || strip -g /wibo/build/wibo )

# Export binary (usage: docker build --target export --output build .)
FROM scratch AS export
COPY --from=build /wibo/build/wibo .

# Runnable container
FROM alpine:latest
COPY --from=build /wibo/build/wibo /usr/local/sbin/wibo
CMD /usr/local/sbin/wibo
