# Build stage
FROM --platform=linux/i386 alpine:latest AS build

# Install dependencies
RUN apk add --no-cache \
    bash \
    cmake \
    ninja \
    g++ \
    linux-headers \
    binutils \
    mingw-w64-binutils \
    mingw-w64-gcc

# Copy source files
WORKDIR /wibo
COPY . /wibo

# Build type (Release, Debug, RelWithDebInfo, MinSizeRel)
ARG build_type=Release

# Build static binary
RUN cmake -S /wibo -B /wibo/build -G Ninja \
        -DCMAKE_BUILD_TYPE="$build_type" \
        -DCMAKE_CXX_FLAGS="-static" \
        -DBUILD_TESTING=ON \
        -DWIBO_ENABLE_FIXTURE_TESTS=ON \
    && cmake --build /wibo/build \
    && ( [ "$build_type" != "Release" ] || strip -g /wibo/build/wibo )

# Export binary (usage: docker build --target export --output build .)
FROM scratch AS export
COPY --from=build /wibo/build/wibo .

# Runnable container
FROM alpine:latest
COPY --from=build /wibo/build/wibo /usr/local/sbin/wibo
CMD /usr/local/sbin/wibo
