# Build stage
FROM --platform=linux/i386 alpine:latest AS build

# Install dependencies
RUN apk add --no-cache cmake ninja g++ linux-headers binutils

# Copy source files
COPY . /wibo

# Build type (Release, Debug, RelWithDebInfo, MinSizeRel)
ARG build_type=Release

# Build static binary
RUN cmake -S /wibo -B /wibo/build -G Ninja -DCMAKE_BUILD_TYPE="$build_type" -DCMAKE_CXX_FLAGS="-static" \
    && cmake --build /wibo/build \
    && ( [ "$build_type" != "Release" ] || strip -g /wibo/build/wibo )

# Export binary (usage: docker build --target export --output build .)
FROM scratch AS export
COPY --from=build /wibo/build/wibo .

# Runnable container
FROM alpine:latest
COPY --from=build /wibo/build/wibo /usr/local/sbin/wibo
CMD /usr/local/sbin/wibo
