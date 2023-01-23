# Build stage
FROM --platform=linux/i386 alpine:latest AS build

# Install dependencies
RUN apk add --no-cache cmake ninja g++ linux-headers binutils

# Copy source files
COPY . /wibo

# Build static binary
# Replace with RelWithDebInfo when -O2 crash is fixed
RUN cmake -S /wibo -B /wibo/build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-static" \
    && cmake --build /wibo/build \
    && strip -g /wibo/build/wibo

# Export binary (usage: docker build --target export --output build .)
FROM scratch AS export
COPY --from=build /wibo/build/wibo .

# Runnable container
FROM alpine:latest
COPY --from=build /wibo/build/wibo /usr/local/sbin/wibo
CMD /usr/local/sbin/wibo
