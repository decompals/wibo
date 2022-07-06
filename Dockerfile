FROM ubuntu:22.04 as build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        g++ \
        g++-multilib \
        cmake \
        ninja-build

COPY . /wibo

# Replace with RelWithDebInfo when -O2 crash is fixed
RUN cmake -S /wibo -B /wibo/build -G Ninja -DCMAKE_BUILD_TYPE=Debug
RUN cmake --build /wibo/build


FROM ubuntu:22.04

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        libstdc++6:i386

COPY --from=build /wibo/build/wibo /usr/local/sbin/wibo

CMD /usr/local/sbin/wibo
