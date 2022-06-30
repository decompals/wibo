FROM ubuntu:22.04 as build

RUN apt-get update && apt-get install -y --no-install-recommends g++ g++-multilib make

COPY . /WiBo

RUN make -C /WiBo


FROM ubuntu:22.04

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6:i386

COPY --from=build /WiBo/wibo /usr/local/sbin/wibo

CMD /usr/local/sbin/wibo
