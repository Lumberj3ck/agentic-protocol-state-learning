# libssh server SUT (stream B1). Adapted from vendor/agentic-protocol-state-learning/targets/libssh (Apache-2.0).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils cmake make gcc libc6-dev libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSLo libssh.tar.xz https://www.libssh.org/files/0.12/libssh-0.12.2.tar.xz \
    && echo '49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f  libssh.tar.xz' | sha256sum -c - \
    && tar -xJf libssh.tar.xz \
    && cmake -S libssh-0.12.2 -B out -DCMAKE_BUILD_TYPE=MinSizeRel \
       -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_SERVER=ON -DWITH_EXAMPLES=OFF \
       -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF -DWITH_SFTP=OFF -DWITH_PCAP=OFF \
       -DWITH_NACL=OFF -DWITH_PKCS11_PROVIDER=OFF \
    && cmake --build out -j3 && cmake --install out --strip
COPY server.c /build/server.c
RUN gcc -O2 -Wall -Wextra -Werror server.c -o /server -lssh -lpthread && strip /server \
    && openssl genrsa -traditional -out /build/ssh_host_rsa_key 3072

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /etc/psm && touch /etc/psm/authorized_keys
COPY --from=build /usr/local/lib/libssh.so* /usr/local/lib/
COPY --from=build /server /server
COPY --from=build /build/ssh_host_rsa_key /etc/psm/ssh_host_rsa_key
RUN ldconfig
EXPOSE 22
CMD ["/server"]
