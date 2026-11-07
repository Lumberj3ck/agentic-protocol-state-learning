FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils cmake make gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSLo libssh.tar.xz https://www.libssh.org/files/0.12/libssh-0.12.2.tar.xz \
    && echo '49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f  libssh.tar.xz' | sha256sum -c - \
    && tar -xJf libssh.tar.xz \
    && cmake -S libssh-0.12.2 -B out -DCMAKE_BUILD_TYPE=MinSizeRel \
       -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_SERVER=ON -DWITH_EXAMPLES=OFF \
       -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF -DWITH_SFTP=OFF -DWITH_PCAP=OFF \
       -DWITH_NACL=OFF -DWITH_PKCS11_PROVIDER=OFF \
    && cmake --build out -j2 && cmake --install out --strip
COPY server.c /build/server.c
RUN gcc -O2 -Wall -Wextra -Werror server.c -o /server -lssh -lpthread \
    && strip /server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/libssh.so* /usr/local/lib/
COPY --from=build /server /server
RUN ldconfig
EXPOSE 22
CMD ["/server"]
