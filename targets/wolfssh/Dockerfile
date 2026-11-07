FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates curl openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSL https://www.wolfssl.com/wolfssl-5.9.4.tar.gz -o ssl.tar.gz && echo 'a6de5589c07c485cd72f520d9ac3872099e6d235bffc31058bc4c2d7f98bfe64  ssl.tar.gz' | sha256sum -c - && tar xzf ssl.tar.gz && cd wolfssl-5.9.4 && ./configure --enable-ssh --enable-keygen --enable-curve25519 --enable-aesctr --disable-shared --enable-static --disable-examples --disable-crypttests && make -j2 && make install
RUN curl -fsSL https://www.wolfssl.com/wolfssh-1.6.0.tar.gz -o ssh.tar.gz && echo '5bd4425d40a451607c78fcab2629242751e6cc59b5c9ebdfa4805fc704e1bfef  ssh.tar.gz' | sha256sum -c - && tar xzf ssh.tar.gz && cd wolfssh-1.6.0 &&  LIBS=-lm ./configure --enable-all --disable-shared --enable-static && make -j2 && make install
COPY server.c .
RUN cc -O2 -o server server.c -I/usr/local/include -L/usr/local/lib -lwolfssh -lwolfssl -lm -lpthread && strip server && openssl ecparam -name prime256v1 -genkey -noout -out host-key.pem
FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /build/server /build/host-key.pem ./
EXPOSE 22
CMD ["./server"]
