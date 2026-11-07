FROM rust:1.92.0-slim-bookworm@sha256:f1f73538ebe623fd3673a35aff3df358ae1084c64c55646516e5b17b321b6c9b AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# "rsa" feature adds crates not in the teammate lock file: resolve (russh itself pinned =0.65.1), keep the resolved lock in the image
RUN cargo build --release && sha256sum Cargo.lock

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN mkdir -p /etc/psm && touch /etc/psm/authorized_keys
COPY --from=build /build/target/release/smlearn-russh-server /usr/local/bin/smlearn-russh-server
COPY --from=build /build/Cargo.lock /Cargo.lock.resolved
EXPOSE 22
CMD ["/usr/local/bin/smlearn-russh-server"]
