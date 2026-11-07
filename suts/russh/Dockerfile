FROM rust:1.92.0-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
COPY --from=build /build/target/release/smlearn-russh-server /usr/local/bin/smlearn-russh-server
EXPOSE 22
CMD ["/usr/local/bin/smlearn-russh-server"]
