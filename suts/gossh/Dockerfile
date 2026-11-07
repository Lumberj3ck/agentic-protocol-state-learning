FROM golang:1.23-bookworm AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /gossh . && go version > /go-version.txt
FROM debian:bookworm-slim
COPY --from=build /gossh /usr/local/bin/gossh
COPY --from=build /go-version.txt /go-version.txt
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/gossh"]
