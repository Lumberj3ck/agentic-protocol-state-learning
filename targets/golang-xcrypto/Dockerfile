FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY server.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ssh-server .

FROM scratch
COPY --from=build /ssh-server /ssh-server
EXPOSE 22
ENTRYPOINT ["/ssh-server"]
