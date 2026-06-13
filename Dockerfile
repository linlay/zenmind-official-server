FROM golang:1.26 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/zenmind-server ./cmd/server

FROM alpine:3.22

WORKDIR /app
COPY --from=build /out/zenmind-server /app/zenmind-server
RUN addgroup -S zenmind && adduser -S -G zenmind zenmind && mkdir -p /data && chown -R zenmind:zenmind /data
USER zenmind

EXPOSE 8080
ENTRYPOINT ["/app/zenmind-server"]
