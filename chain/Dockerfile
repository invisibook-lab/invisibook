# ---- Build stage ----
FROM golang:1.25.7 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o invisibook .

# ---- Runtime stage ----
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/invisibook .
COPY cfg/ cfg/

EXPOSE 7999 8999 8887

ENTRYPOINT ["./invisibook"]
