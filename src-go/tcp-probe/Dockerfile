# Build stage
FROM golang:1.21-alpine AS builder

# Install git for go mod download (some deps use git)
RUN apk add --no-cache git

WORKDIR /app

# Copy source and build
COPY go.mod main.go ./
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server .

# Runtime stage - minimal image
FROM alpine:3.19

# Install ca-certificates for HTTPS/Let's Encrypt
RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /server /app/server

# Port documentation
EXPOSE 80 443 8080

ENTRYPOINT ["/app/server"]
