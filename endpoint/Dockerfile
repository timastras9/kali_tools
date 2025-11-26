# Build stage
FROM golang:latest

WORKDIR /app

# Copy everything first
COPY . .

# Download dependencies and build
RUN go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -o /endpoint .

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy the binary
COPY --from=0 /endpoint /app/endpoint

# Fly.io uses PORT env var
ENV PORT=8080

EXPOSE 8080

# Run the API server
CMD ["/app/endpoint", "-api"]
