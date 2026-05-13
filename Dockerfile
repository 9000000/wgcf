FROM golang:1.25.5-alpine AS builder

WORKDIR /src

# Step 1: Copy root manifests AND the local openapi module (required by go.mod replace reference)
COPY go.mod go.sum ./
COPY openapi/ openapi/

# Step 2: Pre-download dependencies to establish an unbreakable build cache layer
RUN apk add --no-cache git && go mod download

# Step 3: Copy the remaining repository files and execute the final compilation
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o wgcf

# Final ultra-lightweight runtime environment
FROM alpine:3.23.2

# Guarantee CA Certificates exist for foolproof HTTPS connectivity to Telegram and Cloudflare APIs
RUN apk add --no-cache ca-certificates

WORKDIR /
COPY --from=builder /src/wgcf /wgcf

ENTRYPOINT ["/wgcf"]
