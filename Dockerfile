# build stage
FROM golang:1.24 AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ce-vcd-power-schedule ./cmd/ce-vcd-power-schedule

# Runtime stage
FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /out/ce-vcd-power-schedule /app/ce-vcd-power-schedule
ENTRYPOINT ["/app/ce-vcd-power-schedule"]
