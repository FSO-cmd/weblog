FROM golang:1.26 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o weblog .


FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/weblog .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/uploads ./uploads
COPY --from=builder /app/schema.sql ./schema.sql

EXPOSE 8080

CMD ["./weblog"]