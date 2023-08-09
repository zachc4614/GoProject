FROM golang:1.20 AS builder

WORKDIR /app
COPY password_manager_client/ .

RUN go build -o main .

FROM debian:buster-slim

WORKDIR /app
COPY --from=builder /app/main .

CMD ["./main"]
