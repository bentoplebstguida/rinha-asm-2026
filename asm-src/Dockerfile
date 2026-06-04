# syntax=docker/dockerfile:1.7
# Force amd64 for the rinha runner.

FROM --platform=linux/amd64 alpine:3.20 AS build

RUN apk add --no-cache nasm gcc musl-dev

WORKDIR /src
COPY tree.inc main.asm ./
# nasm -f elf64 + gcc link against musl for static-ish binary
RUN nasm -f elf64 main.asm -o main.o \
    && gcc -static -o fraud-api main.o -no-pie

FROM --platform=linux/amd64 scratch

WORKDIR /app
COPY --from=build /src/fraud-api /app/fraud-api

EXPOSE 8080

CMD ["/app/fraud-api"]
