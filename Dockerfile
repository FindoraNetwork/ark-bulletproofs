FROM 563536162678.dkr.ecr.us-west-2.amazonaws.com/rust:2020-09-15 AS builder
RUN cargo install cargo-audit
RUN mkdir /app
WORKDIR /app/
COPY ./README.md /app/README.md
COPY ./Cargo* /app/
COPY ./benches /app/benches
COPY ./docs /app/docs
COPY ./src /app/src
COPY ./tests /app/tests
RUN cargo audit
RUN cargo check
RUN cargo test
RUN rm -rf /app/target
FROM debian:buster
COPY --from=builder /app /app
