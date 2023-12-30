FROM rust:alpine

RUN apk add --no-cache musl-dev gcc

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

COPY . .

RUN cargo build --release

RUN cp /app/target/release/notes-actix /app/

RUN cargo clean

EXPOSE 9001

CMD ["./notes-actix"]