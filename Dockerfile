# --- build stage ---
FROM rust:1-bookworm AS build
WORKDIR /app

# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Build the real binary.
COPY src ./src
RUN touch src/main.rs && cargo build --release

# --- runtime stage ---
FROM debian:bookworm-slim
WORKDIR /app
RUN useradd -m app
COPY --from=build /app/target/release/ghostdrop /usr/local/bin/ghostdrop
COPY public ./public

ENV PORT=3000
EXPOSE 3000
USER app
CMD ["ghostdrop"]
