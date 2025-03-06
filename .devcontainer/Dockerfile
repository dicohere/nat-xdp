FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

USER vscode
RUN rustup toolchain install nightly
RUN rustup component add --toolchain nightly rust-src
RUN cargo install bpf-linker
USER root
