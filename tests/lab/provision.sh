#!/usr/bin/env bash
# Provision a lab VM (Ubuntu 20.04-24.04) to build the agent and run the
# oracles. Mirrors .github/workflows/oracle.yml. Run inside the VM as a
# sudo-capable user: bash tests/lab/provision.sh
set -euo pipefail
BPF_TOOLCHAIN=${BPF_TOOLCHAIN:-nightly-2026-02-17}
BPF_LINKER_VERSION=${BPF_LINKER_VERSION:-0.10.3}
VENV=${VENV:-/opt/oracle-venv}

sudo apt-get update -qq
# clang-18/llvm-18 as in CI where the release ships them (noble); older
# releases get their default clang/llvm. The eBPF build itself links with
# bpf-linker against the nightly's own LLVM, so either works.
llvm=(clang-18 llvm-18)
apt-cache policy clang-18 | grep -q "Candidate: [0-9]" || llvm=(clang llvm)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq "${llvm[@]}" libelf-dev "linux-headers-$(uname -r)" \
  pkg-config libssl-dev openssl build-essential curl git rsync \
  golang-go docker.io python3-pip python3-venv iproute2 util-linux >/dev/null
sudo usermod -aG docker "$USER"

if ! command -v rustup >/dev/null && [[ ! -x ~/.cargo/bin/rustup ]]; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain none
fi
export PATH=$HOME/.cargo/bin:$PATH
rustup toolchain install "$BPF_TOOLCHAIN" --profile minimal -c rust-src
rustup toolchain install 1.93.0 --profile minimal -c rust-src
command -v bpf-linker >/dev/null ||
  cargo +"$BPF_TOOLCHAIN" install -q bpf-linker --locked --version "$BPF_LINKER_VERSION"

sudo python3 -m venv "$VENV"
sudo "$VENV/bin/pip" install -q pyroute2 redis 'psycopg[binary]' pymysql cryptography \
  grpcio mysql-connector-python confluent-kafka kafka-python pika dnspython
echo "provisioned: kernel $(uname -r), $(rustc +"$BPF_TOOLCHAIN" -V), $(bpf-linker --version), $(go version)"
