#!/usr/bin/env bash
# Unprivileged KVM lab for running the agent on several kernels.
#
#   vm.sh up <name> <noble|noble-hwe|jammy|focal|rocky8|rocky9> [vcpus=32] [mem_gb=32]
#   vm.sh ssh <name> [cmd...]      vm.sh down <name>
#   vm.sh port <name>              vm.sh list
#   vm.sh destroy-all              (kills every lab VM, rm -rf $LAB)
#
# Needs only qemu-system-x86_64, qemu-img, ssh and membership of the kvm
# group: user-mode networking with an SSH hostfwd on 127.0.0.1, and the
# cloud-init seed served from a directory as a vvfat drive labelled cidata.
# Everything lives under $LAB (default ~/.cache/panopticon-lab), which must be
# a directory owned by you; it is kept at mode 0700. The SSH key in it gets
# passwordless root in every VM, so a shared path such as /tmp is unsafe on a
# multi-user host: set LAB=/tmp/panopticon-lab only on a single-user box.
set -euo pipefail
LAB=${LAB:-${XDG_CACHE_HOME:-$HOME/.cache}/panopticon-lab}
KEY=$LAB/id_ed25519
IMG=$LAB/images
VMS=$LAB/vms
URL=https://cloud-images.ubuntu.com
ROCKY=https://dl.rockylinux.org/pub/rocky

die() { echo "vm.sh: $*" >&2; exit 1; }
owned() { [[ ! -L $1 && $(stat -c %u "$1") == "$(id -u)" ]]; } # not a symlink, ours

check_lab() { # refuse a lab dir (or key) another user created or could write
  [[ -e $LAB || -L $LAB ]] || { mkdir -p "$(dirname "$LAB")"; mkdir -m 700 "$LAB"; }
  if [[ ! -d $LAB ]] || ! owned "$LAB"; then
    die "$LAB is not a directory owned by $(id -un); refusing"
  fi
  # Tightening our own dir is safe; anything planted while it was looser is
  # caught by the ownership checks on the key below.
  [[ $(stat -c %a "$LAB") == 700 ]] || chmod 700 "$LAB"
  local f
  for f in "$KEY" "$KEY.pub"; do
    [[ -e $f || -L $f ]] && ! owned "$f" && die "$f is not owned by $(id -un); refusing to use it"
  done
  return 0
}
vmdir() { [[ -d $VMS/$1 ]] || die "no VM named $1"; echo "$VMS/$1"; }
running() { [[ -f $1/pid ]] && kill -0 "$(cat "$1/pid")" 2>/dev/null; }

sshvm() { # sshvm <dir> [cmd...]; one shared control connection per VM
  local d=$1; shift
  ssh -i "$KEY" -p "$(cat "$d/port")" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 \
    -o ServerAliveInterval=30 -o ControlMaster=auto \
    -o ControlPath="$LAB/cm-%p" -o ControlPersist=10m ubuntu@127.0.0.1 "$@"
}
ctl_exit() { ssh -o ControlPath="$LAB/cm-$(cat "$1/port")" -O exit x 2>/dev/null || true; }

wait_ssh() { # wait_ssh <dir>: up to 10 minutes
  for _ in $(seq 120); do
    running "$1" || die "qemu exited; see $1/serial.log"
    sshvm "$1" true 2>/dev/null && return 0
    sleep 5
  done
  die "no SSH after 10 minutes; see $1/serial.log"
}

boot() { # boot <dir>
  local d=$1
  qemu-system-x86_64 -enable-kvm -cpu host -machine q35 \
    -smp "$(cat "$d/vcpus")" -m "$(cat "$d/mem_gb")G" \
    -drive file="$d/disk.qcow2",if=virtio,discard=unmap \
    -drive driver=vvfat,dir="$d/seed",label=cidata,if=virtio,read-only=on \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$(cat "$d/port")"-:22 \
    -device virtio-net-pci,netdev=n0 \
    -display none -serial file:"$d/serial.log" \
    -daemonize -pidfile "$d/pid"
}

free_port() { # first port from 2230 not used by a lab VM or any listener
  local p=2230
  while cat "$VMS"/*/port 2>/dev/null | grep -qx "$p" ||
    ss -Htln "sport = :$p" | grep -q .; do p=$((p + 1)); done
  echo "$p"
}

up() {
  local name=${1:?name} rel=${2:?release} vcpus=${3:-32} mem=${4:-32} base src d t
  case $rel in
    noble | noble-hwe) base=noble ;;
    jammy | focal | rocky8 | rocky9) base=$rel ;;
    *) die "release must be noble, noble-hwe, jammy, focal, rocky8 or rocky9" ;;
  esac
  src=$URL/$base/current/$base-server-cloudimg-amd64.img
  # Latest Rocky 8.x / 9.x GenericCloud qcow2 (RHEL 8: 4.18, RHEL 9: 5.14).
  [[ $base == rocky* ]] &&
    src=$ROCKY/${base#rocky}/images/x86_64/Rocky-${base#rocky}-GenericCloud-Base.latest.x86_64.qcow2
  d=$VMS/$name
  [[ -e $d ]] && die "$name exists; vm.sh down $name first"
  mkdir -p "$IMG" "$VMS"
  [[ -f $KEY ]] || ssh-keygen -q -t ed25519 -N '' -C panopticon-lab -f "$KEY"
  if [[ ! -f $IMG/$base.img ]]; then
    curl -fsSL --retry 3 -o "$IMG/$base.img.part" "$src"
    mv "$IMG/$base.img.part" "$IMG/$base.img"
  fi
  mkdir -p "$d/seed"
  echo "$vcpus" >"$d/vcpus"; echo "$mem" >"$d/mem_gb"; echo "$rel" >"$d/release"
  free_port >"$d/port"
  qemu-img create -q -f qcow2 -F qcow2 -b "$IMG/$base.img" "$d/disk.qcow2" 80G
  printf 'instance-id: %s\nlocal-hostname: %s\n' "$name" "$name" >"$d/seed/meta-data"
  cat >"$d/seed/user-data" <<EOF
#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: [$(cat "$KEY.pub")]
EOF
  t=$(date +%s)
  boot "$d"
  wait_ssh "$d"
  sshvm "$d" 'cloud-init status --wait >/dev/null || true'
  if [[ $rel == noble-hwe ]]; then
    sshvm "$d" 'sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive \
      apt-get install -yq linux-generic-hwe-24.04 >/dev/null && sudo reboot' || true
    ctl_exit "$d"
    sleep 10
    wait_ssh "$d"
  fi
  echo "$name up in $(($(date +%s) - t))s: port $(cat "$d/port"), kernel $(sshvm "$d" uname -r)"
}

down() {
  local d; d=$(vmdir "${1:?name}")
  if running "$d"; then
    ctl_exit "$d"
    kill "$(cat "$d/pid")"
  fi
  rm -rf "$d"
}

list() {
  local d
  for d in "$VMS"/*/; do
    [[ -f $d/port ]] || continue
    printf '%-16s %-10s port %s  %s vcpu %sG  %s\n' "$(basename "$d")" \
      "$(cat "$d/release")" "$(cat "$d/port")" "$(cat "$d/vcpus")" \
      "$(cat "$d/mem_gb")" "$(running "$d" && echo running || echo stopped)"
  done
}

destroy_all() {
  local p
  for p in "$VMS"/*/pid; do [[ -f $p ]] && kill "$(cat "$p")" 2>/dev/null || true; done
  for p in "$LAB"/cm-*; do [[ -S $p ]] && ssh -o ControlPath="$p" -O exit x 2>/dev/null || true; done
  rm -rf "$LAB"
}

cmd=${1:-}; shift || true
case $cmd in up | ssh | port | down | list | destroy-all) check_lab ;; esac
case $cmd in
  up) up "$@" ;;
  ssh) d=$(vmdir "${1:?name}"); shift; sshvm "$d" "$@" ;;
  port) cat "$(vmdir "${1:?name}")/port" ;;
  down) down "$@" ;;
  list) list ;;
  destroy-all) destroy_all ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
