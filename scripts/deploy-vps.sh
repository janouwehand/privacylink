#!/usr/bin/env bash
set -euo pipefail

environment="${1:-}"
image="${2:-}"

case "$environment" in
  staging|production) ;;
  *) echo 'Environment must be staging or production.' >&2; exit 64 ;;
esac

if [[ ! "$image" =~ ^ghcr\.io/janouwehand/privacylink@sha256:[a-f0-9]{64}$ ]]; then
  echo 'Image must be the expected GHCR image pinned by a SHA-256 digest.' >&2
  exit 64
fi

: "${VPS_HOST:?Set VPS_HOST in the selected GitHub environment}"
: "${VPS_USER:?Set VPS_USER in the selected GitHub environment}"
: "${VPS_SSH_PRIVATE_KEY:?Set VPS_SSH_PRIVATE_KEY in the selected GitHub environment}"
: "${VPS_SSH_KNOWN_HOSTS:?Set VPS_SSH_KNOWN_HOSTS in the selected GitHub environment}"

ssh_dir="$(mktemp -d)"
trap 'rm -rf "$ssh_dir"' EXIT
key_file="$ssh_dir/id_ed25519"
known_hosts_file="$ssh_dir/known_hosts"
printf '%s\n' "$VPS_SSH_PRIVATE_KEY" > "$key_file"
printf '%s\n' "$VPS_SSH_KNOWN_HOSTS" > "$known_hosts_file"
chmod 600 "$key_file" "$known_hosts_file"

ssh_options=(-i "$key_file" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o "UserKnownHostsFile=$known_hosts_file")
remote="$VPS_USER@$VPS_HOST"
ssh "${ssh_options[@]}" "$remote" "sudo /usr/local/sbin/privacylink-deploy '$environment' '$image'"

