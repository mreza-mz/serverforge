#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf 'ServerForge: %s\n' "$*" >&2; exit 1; }

install_only=false
ssh_controller=false
setup_args=()
while (($#)); do
    case "$1" in
        --install-only) install_only=true ;;
        --ssh-controller) ssh_controller=true ;;
        --dry-run|--resume) setup_args+=("$1") ;;
        --config)
            (($# > 1)) || fail "Supply a path after --config."
            setup_args+=("$1" "$2")
            shift ;;
        -h|--help)
            printf '%s\n' 'Usage: bash bootstrap.sh [--install-only] [--ssh-controller] [--dry-run|--resume] [--config PATH]'
            exit 0 ;;
        *) fail "Unknown option. See --help." ;;
    esac
    shift
done

. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" =~ ^(22\.04|24\.04|26\.04)$ ]] ||
    fail "Use Ubuntu 22.04, 24.04, or 26.04 LTS."
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64) binary_sha=dd98729829929018b33f1d0650b6e6ca7d55d705464536525f9b79bd9b2562b4 ;;
    arm64) binary_sha=b3b6057aa53474569b2486ce0bdda7184f6c9ef14f80a6bf78e39e38ed494e3a ;;
    *) fail "Supported architectures are amd64 and arm64." ;;
esac

if ! "$install_only"; then
    [[ -t 1 && -t 2 ]] && ( : </dev/tty ) 2>/dev/null || fail "Open a terminal, or use --install-only."
fi
privilege=()
if ((EUID != 0)); then privilege=(sudo); fi
export PATH="$HOME/.local/bin:$PATH"

ansible_ready() {
    local version
    version=$(ansible-playbook --version 2>/dev/null) || return 1
    [[ $version =~ \[core\ ([0-9]+\.[0-9]+) ]] || return 1
    dpkg --compare-versions "${BASH_REMATCH[1]}" ge 2.20
}

packages=()
command -v curl >/dev/null || packages+=(curl)
if "$ssh_controller" && ! command -v ssh >/dev/null; then packages+=(openssh-client); fi
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
if ! ansible_ready && ! command -v uv >/dev/null && ! command -v pipx >/dev/null; then
    packages+=(pipx)
fi
if (("${#packages[@]}" > 0)); then
    printf 'Installing bootstrap packages: %s\n' "${packages[*]}"
    "${privilege[@]}" apt-get update </dev/null
    "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" </dev/null
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
download_base=${SERVERFORGE_DOWNLOAD_BASE:-https://github.com/mreza-mz/serverforge/releases/download/v0.3.0}
[[ $download_base == https://* ]] || fail "The binary download URL must use HTTPS."
asset="serverforge-linux-$arch"
printf '%s\n' 'Downloading the ServerForge binary.'
curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 -o "$work/serverforge" -- "${download_base%/}/$asset" ||
    fail "Could not download ServerForge. Set SERVERFORGE_DOWNLOAD_BASE to an HTTPS mirror hosting the release assets."
printf '%s  %s\n' "$binary_sha" "$work/serverforge" | sha256sum -c --status ||
    fail "The ServerForge binary checksum does not match."

if ! ansible_ready; then
    printf '%s\n' 'Installing Ansible Core in an isolated Python environment.'
    if ! command -v uv >/dev/null; then pipx install uv </dev/null; fi
    uv tool install --python 3.12 'ansible-core==2.20.11' </dev/null
    hash -r
    ansible_ready || fail "Ansible Core 2.20 or later must be available on PATH."
fi

destination="$HOME/.local/bin/serverforge"
install -D -m 0755 "$work/serverforge" "$destination"
printf 'ServerForge installed at %s\n' "$destination"

if ! "$install_only"; then
    if "$ssh_controller"; then
        "$destination" setup "${setup_args[@]}" </dev/tty
    else
        ansible_dir=$(dirname "$(command -v ansible-playbook)")
        "${privilege[@]}" env "PATH=$ansible_dir:/usr/sbin:/usr/bin:/sbin:/bin" \
            "$destination" setup "${setup_args[@]}" </dev/tty
    fi
fi
