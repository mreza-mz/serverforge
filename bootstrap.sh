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
    amd64) go_sha=9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec; go_zip_sha=e1edb778de0aa08c8e827f5a873b35a46afe680fb241482c531725b2355e470d ;;
    arm64) go_sha=6c2f29b458b5add0835f18b776f69c8881a6d88428f1484a6da55755e620757e; go_zip_sha=51902dab7e130b07083119a36ce09e0cc50fdd9d0d64184c24bd302072ad8b70 ;;
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
command -v git >/dev/null || packages+=(git)
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
go_bin=go
go_version=$(GOTOOLCHAIN=local go version 2>/dev/null || true)
if [[ ! $go_version =~ go([0-9]+\.[0-9]+) ]] ||
    ! dpkg --compare-versions "${BASH_REMATCH[1]}" ge 1.26; then
    printf '%s\n' 'Downloading the Go build toolchain.'
    if curl -fsSL "https://go.dev/dl/go1.26.11.linux-$arch.tar.gz" -o "$work/go.tar.gz"; then
        printf '%s  %s\n' "$go_sha" "$work/go.tar.gz" | sha256sum -c --status ||
            fail "The Go archive checksum does not match."
        tar -xzf "$work/go.tar.gz" -C "$work"
        go_bin="$work/go/bin/go"
    else
        printf '%s\n' 'Trying the official Go module proxy.'
        module_version="v0.0.1-go1.26.11.linux-$arch"
        curl -fsSL "https://proxy.golang.org/golang.org/toolchain/@v/$module_version.zip" -o "$work/go.zip" ||
            fail "Could not download Go from either official source."
        printf '%s  %s\n' "$go_zip_sha" "$work/go.zip" | sha256sum -c --status ||
            fail "The Go module archive checksum does not match."
        if ! command -v unzip >/dev/null; then
            "${privilege[@]}" apt-get update </dev/null
            "${privilege[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y unzip </dev/null
        fi
        unzip -q "$work/go.zip" -d "$work"
        toolchain="$work/golang.org/toolchain@$module_version"
        chmod +x "$toolchain"/bin/* "$toolchain"/pkg/tool/linux_"$arch"/*
        go_bin="$toolchain/bin/go"
    fi
fi

if ! ansible_ready; then
    printf '%s\n' 'Installing Ansible Core in an isolated Python environment.'
    if ! command -v uv >/dev/null; then pipx install uv </dev/null; fi
    uv tool install --python 3.12 'ansible-core==2.20.11' </dev/null
    hash -r
    ansible_ready || fail "Ansible Core 2.20 or later must be available on PATH."
fi

printf '%s\n' 'Building ServerForge.'
git clone --quiet --depth 1 https://github.com/mreza-mz/serverforge.git "$work/source" </dev/null
(cd "$work/source" && GOTOOLCHAIN=local "$go_bin" build -trimpath -o "$work/serverforge" ./cmd/serverforge)
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
