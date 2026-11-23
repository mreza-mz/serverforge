#!/bin/bash
set -euo pipefail
directory=/run/serverforge-firewall
jail=/etc/fail2ban/jail.d/99-serverforge-sshd.local
action=$1
service=$2
token=$3

exec 9>/run/serverforge-firewall.lock
flock -x 9

case "$action" in
  arm)
    # Prepare under one lock. The EXIT handler removes an unarmed snapshot
    # if copying state or starting systemd's timer fails.
    armed=no
    reserved=no
    cleanup() {
      rm -f -- "$0"
      if [[ "$reserved" == yes && "$armed" == no ]]; then
        rm -rf -- "$directory"
      fi
    }
    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM
    mkdir -m 0700 "$directory"
    reserved=yes
    install -m 0700 "$0" "$directory/restore.sh"
    printf "%s\n" "$token" > "$directory/token"
    if [[ "$service" == ufw ]]; then
      cp -a /etc/ufw "$directory/ufw"
      cp -a /etc/default/ufw "$directory/default-ufw"
      status=$(LC_ALL=C /usr/sbin/ufw status)
      if grep -q '^Status: active' <<<"$status"; then touch "$directory/active"; fi
    else
      if [[ -e "$jail" ]]; then cp -a "$jail" "$directory/jail"; fi
      if systemctl is-active --quiet fail2ban; then touch "$directory/active"; fi
    fi
    if systemctl is-enabled --quiet "$service"; then touch "$directory/enabled"; fi
    if systemctl is-active --quiet "$service"; then touch "$directory/unit-active"; fi
    systemd-run --unit="serverforge-rollback-$token" --on-active=180s \
      --timer-property=AccuracySec=1s --collect /bin/bash "$directory/restore.sh" rollback "$service" "$token"
    armed=yes
    ;;
  rollback)
    [[ -f "$directory/token" && "$(<"$directory/token")" == "$token" ]] || exit 0
    if [[ "$service" == ufw ]]; then
      if [[ ! -f "$directory/unit-active" ]]; then systemctl stop ufw; fi
      /usr/sbin/ufw --force disable
      cp -a "$directory/ufw/." /etc/ufw/
      cp -a "$directory/default-ufw" /etc/default/ufw
      if [[ -f "$directory/active" ]]; then /usr/sbin/ufw --force enable; fi
    else
      systemctl stop fail2ban
      if [[ -f "$directory/jail" ]]; then
        cp -a "$directory/jail" "$jail"
      else
        rm -f "$jail"
      fi
      if [[ -f "$directory/active" ]]; then systemctl start fail2ban; fi
    fi
    if [[ -f "$directory/enabled" ]]; then
      systemctl enable "$service"
    else
      systemctl disable "$service"
    fi
    rm -rf -- "$directory"
    ;;
  commit)
    [[ -f "$directory/token" && "$(<"$directory/token")" == "$token" ]]
    systemctl stop "$4"
    rm -rf -- "$directory"
    ;;
  *) exit 2 ;;
esac
