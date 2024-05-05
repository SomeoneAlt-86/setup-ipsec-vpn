#!/bin/bash

# init script: install this script on a snapshot 

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT=$(date +%F-%T | tr ':' '_')

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null; }
bigecho() { echo "## $1"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_dns_name() {
  FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "Script must be run as root. Try 'sudo bash $0'"
  fi
}

check_vz() {
  if [ -f /proc/user_beancounters ]; then
    exiterr "OpenVZ VPS is not supported."
  fi
}

check_lxc() {
  # shellcheck disable=SC2154
  if [ "$container" = "lxc" ] && [ ! -e /dev/ppp ]; then
cat 1>&2 <<'EOF'
Error: /dev/ppp is missing. LXC containers require configuration.
       See: https://github.com/hwdsl2/setup-ipsec-vpn/issues/1014
EOF
  exit 1
  fi
}

check_os() {
  os_type=$(lsb_release -si 2>/dev/null)
  os_arch=$(uname -m | tr -dc 'A-Za-z0-9_-')
  [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
  case $os_type in
    [Uu]buntu)
      os_type=ubuntu
      ;;
    [Dd]ebian|[Kk]ali)
      os_type=debian
      ;;
    [Rr]aspbian)
      os_type=raspbian
      ;;
    *)
      exiterr "This script only supports Ubuntu and Debian."
      ;;
  esac
  os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
  if [ "$os_ver" = 8 ] || [ "$os_ver" = "jessiesid" ]; then
    exiterr "Debian 8 or Ubuntu < 16.04 is not supported."
  fi
  if [ "$os_type" = "ubuntu" ] && [ "$os_ver" = "bustersid" ] \
    && [ "$os_arch" != "x86_64" ]; then
cat 1>&2 <<EOF
Error: For Ubuntu 18.04, this script supports only the x86_64 architecture.
       This system runs on $os_arch and is unsupported.
EOF
    exit 1
  fi
}

check_iface() {
  if ! command -v route >/dev/null 2>&1 && ! command -v ip >/dev/null 2>&1; then
    wait_for_apt
    export DEBIAN_FRONTEND=noninteractive
    (
      set -x
      apt-get -yqq update || apt-get -yqq update
      apt-get -yqq install iproute2 >/dev/null
    )
  fi
  def_iface=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
  [ -z "$def_iface" ] && def_iface=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
  def_state=$(cat "/sys/class/net/$def_iface/operstate" 2>/dev/null)
  if [ -n "$def_state" ] && [ "$def_state" != "down" ]; then
    if ! uname -m | grep -qi -e '^arm' -e '^aarch64'; then
      case $def_iface in
        wl*)
          exiterr "Wireless interface '$def_iface' detected. DO NOT run this script on your PC or Mac!"
          ;;
      esac
    fi
    NET_IFACE="$def_iface"
  else
    eth0_state=$(cat "/sys/class/net/eth0/operstate" 2>/dev/null)
    if [ -z "$eth0_state" ] || [ "$eth0_state" = "down" ]; then
      exiterr "Could not detect the default network interface."
    fi
    NET_IFACE=eth0
  fi
}

check_dns() {
  if { [ -n "$VPN_DNS_SRV1" ] && ! check_ip "$VPN_DNS_SRV1"; } \
    || { [ -n "$VPN_DNS_SRV2" ] && ! check_ip "$VPN_DNS_SRV2"; }; then
    exiterr "The DNS server specified is invalid."
  fi
}

check_server_dns() {
  if [ -n "$VPN_DNS_NAME" ] && ! check_dns_name "$VPN_DNS_NAME"; then
    exiterr "Invalid DNS name. 'VPN_DNS_NAME' must be a fully qualified domain name (FQDN)."
  fi
}

check_client_name() {
  if [ -n "$VPN_CLIENT_NAME" ]; then
    name_len="$(printf '%s' "$VPN_CLIENT_NAME" | wc -m)"
    if [ "$name_len" -gt "64" ] || printf '%s' "$VPN_CLIENT_NAME" | LC_ALL=C grep -q '[^A-Za-z0-9_-]\+' \
      || case $VPN_CLIENT_NAME in -*) true ;; *) false ;; esac; then
      exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
    fi
  fi
}

check_subnets() {
  if [ -s /etc/ipsec.conf ] && grep -qs "hwdsl2 VPN script" /etc/sysctl.conf; then
    L2TP_NET=${VPN_L2TP_NET:-'192.168.42.0/24'}
    XAUTH_NET=${VPN_XAUTH_NET:-'192.168.43.0/24'}
    if ! grep -q "$L2TP_NET" /etc/ipsec.conf \
      || ! grep -q "$XAUTH_NET" /etc/ipsec.conf; then
      echo "Error: The custom VPN subnets specified do not match initial install." >&2
      echo "       See Advanced usage -> Customize VPN subnets for more information." >&2
      exit 1
    fi
  fi
}

check_iptables() {
  if [ -x /sbin/iptables ] && ! iptables -nL INPUT >/dev/null 2>&1; then
    exiterr "IPTables check failed. Reboot and re-run this script."
  fi
}

start_setup() {
  bigecho "VPN setup in progress... Please be patient."
  mkdir -p /opt/src
  cd /opt/src || exit 1
}

wait_for_apt() {
  count=0
  apt_lk=/var/lib/apt/lists/lock
  pkg_lk=/var/lib/dpkg/lock
  while fuser "$apt_lk" "$pkg_lk" >/dev/null 2>&1 \
    || lsof "$apt_lk" >/dev/null 2>&1 || lsof "$pkg_lk" >/dev/null 2>&1; do
    [ "$count" = 0 ] && echo "## Waiting for apt to be available..."
    [ "$count" -ge 100 ] && exiterr "Could not get apt/dpkg lock."
    count=$((count+1))
    printf '%s' '.'
    sleep 3
  done
}

update_apt_cache() {
  bigecho "Installing packages required for setup..."
  export DEBIAN_FRONTEND=noninteractive
  (
    set -x
    apt-get -yqq update || apt-get -yqq update
  ) || exiterr "'apt-get update' failed."
}

install_setup_pkgs() {
  (
    set -x
    apt-get -yqq install wget dnsutils openssl \
      iptables iproute2 gawk grep sed net-tools >/dev/null \
    || apt-get -yqq install wget dnsutils openssl \
      iptables iproute2 gawk grep sed net-tools >/dev/null
  ) || exiterr2
}

get_default_ip() {
  def_ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
  if check_ip "$def_ip" \
    && ! printf '%s' "$def_ip" | grep -Eq '^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'; then
    public_ip="$def_ip"
  fi
}

detect_ip() {
  public_ip=${VPN_PUBLIC_IP:-''}
  check_ip "$public_ip" || get_default_ip
  check_ip "$public_ip" && return 0
  bigecho "Trying to auto discover IP of this server..."
  check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ipv4.icanhazip.com)
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ip1.dynupdate.no-ip.com)
  check_ip "$public_ip" || exiterr "Cannot detect this server's public IP. Define it as variable 'VPN_PUBLIC_IP' and re-run this script."
}

install_vpn_pkgs() {
  bigecho "Installing packages required for the VPN..."
  (
    set -x
    apt-get -yqq install libnss3-dev libnspr4-dev pkg-config \
      libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
      libcurl4-nss-dev flex bison gcc make libnss3-tools \
      libevent-dev libsystemd-dev uuid-runtime ppp xl2tpd >/dev/null
  ) || exiterr2
  if [ "$os_type" = "debian" ] && [ "$os_ver" = 12 ]; then
    (
      set -x
      apt-get -yqq install rsyslog >/dev/null
    ) || exiterr2
  fi
}

install_nss_pkgs() {
  if [ "$os_type" = "ubuntu" ] && [ "$os_ver" = "bustersid" ] && [ "$os_arch" = "x86_64" ] \
    && ! dpkg -l libnss3-dev 2>/dev/null | grep -qF '3.49.1'; then
    base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
    nss_url1="https://mirrors.kernel.org/ubuntu/pool/main/n/nss"
    nss_url2="https://mirrors.kernel.org/ubuntu/pool/universe/n/nss"
    deb1="libnss3_3.49.1-1ubuntu1.9_amd64.deb"
    deb2="libnss3-dev_3.49.1-1ubuntu1.9_amd64.deb"
    deb3="libnss3-tools_3.49.1-1ubuntu1.9_amd64.deb"
    bigecho "Installing NSS packages on Ubuntu 18.04..."
    cd /opt/src || exit 1
    nss_dl=0
    /bin/rm -f "$deb1" "$deb2" "$deb3"
    if wget -t 3 -T 30 -q "$base_url/$deb1" "$base_url/$deb2" "$base_url/$deb3"; then
      apt-get -yqq install "./$deb1" "./$deb2" "./$deb3" >/dev/null
    else
      /bin/rm -f "$deb1" "$deb2" "$deb3"
      if wget -t 3 -T 30 -q "$nss_url1/$deb1" "$nss_url1/$deb2" "$nss_url2/$deb3"; then
        apt-get -yqq install "./$deb1" "./$deb2" "./$deb3" >/dev/null
      else
        nss_dl=1
        echo "Error: Could not download NSS packages." >&2
      fi
    fi
    /bin/rm -f "$deb1" "$deb2" "$deb3"
    [ "$nss_dl" = 1 ] && exit 1
  fi
}

install_fail2ban() {
  bigecho "Installing Fail2Ban to protect SSH..."
  (
    set -x
    apt-get -yqq install fail2ban >/dev/null
  )
}

link_scripts() {
  cd /opt/src || exit 1
  /bin/mv -f ikev2setup.sh ikev2.sh
  /bin/mv -f add_vpn_user.sh addvpnuser.sh
  /bin/mv -f del_vpn_user.sh delvpnuser.sh
  echo "+ ikev2.sh addvpnuser.sh delvpnuser.sh"
  for sc in ikev2.sh addvpnuser.sh delvpnuser.sh; do
    [ -s "$sc" ] && chmod +x "$sc" && ln -s "/opt/src/$sc" /usr/bin 2>/dev/null
  done
}

get_helper_scripts() {
  bigecho "Downloading helper scripts..."
  base1="https://raw.githubusercontent.com/hwdsl2/setup-ipsec-vpn/master/extras"
  base2="https://gitlab.com/hwdsl2/setup-ipsec-vpn/-/raw/master/extras"
  sc1=ikev2setup.sh
  sc2=add_vpn_user.sh
  sc3=del_vpn_user.sh
  cd /opt/src || exit 1
  /bin/rm -f "$sc1" "$sc2" "$sc3"
  if wget -t 3 -T 30 -q "$base1/$sc1" "$base1/$sc2" "$base1/$sc3"; then
    link_scripts
  else
    /bin/rm -f "$sc1" "$sc2" "$sc3"
    if wget -t 3 -T 30 -q "$base2/$sc1" "$base2/$sc2" "$base2/$sc3"; then
      link_scripts
    else
      echo "Warning: Could not download helper scripts." >&2
      /bin/rm -f "$sc1" "$sc2" "$sc3"
    fi
  fi
}

get_swan_ver() {
  SWAN_VER=4.14
  base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
  swan_ver_url="$base_url/v1-$os_type-$os_ver-swanver"
  swan_ver_latest=$(wget -t 2 -T 10 -qO- "$swan_ver_url" | head -n 1)
  [ -z "$swan_ver_latest" ] && swan_ver_latest=$(curl -m 10 -fsL "$swan_ver_url" 2>/dev/null | head -n 1)
  if printf '%s' "$swan_ver_latest" | grep -Eq '^([3-9]|[1-9][0-9]{1,2})(\.([0-9]|[1-9][0-9]{1,2})){1,2}$'; then
    SWAN_VER="$swan_ver_latest"
  fi
}

check_libreswan() {
  check_result=0
  ipsec_ver=$(/usr/local/sbin/ipsec --version 2>/dev/null)
  swan_ver_old=$(printf '%s' "$ipsec_ver" | sed -e 's/.*Libreswan U\?//' -e 's/\( (\|\/K\).*//')
  ipsec_bin="/usr/local/sbin/ipsec"
  if [ -n "$swan_ver_old" ] && printf '%s' "$ipsec_ver" | grep -qi 'libreswan' \
    && [ "$(find "$ipsec_bin" -mmin -10080)" ]; then
    check_result=1
    return 0
  fi
  get_swan_ver
  if [ -s "$ipsec_bin" ] && [ "$swan_ver_old" = "$SWAN_VER" ]; then
    touch "$ipsec_bin"
  fi
  [ "$swan_ver_old" = "$SWAN_VER" ] && check_result=1
}

get_libreswan() {
  if [ "$check_result" = 0 ]; then
    bigecho "Downloading Libreswan..."
    cd /opt/src || exit 1
    swan_file="libreswan-$SWAN_VER.tar.gz"
    swan_url1="https://github.com/libreswan/libreswan/archive/v$SWAN_VER.tar.gz"
    swan_url2="https://download.libreswan.org/$swan_file"
    (
      set -x
      wget -t 3 -T 30 -q -O "$swan_file" "$swan_url1" || wget -t 3 -T 30 -q -O "$swan_file" "$swan_url2"
    ) || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    tar xzf "$swan_file" && /bin/rm -f "$swan_file"
  else
    bigecho "Libreswan $swan_ver_old is already installed, skipping..."
  fi
}

install_libreswan() {
  if [ "$check_result" = 0 ]; then
    bigecho "Compiling and installing Libreswan, please wait..."
    cd "libreswan-$SWAN_VER" || exit 1
cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS=-w -s
USE_DNSSEC=false
USE_DH2=true
USE_NSS_KDF=false
FINALNSSDIR=/etc/ipsec.d
EOF
    if ! grep -qs IFLA_XFRM_LINK /usr/include/linux/if_link.h; then
      echo "USE_XFRM_INTERFACE_IFLA_HEADER=true" >> Makefile.inc.local
    fi
    NPROCS=$(grep -c ^processor /proc/cpuinfo)
    [ -z "$NPROCS" ] && NPROCS=1
    (
      set -x
      make "-j$((NPROCS+1))" -s base >/dev/null && make -s install-base >/dev/null
    )
    cd /opt/src || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    if ! /usr/local/sbin/ipsec --version 2>/dev/null | grep -qF "$SWAN_VER"; then
      exiterr "Libreswan $SWAN_VER failed to build."
    fi
  fi
}


vpnsetup() {
  check_root
  check_vz
  check_lxc
  check_os
  check_iface
  check_dns
  check_server_dns
  check_client_name
  check_subnets
  check_iptables
  check_libreswan
  start_setup
  wait_for_apt
  update_apt_cache
  install_setup_pkgs
  detect_ip
  install_vpn_pkgs
  install_nss_pkgs
  install_fail2ban
  get_helper_scripts
  get_libreswan
  install_libreswan
}

## Defer setup until we have the complete script
vpnsetup "$@"

exit "$status"
