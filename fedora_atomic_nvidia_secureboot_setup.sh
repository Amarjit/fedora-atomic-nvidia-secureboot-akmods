#!/usr/bin/env bash
# Fedora Atomic / rpm-ostree NVIDIA + Secure Boot akmods setup helper
#
# Created and maintained by Amarjit Bharath.
#
# WHAT THIS IS
#   A resumable setup script for Fedora Atomic / rpm-ostree desktops that use the
#   NVIDIA proprietary driver with Secure Boot enabled.
#
#   Target systems include Fedora Silverblue, Kinoite, Sway Atomic, Budgie Atomic,
#   COSMIC Atomic, and other Fedora Atomic variants. It intentionally does not
#   depend on a specific desktop environment.
#
# WHY THIS EXISTS
#   NVIDIA's proprietary kernel module is not accepted by Secure Boot unless the
#   module is signed with a key that your firmware/kernel trusts.
#
#   On traditional Fedora Workstation, akmods can usually use keys from:
#       /etc/pki/akmods/
#
#   On Fedora Atomic / rpm-ostree systems, akmods can build modules in a context
#   where the normal host /etc/pki/akmods keys are not visible in the way kmod
#   signing expects. The common workaround is to package your local signing key
#   into a local RPM called:
#       akmods-keys
#
# SECURITY CAVEAT
#   The akmods-keys RPM contains your private MOK signing key. This is the ugly
#   but practical tradeoff for automatic future NVIDIA/kernel rebuilds with
#   Secure Boot enabled on Fedora Atomic.
#
#   Do NOT share:
#       - the private key
#       - the generated akmods-keys RPM
#       - backups containing either of those files
#
#   If an attacker already has root while this key is present, they could sign a
#   malicious kernel module that your Secure Boot setup would trust. For a normal
#   personal workstation this is often acceptable because root already means the
#   machine is largely compromised, but it is not ideal for high-security or
#   hostile multi-user environments.
#
# IMPORTANT GOTCHA
#   Do not remove akmods-keys while keeping akmod-nvidia installed. akmods may
#   automatically rebuild NVIDIA modules later. Without akmods-keys, those rebuilt
#   modules can be unsigned, and Secure Boot will reject them with:
#       Key was rejected by service
#       Loading of unsigned module is rejected
#
# HOW TO USE
#   chmod +x fedora_atomic_nvidia_secureboot_setup.sh
#   sudo ./fedora_atomic_nvidia_secureboot_setup.sh
#
#   Diagnostic-only mode, does not stage rpm-ostree changes:
#       sudo ./fedora_atomic_nvidia_secureboot_setup.sh --status
#
#   When the script says a reboot is required, reboot, then run the script again.
#   It checks the current state and resumes from the next required step.
#
# MOK ENROLLMENT REBOOT INSTRUCTIONS
#   If the script runs mokutil --import, it will ask you to create a temporary
#   password. That password is NOT your Linux login password. You only use it once
#   in the blue MOK Manager screen during the next reboot.
#
#   On reboot, choose roughly:
#       Enroll MOK
#       Continue
#       Yes
#       enter the temporary password you created
#       Reboot
#
#   Then boot back into Fedora and run this script again.
#
# WHAT IT DOES
#   - checks this is an rpm-ostree Fedora Atomic system
#   - checks/stages RPM Fusion repositories
#   - checks/stages NVIDIA packages
#   - adds nouveau blacklist and nvidia-drm.modeset=1 kernel args
#   - creates or reuses a local akmods signing key
#   - checks/enrolls the public MOK key
#   - builds and installs a local akmods-keys RPM
#   - uses akmods to build a signed NVIDIA kmod RPM
#   - inspects signatures inside generated kmod RPMs
#   - normally lets akmods provide the signed NVIDIA module automatically
#   - optionally layers the signed kmod RPM only with --layer-kmod-rpm recovery mode
#   - verifies module signer, Secure Boot state, and nvidia-smi

set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
STATE_DIR="/var/lib/atomic-nvidia-secureboot-setup"
BUILD_DIR="$STATE_DIR/akmods-keys-local"
QUARANTINE_DIR="$STATE_DIR/quarantine/akmods/nvidia"
LOG_FILE="$STATE_DIR/setup.log"
AKMODS_CERT_DIR="/etc/pki/akmods/certs"
AKMODS_PRIV_DIR="/etc/pki/akmods/private"
PACKAGED_CERT="/etc/pki/akmods-keys/certs/public_key.der"
PACKAGED_PRIV="/etc/pki/akmods-keys/private/private_key.priv"
MACRO_FILE="/etc/rpm/macros.kmodtool"
MODE="run"
LAYER_KMOD_RPM="no"

KARGS=(
  "rd.driver.blacklist=nouveau"
  "modprobe.blacklist=nouveau"
  "nvidia-drm.modeset=1"
)

REQUIRED_PACKAGES=(
  "akmod-nvidia"
  "xorg-x11-drv-nvidia-cuda"
)

case "${1:-}" in
  --layer-kmod-rpm)
    LAYER_KMOD_RPM="yes"
    ;;
  --status|-s)
    MODE="status"
    ;;
  --help|-h)
    cat <<'EOF'
Fedora Atomic NVIDIA + Secure Boot setup helper

Usage:
  sudo ./fedora_atomic_nvidia_secureboot_setup.sh
  sudo ./fedora_atomic_nvidia_secureboot_setup.sh --layer-kmod-rpm
  sudo ./fedora_atomic_nvidia_secureboot_setup.sh --status

Modes:
  default     Run/resume setup. May stage rpm-ostree changes and ask for reboots.
  --status   Diagnostic-only. Shows current state and does not stage rpm-ostree changes.

Options:
  --layer-kmod-rpm
      Recovery mode. Manually layer the generated kmod-nvidia RPM into rpm-ostree.
      Not normally needed. Kernel-specific kmod RPMs may block future upgrades.
EOF
    exit 0
    ;;
  "")
    ;;
  *)
    printf 'Unknown option: %s
Use --help for usage.
' "$1" >&2
    exit 2
    ;;
esac

if [[ "$#" -gt 1 ]]; then
  printf 'Too many arguments.
Use --help for usage.
' >&2
  exit 2
fi

log() {
  printf '
[%s] %s
' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"
}

warn() {
  printf '
[%s] WARNING: %s
' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2
}

fail() {
  printf '
[%s] ERROR: %s
' "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2
  exit 1
}

explain() {
  printf '
---
%s
---
' "$*" | tee -a "$LOG_FILE"
}

run() {
  log "+ $*"
  "$@" 2>&1 | tee -a "$LOG_FILE"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    exec sudo --preserve-env=PATH bash "$0" "$@"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

is_rpm_installed() {
  rpm -q "$1" >/dev/null 2>&1
}

rpm_qa_matches() {
  rpm -qa | grep -Eq "$1"
}

is_atomic_system() {
  [[ -e /run/ostree-booted ]] && command -v rpm-ostree >/dev/null 2>&1
}

current_kernel() {
  uname -r
}

secure_boot_state() {
  mokutil --sb-state 2>/dev/null || true
}

is_secure_boot_enabled() {
  secure_boot_state | grep -qi 'SecureBoot enabled'
}

pending_rpm_ostree_changes() {
  rpm-ostree status 2>/dev/null | grep -q 'Changes queued for next boot'
}

sha256_file() {
  local file="$1"
  if [[ -e "$file" ]]; then
    sha256sum "$file" | awk '{print $1}'
  else
    printf 'missing'
  fi
}

show_file_identity() {
  local label="$1"
  local file="$2"
  log "$label"
  if [[ -e "$file" ]]; then
    ls -la "$file" | tee -a "$LOG_FILE"
    printf 'sha256: %s
' "$(sha256_file "$file")" | tee -a "$LOG_FILE"
  else
    printf 'missing: %s
' "$file" | tee -a "$LOG_FILE"
  fi
}

show_file_metadata() {
  local label="$1"
  local file="$2"
  log "$label"
  if [[ -e "$file" ]]; then
    ls -la "$file" | tee -a "$LOG_FILE"
  else
    printf 'missing: %s
' "$file" | tee -a "$LOG_FILE"
  fi
}

assert_script_owned_path() {
  local path="$1"
  case "$path" in
    "$STATE_DIR"/*|/tmp/atomic-nvidia-kmod-inspect.*)
      return 0
      ;;
    *)
      fail "Refusing to remove unexpected path outside script-owned state: $path"
      ;;
  esac
}

remove_script_owned_path() {
  local path="$1"
  assert_script_owned_path "$path"
  if [[ -e "$path" ]]; then
    log "Removing script-owned temporary path: $path"
    rm -rf "$path"
  fi
}

compare_files_by_hash() {
  local left_label="$1"
  local left_file="$2"
  local right_label="$3"
  local right_file="$4"
  local left_hash right_hash redacted

  left_hash="$(sha256_file "$left_file")"
  right_hash="$(sha256_file "$right_file")"
  redacted=0
  if [[ "$left_label $left_file $right_label $right_file" == *private* || "$left_label $left_file $right_label $right_file" == *.priv* ]]; then
    redacted=1
  fi

  log "Comparing $left_label to $right_label"
  if [[ "$redacted" -eq 1 ]]; then
    printf '%s: %s
' "$left_label" "$( [[ "$left_hash" == "missing" ]] && printf missing || printf present-redacted )" | tee -a "$LOG_FILE"
    printf '%s: %s
' "$right_label" "$( [[ "$right_hash" == "missing" ]] && printf missing || printf present-redacted )" | tee -a "$LOG_FILE"
  else
    printf '%s: %s
' "$left_label" "$left_hash" | tee -a "$LOG_FILE"
    printf '%s: %s
' "$right_label" "$right_hash" | tee -a "$LOG_FILE"
  fi

  if [[ "$left_hash" == "$right_hash" && "$left_hash" != "missing" ]]; then
    log "Comparison result: MATCH"
  else
    warn "Comparison result: DIFFERENT OR MISSING"
  fi
}

current_kernel_kmod_rpms() {
  local kernel
  kernel="$(current_kernel)"
  find /var/cache/akmods/nvidia -type f -name "kmod-nvidia-${kernel}-*.rpm" -printf '%T@ %p
' 2>/dev/null | sort -n | awk '{$1=""; sub(/^ /,""); print}'
}

latest_current_kernel_kmod_rpm() {
  current_kernel_kmod_rpms | tail -n 1
}

quarantine_kmod_rpm() {
  local rpm_path="$1" dest_dir dest_path base ts
  [[ -e "$rpm_path" ]] || fail "Cannot quarantine missing kmod RPM: $rpm_path"

  dest_dir="$QUARANTINE_DIR"
  assert_script_owned_path "$dest_dir"
  install -d -m 0700 "$dest_dir"

  base="$(basename "$rpm_path")"
  ts="$(date +%Y%m%d%H%M%S)"
  dest_path="$dest_dir/${base}.unsigned-or-invalid.${ts}"

  log "Quarantining invalid cached kmod RPM."
  log "Source: $rpm_path"
  log "Destination: $dest_path"
  mv -f "$rpm_path" "$dest_path"
}

reboot_notice_and_exit() {
  log "A reboot is required before continuing."
  log "Reboot now, then run: sudo $SCRIPT_NAME"
  log "The script is resumable; it will continue from the next unfinished check."
  exit 0
}

module_reboot_notice_and_exit() {
  log "A reboot is required so the signed NVIDIA module can become active."
  if [[ "$LAYER_KMOD_RPM" == "yes" ]]; then
    log "Reboot now, then run: sudo $SCRIPT_NAME --layer-kmod-rpm"
  else
    log "Reboot now, then run: sudo $SCRIPT_NAME"
  fi
  log "The script is resumable; it will verify the active NVIDIA module after reboot."
  exit 0
}

mok_reboot_notice_and_exit() {
  explain "MOK enrollment required on next reboot

A public signing key has been queued with mokutil. During the next reboot, you should see a blue MOK Manager screen.

Use this menu path:
  1. Enroll MOK
  2. Continue
  3. Yes
  4. Enter the temporary password you just created for mokutil
  5. Reboot

Notes:
  - The temporary MOK password is not your Linux login password.
  - It is only used once to approve this key.
  - If you miss the screen or choose Continue Boot, boot Fedora and rerun this script."

  log "Reboot now, enroll the MOK key in the blue MOK Manager screen, then run: sudo $SCRIPT_NAME"
  exit 0
}

preflight() {
  mkdir -p "$STATE_DIR"
  touch "$LOG_FILE"
  chmod 0700 "$STATE_DIR"
  chmod 0600 "$LOG_FILE" || true

  explain "Fedora Atomic NVIDIA + Secure Boot setup

This script is resumable. It checks what is already done, stages rpm-ostree changes when needed, then stops and asks for a reboot when Fedora needs to boot into the new deployment.

The log file may contain sensitive system and signing-key metadata. Do not post it publicly without reviewing it first.

Mode: $MODE"

  require_cmd rpm
  require_cmd rpm-ostree
  require_cmd mokutil
  require_cmd modinfo
  require_cmd find
  require_cmd awk
  require_cmd sed
  require_cmd grep
  require_cmd install
  require_cmd cp
  require_cmd chmod
  require_cmd mv
  require_cmd mkdir
  require_cmd basename
  require_cmd date
  require_cmd openssl
  require_cmd mktemp

  if ! is_atomic_system; then
    fail "This script is intended for Fedora Atomic/rpm-ostree systems booted through OSTree. /run/ostree-booted or rpm-ostree is missing."
  fi

  if ! rpm-ostree status >/dev/null 2>&1; then
    fail "rpm-ostree is present but not working. Fix rpm-ostree before continuing."
  fi

  log "Current kernel: $(current_kernel)"
  log "Secure Boot state: $(secure_boot_state | tr '
' ' ')"
  log "Booted deployment snapshot:"
  rpm-ostree status | sed -n '1,35p' | tee -a "$LOG_FILE"
}

check_supported_boot_mode() {
  explain "Check: boot mode and Secure Boot visibility

This script can prepare signed NVIDIA modules whether Secure Boot is currently enabled or disabled, but MOK enrollment requires UEFI Secure Boot/shim support."

  if [[ ! -d /sys/firmware/efi ]]; then
    fail "This system does not appear to be booted in UEFI mode. MOK/Secure Boot enrollment will not work from this boot."
  fi

  local sb
  sb="$(secure_boot_state | tr '
' ' ')"
  log "mokutil Secure Boot state: $sb"

  if grep -qi 'EFI variables are not supported' <<<"$sb"; then
    fail "mokutil cannot access EFI variables. Boot in UEFI mode with efivarfs available before continuing."
  fi
}

fedora_version_id() {
  local version_id
  version_id="$(. /etc/os-release && printf '%s' "$VERSION_ID")"
  [[ -n "$version_id" ]] || fail "Could not determine Fedora VERSION_ID from /etc/os-release."
  printf '%s' "$version_id"
}

check_fedora_family() {
  if ! grep -Eqi '^(ID=fedora|ID_LIKE=.*fedora)' /etc/os-release; then
    warn "This does not look like a Fedora-family OS from /etc/os-release. Continuing only because rpm-ostree is present."
  fi
}

rpm_pkg_version() {
  local pkg="$1"
  if rpm -q "$pkg" >/dev/null 2>&1; then
    rpm -q --qf '%{VERSION}' "$pkg" 2>/dev/null || true
  fi
}

ensure_rpmfusion_repos() {
  explain "Check: RPM Fusion repositories

NVIDIA's proprietary Fedora packages come from RPM Fusion. This checks whether RPM Fusion release packages are installed. If missing, it stages them with rpm-ostree and requires a reboot."

  local version_id free_version nonfree_version
  version_id="$(fedora_version_id)"
  free_version="$(rpm_pkg_version rpmfusion-free-release)"
  nonfree_version="$(rpm_pkg_version rpmfusion-nonfree-release)"

  log "Fedora VERSION_ID: $version_id"
  log "Installed rpmfusion-free-release version: ${free_version:-not installed}"
  log "Installed rpmfusion-nonfree-release version: ${nonfree_version:-not installed}"

  if [[ "$free_version" == "$version_id" && "$nonfree_version" == "$version_id" ]]; then
    log "RPM Fusion release packages are installed for Fedora $version_id."
    return
  fi

  if [[ -n "$free_version" || -n "$nonfree_version" ]]; then
    warn "RPM Fusion release packages are installed, but not for Fedora $version_id."
    rpm -qa | grep -E '^rpmfusion-(free|nonfree)-release' | sort | tee -a "$LOG_FILE" || true
    fail "Reinstall RPM Fusion release packages for Fedora $version_id before continuing."
  fi

  log "Staging RPM Fusion release packages for Fedora $version_id."
  run rpm-ostree install \
    "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${version_id}.noarch.rpm" \
    "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${version_id}.noarch.rpm"
  reboot_notice_and_exit
}

ensure_kernel_args() {
  explain "Check: kernel arguments

The open-source nouveau driver must stay out of the way, and NVIDIA DRM modesetting should be enabled for modern Wayland desktops."

  local changed=0 existing
  existing="$(rpm-ostree kargs 2>/dev/null || true)"

  log "Current kernel arguments:"
  printf '%s
' "$existing" | tee -a "$LOG_FILE"

  for arg in "${KARGS[@]}"; do
    if grep -qw -- "$arg" <<<"$existing"; then
      log "Kernel arg already present: $arg"
    else
      log "Adding kernel arg: $arg"
      run rpm-ostree kargs --append-if-missing="$arg"
      changed=1
    fi
  done

  [[ "$changed" -eq 1 ]] && reboot_notice_and_exit
}

ensure_nvidia_packages() {
  explain "Check: NVIDIA packages

This checks that akmod-nvidia is installed to build the kernel module and xorg-x11-drv-nvidia-cuda is installed for nvidia-smi."

  local missing=()
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if is_rpm_installed "$pkg"; then
      log "Package installed: $pkg"
    else
      missing+=("$pkg")
    fi
  done

  if [[ "${#missing[@]}" -gt 0 ]]; then
    log "Staging missing NVIDIA packages: ${missing[*]}"
    run rpm-ostree install "${missing[@]}"
    reboot_notice_and_exit
  fi

  require_cmd akmods
}

ensure_build_tools() {
  explain "Check: local build/inspection tools

This script needs rpmbuild to create the local akmods-keys RPM, and rpm2cpio/cpio to inspect RPM contents before trusting them."

  local missing_packages=()
  command -v rpmbuild >/dev/null 2>&1 || missing_packages+=("rpm-build")
  command -v cpio >/dev/null 2>&1 || missing_packages+=("cpio")

  if ! command -v rpm2cpio >/dev/null 2>&1; then
    fail "rpm2cpio is missing even though rpm should normally provide it. Repair the rpm package before continuing."
  fi

  if [[ "${#missing_packages[@]}" -gt 0 ]]; then
    log "Staging missing build/inspection packages: ${missing_packages[*]}"
    run rpm-ostree install "${missing_packages[@]}"
    reboot_notice_and_exit
  fi

  require_cmd rpmbuild
  require_cmd rpm2cpio
  require_cmd cpio
}

find_akmods_keypair() {
  local create_aliases="${1:-no}"
  local cert priv base candidate count selected_cert selected_priv

  if [[ -e "$AKMODS_CERT_DIR/public_key.der" && -e "$AKMODS_PRIV_DIR/private_key.priv" ]]; then
    echo "$AKMODS_CERT_DIR/public_key.der|$AKMODS_PRIV_DIR/private_key.priv"
    return 0
  fi

  count=0
  selected_cert=""
  selected_priv=""
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    base="$(basename "$candidate" .der)"
    priv="$AKMODS_PRIV_DIR/${base}.priv"
    if [[ -e "$priv" ]]; then
      count=$((count + 1))
      selected_cert="$candidate"
      selected_priv="$priv"
    fi
  done < <(find "$AKMODS_CERT_DIR" -maxdepth 1 -type f -name '*.der' ! -name 'public_key.der' 2>/dev/null | sort)

  if [[ "$count" -eq 0 ]]; then
    return 1
  fi

  if [[ "$count" -gt 1 ]]; then
    warn "Multiple akmods keypairs were found, and canonical public_key.der/private_key.priv are missing."
    find "$AKMODS_CERT_DIR" -maxdepth 1 -type f -name '*.der' 2>/dev/null | sort | tee -a "$LOG_FILE" || true
    fail "Create explicit canonical symlinks or files at $AKMODS_CERT_DIR/public_key.der and $AKMODS_PRIV_DIR/private_key.priv, then rerun."
  fi

  if [[ "$create_aliases" == "yes" ]]; then
    ln -sfn "$selected_cert" "$AKMODS_CERT_DIR/public_key.der"
    ln -sfn "$selected_priv" "$AKMODS_PRIV_DIR/private_key.priv"
    echo "$AKMODS_CERT_DIR/public_key.der|$AKMODS_PRIV_DIR/private_key.priv"
  else
    echo "$selected_cert|$selected_priv"
  fi
  return 0

}

cert_common_name() {
  local cert="$1" subject cn
  subject="$(openssl x509 -inform DER -in "$cert" -noout -subject -nameopt RFC2253 2>/dev/null || true)"
  cn="$(sed -n 's/^subject=.*CN=\([^,]*\).*$/\1/p' <<<"$subject")"
  [[ -n "$cn" ]] || fail "Could not read certificate Common Name from $cert."
  printf '%s' "$cn"
}

cert_subject_key_id() {
  local cert="$1" key_id
  key_id="$(openssl x509 -inform DER -in "$cert" -noout -ext subjectKeyIdentifier 2>/dev/null \
    | sed -n 's/^[[:space:]]*//; /^[A-Fa-f0-9][A-Fa-f0-9]:/p' \
    | tr -d ':[:space:]' \
    | tr '[:lower:]' '[:upper:]')"
  printf '%s' "$key_id"
}

expected_key_common_name() {
  local pair cert
  pair="$(find_akmods_keypair)" || fail "No akmods keypair found."
  cert="${pair%%|*}"
  cert_common_name "$cert"
}

expected_key_id() {
  local pair cert
  pair="$(find_akmods_keypair)" || fail "No akmods keypair found."
  cert="${pair%%|*}"
  cert_subject_key_id "$cert"
}

require_files_same_hash() {
  local left_label="$1"
  local left_file="$2"
  local right_label="$3"
  local right_file="$4"
  local left_hash right_hash redacted

  left_hash="$(sha256_file "$left_file")"
  right_hash="$(sha256_file "$right_file")"
  redacted=0
  if [[ "$left_label $left_file $right_label $right_file" == *private* || "$left_label $left_file $right_label $right_file" == *.priv* ]]; then
    redacted=1
  fi

  log "Requiring $left_label to match $right_label"
  if [[ "$redacted" -eq 1 ]]; then
    printf '%s: %s
' "$left_label" "$( [[ "$left_hash" == "missing" ]] && printf missing || printf present-redacted )" | tee -a "$LOG_FILE"
    printf '%s: %s
' "$right_label" "$( [[ "$right_hash" == "missing" ]] && printf missing || printf present-redacted )" | tee -a "$LOG_FILE"
  else
    printf '%s: %s
' "$left_label" "$left_hash" | tee -a "$LOG_FILE"
    printf '%s: %s
' "$right_label" "$right_hash" | tee -a "$LOG_FILE"
  fi

  if [[ "$left_hash" != "$right_hash" || "$left_hash" == "missing" ]]; then
    fail "Key mismatch: $left_label does not match $right_label."
  fi

  log "Required key comparison result: MATCH"
}

ensure_akmods_keypair() {
  local had_canonical=0

  explain "Check: local akmods signing key

Secure Boot rejects unsigned third-party kernel modules. NVIDIA's proprietary module must be signed with a key enrolled in MOK."

  mkdir -p "$AKMODS_CERT_DIR" "$AKMODS_PRIV_DIR"
  [[ -e "$AKMODS_CERT_DIR/public_key.der" && -e "$AKMODS_PRIV_DIR/private_key.priv" ]] && had_canonical=1

  if find_akmods_keypair yes >/dev/null; then
    local pair cert priv
    pair="$(find_akmods_keypair yes)"
    cert="${pair%%|*}"
    priv="${pair##*|}"
    log "akmods signing keypair exists in /etc/pki/akmods."
    if [[ "$had_canonical" -eq 0 ]]; then
      log "Created canonical akmods key aliases because exactly one matching keypair was found."
    fi
    log "Selected akmods public key: $cert"
    log "Selected akmods private key: $priv"
    show_file_identity "Original akmods public key" "$cert"
    show_file_metadata "Original akmods private key" "$priv"
    return
  fi

  require_cmd kmodgenca
  log "No akmods keypair found; generating one with kmodgenca -a."
  run kmodgenca -a

  find_akmods_keypair yes >/dev/null || fail "kmodgenca completed, but no matching keypair was found under /etc/pki/akmods."

  local pair cert priv
  pair="$(find_akmods_keypair yes)"
  cert="${pair%%|*}"
  priv="${pair##*|}"
  log "Selected generated akmods public key: $cert"
  log "Selected generated akmods private key: $priv"
  show_file_identity "Generated akmods public key" "$cert"
  show_file_metadata "Generated akmods private key" "$priv"
}

ensure_mok_enrolled() {
  explain "Check: MOK enrollment

The public half of the akmods signing key must be enrolled. Without this, Secure Boot will reject the signed NVIDIA module."

  local pair cert
  pair="$(find_akmods_keypair)" || fail "No akmods keypair found."
  cert="${pair%%|*}"

  show_file_identity "Public key being tested with mokutil" "$cert"

  if mokutil --test-key "$cert" 2>&1 | tee -a "$LOG_FILE" | grep -qi 'already enrolled'; then
    log "MOK public key is already enrolled."
    return
  fi

  warn "MOK public key is not enrolled yet."
  explain "About to queue MOK enrollment

mokutil --import will ask you to create a temporary password. On next reboot, use:
  Enroll MOK -> Continue -> Yes -> enter temporary password -> Reboot"

  run mokutil --import "$cert"
  mok_reboot_notice_and_exit
}

write_akmods_keys_sources() {
  local pair cert priv
  pair="$(find_akmods_keypair)" || fail "No akmods keypair found."
  cert="${pair%%|*}"
  priv="${pair##*|}"

  remove_script_owned_path "$BUILD_DIR"
  install -d -m 0700 "$BUILD_DIR/rpmbuild/BUILD" "$BUILD_DIR/rpmbuild/RPMS" "$BUILD_DIR/rpmbuild/SOURCES" "$BUILD_DIR/rpmbuild/SPECS" "$BUILD_DIR/rpmbuild/SRPMS"

  cat > "$BUILD_DIR/macros.kmodtool" <<'EOF'
%_kmodtool_signmodules_pubkey /etc/pki/akmods-keys/certs/public_key.der
%_kmodtool_signmodules_privkey /etc/pki/akmods-keys/private/private_key.priv
EOF

  cat > "$BUILD_DIR/akmods-keys.spec" <<'EOF'
Name:           akmods-keys
Version:        0.0.2
Release:        1%{?dist}
Summary:        Local akmods signing keys for rpm-ostree kmod builds
License:        MIT
BuildArch:      noarch
Source0:        public_key.der
Source1:        private_key.priv
Source2:        macros.kmodtool

%description
Local akmods signing key material and kmodtool macros for rpm-ostree based systems.

%prep
%build
%install
install -D -m 0644 %{SOURCE0} %{buildroot}/etc/pki/akmods-keys/certs/public_key.der
install -D -m 0600 %{SOURCE1} %{buildroot}/etc/pki/akmods-keys/private/private_key.priv
install -D -m 0644 %{SOURCE2} %{buildroot}/etc/rpm/macros.kmodtool

%files
%dir /etc/pki/akmods-keys
%dir /etc/pki/akmods-keys/certs
%attr(0700,root,root) %dir /etc/pki/akmods-keys/private
/etc/pki/akmods-keys/certs/public_key.der
%attr(0600,root,root) /etc/pki/akmods-keys/private/private_key.priv
/etc/rpm/macros.kmodtool
EOF

  cp "$cert" "$BUILD_DIR/rpmbuild/SOURCES/public_key.der"
  cp "$priv" "$BUILD_DIR/rpmbuild/SOURCES/private_key.priv"
  cp "$BUILD_DIR/macros.kmodtool" "$BUILD_DIR/rpmbuild/SOURCES/macros.kmodtool"
  cp "$BUILD_DIR/akmods-keys.spec" "$BUILD_DIR/rpmbuild/SPECS/akmods-keys.spec"

  chmod 0600 "$BUILD_DIR/rpmbuild/SOURCES/private_key.priv"
  chmod 0644 "$BUILD_DIR/rpmbuild/SOURCES/public_key.der" "$BUILD_DIR/rpmbuild/SOURCES/macros.kmodtool"

  require_files_same_hash "original public key" "$cert" "RPM source public_key.der" "$BUILD_DIR/rpmbuild/SOURCES/public_key.der"
  require_files_same_hash "original private key" "$priv" "RPM source private_key.priv" "$BUILD_DIR/rpmbuild/SOURCES/private_key.priv"
}

ensure_akmods_keys_package_installed() {
  explain "Check: akmods-keys package

Fedora Atomic/rpm-ostree needs a local akmods-keys RPM so the signing key is visible to kmod signing. This RPM contains the private key; keep it local."

  if is_rpm_installed akmods-keys && [[ -e "$PACKAGED_CERT" && -e "$PACKAGED_PRIV" && -e "$MACRO_FILE" ]]; then
    log "akmods-keys is installed; validating installed key files and RPM macro content."

    if grep -qxF "%_kmodtool_signmodules_pubkey $PACKAGED_CERT" "$MACRO_FILE" \
      && grep -qxF "%_kmodtool_signmodules_privkey $PACKAGED_PRIV" "$MACRO_FILE"; then
      chmod 0644 "$PACKAGED_CERT" || true
      chmod 0600 "$PACKAGED_PRIV" || true

      local pair cert priv
      pair="$(find_akmods_keypair)" || fail "No akmods keypair found."
      cert="${pair%%|*}"
      priv="${pair##*|}"

      require_files_same_hash "original public key" "$cert" "active packaged public key" "$PACKAGED_CERT"
      require_files_same_hash "original private key" "$priv" "active packaged private key" "$PACKAGED_PRIV"

      log "Installed akmods-keys package is valid for the current local signing key."
      return
    fi

    warn "Installed akmods-keys package exists, but its macro content does not match this script's expected signing paths. Rebuilding local akmods-keys RPM."
  fi

  log "Building local akmods-keys RPM."
  write_akmods_keys_sources

  run rpmbuild --define "_topdir $BUILD_DIR/rpmbuild" -ba "$BUILD_DIR/rpmbuild/SPECS/akmods-keys.spec"

  local rpm_path inspect_dir pair cert priv
  rpm_path="$(find "$BUILD_DIR/rpmbuild/RPMS" -type f -name 'akmods-keys-*.rpm' | head -n 1 || true)"
  [[ -n "$rpm_path" ]] || fail "akmods-keys RPM was not created."

  run rpm -qplv "$rpm_path"

  inspect_dir="$BUILD_DIR/inspect-akmods-keys-rpm"
  remove_script_owned_path "$inspect_dir"
  mkdir -p "$inspect_dir"
  (cd "$inspect_dir" && rpm2cpio "$rpm_path" | cpio -idm --quiet)

  pair="$(find_akmods_keypair)"
  cert="${pair%%|*}"
  priv="${pair##*|}"
  require_files_same_hash "original public key" "$cert" "packaged public key inside RPM" "$inspect_dir/etc/pki/akmods-keys/certs/public_key.der"
  require_files_same_hash "original private key" "$priv" "packaged private key inside RPM" "$inspect_dir/etc/pki/akmods-keys/private/private_key.priv"

  log "Packaged RPM macro content from RPM:"
  cat "$inspect_dir/$MACRO_FILE" | tee -a "$LOG_FILE"

  run rpm-ostree install "$rpm_path"
  reboot_notice_and_exit
}

ensure_packaged_key_permissions() {
  explain "Check: packaged key permissions

The kmod signing helper must be able to read both the public certificate and private key during the akmods build. The packaged private key is kept root-readable for the local build/signing process."

  [[ -e "$PACKAGED_CERT" ]] || fail "Missing $PACKAGED_CERT"
  [[ -e "$PACKAGED_PRIV" ]] || fail "Missing $PACKAGED_PRIV"
  [[ -e "$MACRO_FILE" ]] || fail "Missing $MACRO_FILE"

  chmod 0644 "$PACKAGED_CERT"
  chmod 0600 "$PACKAGED_PRIV"
  ls -la "$PACKAGED_CERT" "$PACKAGED_PRIV" "$MACRO_FILE" | tee -a "$LOG_FILE"

  local pair cert priv
  pair="$(find_akmods_keypair)"
  cert="${pair%%|*}"
  priv="${pair##*|}"
  require_files_same_hash "original public key" "$cert" "active packaged public key" "$PACKAGED_CERT"
  require_files_same_hash "original private key" "$priv" "active packaged private key" "$PACKAGED_PRIV"

  log "Active RPM macro content:"
  cat "$MACRO_FILE" | tee -a "$LOG_FILE"
}

verify_kmod_rpm_signature() {
  local rpm_path="$1" inspect_dir cleanup_inspect expected_signer expected_sig_key signer_count unsigned_count mismatch_count module_count module_file signer sig_key normalized_sig_key

  [[ -e "$rpm_path" ]] || { warn "Cannot verify missing kmod RPM: $rpm_path"; return 1; }

  explain "Verify: kmod RPM module signatures

This extracts the kmod-nvidia RPM and runs modinfo against each NVIDIA module inside before trusting it."

  expected_signer="$(expected_key_common_name)"
  expected_sig_key="$(expected_key_id)"
  log "Expected NVIDIA module signer from local MOK certificate: $expected_signer"
  if [[ -n "$expected_sig_key" ]]; then
    log "Expected NVIDIA module sig_key from local MOK certificate: $expected_sig_key"
  elif [[ "$MODE" != "status" ]]; then
    warn "Could not read Subject Key Identifier from local MOK certificate."
    return 1
  else
    warn "Could not read Subject Key Identifier from local MOK certificate; falling back to signer CN comparison."
  fi

  cleanup_inspect=0
  if [[ "$MODE" == "status" ]]; then
    inspect_dir="$(mktemp -d /tmp/atomic-nvidia-kmod-inspect.XXXXXX)" || { warn "Failed to create temporary inspection directory."; return 1; }
    cleanup_inspect=1
  else
    inspect_dir="$BUILD_DIR/inspect-kmod-rpm"
    remove_script_owned_path "$inspect_dir"
    mkdir -p "$inspect_dir"
  fi

  if ! (cd "$inspect_dir" && rpm2cpio "$rpm_path" | cpio -idm --quiet); then
    warn "Failed to extract kmod RPM for inspection: $rpm_path"
    [[ "$cleanup_inspect" -eq 1 ]] && remove_script_owned_path "$inspect_dir"
    return 1
  fi

  module_count=0
  signer_count=0
  unsigned_count=0
  mismatch_count=0

  while IFS= read -r -d '' module_file; do
    module_count=$((module_count + 1))
    signer="$(modinfo -F signer "$module_file" 2>/dev/null || true)"
    sig_key="$(modinfo -F sig_key "$module_file" 2>/dev/null || true)"
    normalized_sig_key="$(tr -d ':[:space:]' <<<"$sig_key" | tr '[:lower:]' '[:upper:]')"
    show_file_identity "Module inside kmod RPM: ${module_file#$inspect_dir/}" "$module_file"
    printf 'signer: %s
' "${signer:-blank/unsigned}" | tee -a "$LOG_FILE"
    printf 'sig_key: %s
' "${sig_key:-blank}" | tee -a "$LOG_FILE"
    if [[ -z "$signer" ]]; then
      unsigned_count=$((unsigned_count + 1))
    elif [[ -n "$expected_sig_key" && "$normalized_sig_key" == "$expected_sig_key" ]]; then
      signer_count=$((signer_count + 1))
    elif [[ -z "$expected_sig_key" && "$signer" == "$expected_signer" ]]; then
      signer_count=$((signer_count + 1))
    else
      mismatch_count=$((mismatch_count + 1))
      warn "Module signer '$signer' or sig_key '$sig_key' does not match the expected local key."
    fi
  done < <(find "$inspect_dir/lib/modules" -type f -name 'nvidia*.ko*' -print0 2>/dev/null)

  log "kmod RPM module count: $module_count"
  log "modules signed by expected key: $signer_count"
  log "unsigned modules found: $unsigned_count"
  log "modules signed by a different key: $mismatch_count"

  if [[ "$module_count" -eq 0 ]]; then
    warn "No NVIDIA modules found inside kmod RPM."
    [[ "$cleanup_inspect" -eq 1 ]] && remove_script_owned_path "$inspect_dir"
    return 1
  fi
  if [[ "$unsigned_count" -ne 0 ]]; then
    warn "The kmod RPM contains unsigned NVIDIA modules."
    [[ "$cleanup_inspect" -eq 1 ]] && remove_script_owned_path "$inspect_dir"
    return 1
  fi
  if [[ "$mismatch_count" -ne 0 ]]; then
    warn "The kmod RPM contains modules signed by a different key."
    [[ "$cleanup_inspect" -eq 1 ]] && remove_script_owned_path "$inspect_dir"
    return 1
  fi

  [[ "$cleanup_inspect" -eq 1 ]] && remove_script_owned_path "$inspect_dir"
  log "All NVIDIA modules inside the kmod RPM are signed by the expected key."
  return 0
}

build_signed_kmod_rpm() {
  local kernel rpm_path failed_log latest_log
  kernel="$(current_kernel)"

  explain "Cache/build: signed NVIDIA kmod RPM

Cached kmod RPMs are verified before use. Unsigned or broken cached RPMs are moved aside and rebuilt."

  while true; do
    rpm_path="$(latest_current_kernel_kmod_rpm || true)"
    [[ -n "$rpm_path" ]] || break

    log "Existing kmod RPM found: $rpm_path"
    show_file_identity "Existing cached kmod-nvidia RPM" "$rpm_path"

    if verify_kmod_rpm_signature "$rpm_path"; then
      log "Existing cached kmod RPM is signed and usable."
      return
    fi

    warn "Existing cached kmod RPM is not usable for Secure Boot."
    quarantine_kmod_rpm "$rpm_path"
  done

  log "Building signed NVIDIA kmod RPM with akmods."
  if akmods --force 2>&1 | tee -a "$LOG_FILE"; then
    log "akmods completed successfully."
  else
    warn "akmods exited non-zero. On Atomic this can still mean direct install failed but the RPM was built. Checking cache."
  fi

  rpm_path="$(latest_current_kernel_kmod_rpm || true)"
  if [[ -z "$rpm_path" ]]; then
    failed_log="$(find /var/cache/akmods/nvidia -type f -name "*-for-${kernel}.failed.log" 2>/dev/null | head -n 1 || true)"
    [[ -n "$failed_log" ]] && tail -n 120 "$failed_log" | tee -a "$LOG_FILE"
    fail "No kmod-nvidia RPM found for kernel $kernel."
  fi

  log "Built kmod RPM: $rpm_path"
  show_file_identity "Generated kmod-nvidia RPM" "$rpm_path"
  run rpm -qpl "$rpm_path"
  verify_kmod_rpm_signature "$rpm_path" || fail "Generated kmod RPM is not signed correctly."

  latest_log="$(find /var/cache/akmods/nvidia -type f \( -name "*-for-${kernel}*.log" -o -name "*-for-${kernel}*.failed.log" \) 2>/dev/null | sort | tail -n 1 || true)"
  if [[ -n "$latest_log" ]]; then
    log "Signing evidence from latest akmods log: $latest_log"
    grep -nE 'brp-kmodsign|sign-file|modules are unsigned|Permission denied|Wrote:' "$latest_log" | tail -n 80 | tee -a "$LOG_FILE" || true
  fi
}

layer_signed_kmod_rpm_if_needed() {
  explain "Recovery install: layer signed kmod RPM

This is a recovery path. It manually layers the generated kmod-nvidia RPM into rpm-ostree. It is not normally needed when akmod-nvidia, akmods-keys, and MOK enrollment are working. Manually layered kmod-nvidia-\$kernel RPMs are tied to one exact kernel and may block future rpm-ostree upgrades."

  local kernel rpm_path kmod_pkg rpm_count verify_output active_signer active_sig_key normalized_active_sig_key expected_signer expected_sig_key
  kernel="$(current_kernel)"
  kmod_pkg="kmod-nvidia-${kernel}"

  rpm_count="$(current_kernel_kmod_rpms | wc -l | awk '{print $1}')"
  if [[ "$rpm_count" -gt 1 ]]; then
    warn "Multiple cached kmod RPMs exist for the current kernel. Using the newest one by modification time."
    current_kernel_kmod_rpms | tee -a "$LOG_FILE"
  fi

  rpm_path="$(latest_current_kernel_kmod_rpm || true)"
  [[ -n "$rpm_path" ]] || fail "No kmod-nvidia RPM found for kernel $kernel."

  if rpm -q "$kmod_pkg" >/dev/null 2>&1; then
    log "kmod package is installed: $(rpm -q "$kmod_pkg")"
    verify_output="$(rpm -V "$kmod_pkg" 2>&1 || true)"

    if [[ -n "$verify_output" ]]; then
      printf '%s
' "$verify_output" | tee -a "$LOG_FILE"
      warn "Installed NVIDIA module files differ from the RPM payload. Removing the layered kmod in the next deployment, then rerun after reboot."
      run rpm-ostree uninstall "$kmod_pkg"
      reboot_notice_and_exit
    fi

    active_signer="$(modinfo -F signer nvidia 2>/dev/null || true)"
    active_sig_key="$(modinfo -F sig_key nvidia 2>/dev/null || true)"
    normalized_active_sig_key="$(tr -d ':[:space:]' <<<"$active_sig_key" | tr '[:lower:]' '[:upper:]')"
    expected_signer="$(expected_key_common_name)"
    expected_sig_key="$(expected_key_id)"
    if [[ -z "$expected_sig_key" ]]; then
      fail "Could not read Subject Key Identifier from local MOK certificate; refusing to trust active module signer by name only."
    fi
    if [[ -z "$active_signer" ]]; then
      warn "Installed kmod verifies cleanly, but the active NVIDIA module has no signer. Removing it and relayering after reboot."
      run rpm-ostree uninstall "$kmod_pkg"
      reboot_notice_and_exit
    fi
    if [[ -n "$expected_sig_key" && "$normalized_active_sig_key" != "$expected_sig_key" ]]; then
      warn "Installed kmod verifies cleanly, but the active NVIDIA module sig_key '$active_sig_key' does not match the expected local key. Removing it and relayering after reboot."
      run rpm-ostree uninstall "$kmod_pkg"
      reboot_notice_and_exit
    fi
    log "Installed kmod verification is clean and active signer is: $active_signer"
  else
    verify_kmod_rpm_signature "$rpm_path" || fail "Refusing to layer unsigned/broken kmod RPM."
    log "Staging signed kmod RPM into rpm-ostree deployment."
    run rpm-ostree install "$rpm_path"
    reboot_notice_and_exit
  fi
}

verify_module_signature_and_driver() {
  explain "Verify: module signature and driver load

This checks the exact NVIDIA module that modprobe will use, confirms it has a signer, then runs nvidia-smi."

  local signer sig_key normalized_sig_key module_path expected_signer expected_sig_key
  module_path="$(modinfo -n nvidia 2>/dev/null || true)"
  signer="$(modinfo -F signer nvidia 2>/dev/null || true)"
  sig_key="$(modinfo -F sig_key nvidia 2>/dev/null || true)"
  normalized_sig_key="$(tr -d ':[:space:]' <<<"$sig_key" | tr '[:lower:]' '[:upper:]')"
  expected_signer="$(expected_key_common_name)"
  expected_sig_key="$(expected_key_id)"
  if [[ -z "$expected_sig_key" ]]; then
    fail "Could not read Subject Key Identifier from local MOK certificate; refusing to trust active module signer by name only."
  fi

  log "NVIDIA module path selected by modinfo/modprobe: ${module_path:-not found}"
  log "NVIDIA module signer from modinfo: ${signer:-blank/unsigned}"
  log "NVIDIA module sig_key from modinfo: ${sig_key:-blank}"
  log "Expected NVIDIA module signer from local MOK certificate: $expected_signer"
  [[ -n "$expected_sig_key" ]] && log "Expected NVIDIA module sig_key from local MOK certificate: $expected_sig_key"

  if [[ -z "$module_path" ]]; then
    warn "A signed NVIDIA module RPM is available, but the NVIDIA module is not active in the running deployment yet."
    warn "This can be normal immediately after a successful akmods build."
    warn "If you have already rebooted once after seeing this message and it still appears, inspect the akmods log output or retry with:"
    warn "  sudo $SCRIPT_NAME --layer-kmod-rpm"
    journalctl -u akmods --no-pager -n 120 2>/dev/null | tee -a "$LOG_FILE" || true
    module_reboot_notice_and_exit
  fi

  if [[ -n "$module_path" && -e "$module_path" ]]; then
    show_file_identity "Active NVIDIA module file" "$module_path"
    rpm -qf "$module_path" 2>&1 | tee -a "$LOG_FILE" || true
  fi

  log "All NVIDIA module files under current kernel tree:"
  find "/lib/modules/$(current_kernel)" -name 'nvidia*.ko*' -ls 2>/dev/null | tee -a "$LOG_FILE" || true

  if [[ -z "$signer" ]]; then
    warn "NVIDIA module appears unsigned. Checking overwrite clues."
    rpm -qa | grep -E '^kmod-nvidia' | tee -a "$LOG_FILE" || true
    rpm -V "kmod-nvidia-$(current_kernel)" 2>&1 | tee -a "$LOG_FILE" || true
    journalctl -u akmods --no-pager -n 120 2>/dev/null | tee -a "$LOG_FILE" || true
    fail "NVIDIA module signer is blank. Do not enable Secure Boot until this is fixed."
  fi

  if [[ -n "$expected_sig_key" && "$normalized_sig_key" != "$expected_sig_key" ]]; then
    fail "NVIDIA module sig_key '$sig_key' does not match the expected local key."
  fi

  if nvidia-smi 2>&1 | tee -a "$LOG_FILE"; then
    log "nvidia-smi works."
  else
    modprobe nvidia 2>&1 | tee -a "$LOG_FILE" || true
    dmesg | tail -n 80 | tee -a "$LOG_FILE" || true
    fail "NVIDIA driver did not load."
  fi
}

print_status() {
  explain "Status summary

This prints rpm-ostree deployment state, Secure Boot state, NVIDIA module path/signer, and relevant packages."

  rpm-ostree status | tee -a "$LOG_FILE"
  mokutil --sb-state | tee -a "$LOG_FILE" || true
  modinfo -n nvidia 2>/dev/null | tee -a "$LOG_FILE" || true
  modinfo -F signer nvidia 2>/dev/null | tee -a "$LOG_FILE" || true
  rpm -qa | grep -E '^akmods-keys|^akmod-nvidia|^kmod-nvidia|^xorg-x11-drv-nvidia-cuda' | sort | tee -a "$LOG_FILE" || true
}

status_only() {
  explain "Diagnostic-only status mode

This mode does not stage rpm-ostree changes. It prints the current Secure Boot, rpm-ostree, key, package, cached RPM, and NVIDIA module state."

  preflight "$@"

  log "Pending rpm-ostree changes?"
  if pending_rpm_ostree_changes; then
    printf 'yes
' | tee -a "$LOG_FILE"
  else
    printf 'no
' | tee -a "$LOG_FILE"
  fi

  log "RPM Fusion release packages:"
  rpm -qa | grep -E '^rpmfusion-(free|nonfree)-release' | sort | tee -a "$LOG_FILE" || true

  log "Kernel arguments:"
  rpm-ostree kargs 2>/dev/null | tee -a "$LOG_FILE" || true
  for arg in "${KARGS[@]}"; do
    if rpm-ostree kargs 2>/dev/null | grep -qw -- "$arg"; then
      log "karg present: $arg"
    else
      warn "karg missing: $arg"
    fi
  done

  log "Relevant installed packages:"
  rpm -qa | grep -E '^akmods-keys|^akmod-nvidia|^kmod-nvidia|^xorg-x11-drv-nvidia-cuda|^rpm-build|^cpio' | sort | tee -a "$LOG_FILE" || true

  if find_akmods_keypair >/dev/null 2>&1; then
    local pair cert priv
    pair="$(find_akmods_keypair)"
    cert="${pair%%|*}"
    priv="${pair##*|}"
    show_file_identity "Original public key" "$cert"
    show_file_metadata "Original private key" "$priv"
    mokutil --test-key "$cert" 2>&1 | tee -a "$LOG_FILE" || true
  else
    warn "No original akmods keypair found under /etc/pki/akmods."
  fi

  show_file_identity "Packaged public key" "$PACKAGED_CERT"
  show_file_metadata "Packaged private key" "$PACKAGED_PRIV"
  show_file_identity "Packaged macro file" "$MACRO_FILE"
  [[ -e "$MACRO_FILE" ]] && cat "$MACRO_FILE" | tee -a "$LOG_FILE"

  if find_akmods_keypair >/dev/null 2>&1 && [[ -e "$PACKAGED_CERT" && -e "$PACKAGED_PRIV" ]]; then
    local pair cert priv
    pair="$(find_akmods_keypair)"
    cert="${pair%%|*}"
    priv="${pair##*|}"
    compare_files_by_hash "original public key" "$cert" "packaged public key" "$PACKAGED_CERT"
    compare_files_by_hash "original private key" "$priv" "packaged private key" "$PACKAGED_PRIV"
  fi

  log "Cached kmod RPMs for current kernel:"
  current_kernel_kmod_rpms | tee -a "$LOG_FILE" || true

  local latest_rpm module_path signer
  latest_rpm="$(latest_current_kernel_kmod_rpm || true)"
  if [[ -n "$latest_rpm" ]]; then
    if ! command -v rpm2cpio >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; then
      warn "Skipping cached kmod RPM inspection because rpm2cpio/cpio is missing."
    elif find_akmods_keypair >/dev/null 2>&1; then
      verify_kmod_rpm_signature "$latest_rpm" || true
    else
      warn "Skipping cached kmod RPM signature verification because no local akmods keypair was found."
    fi
  fi

  module_path="$(modinfo -n nvidia 2>/dev/null || true)"
  signer="$(modinfo -F signer nvidia 2>/dev/null || true)"
  printf 'module path: %s
' "${module_path:-not found}" | tee -a "$LOG_FILE"
  printf 'signer: %s
' "${signer:-blank/unsigned}" | tee -a "$LOG_FILE"
  [[ -n "$module_path" && -e "$module_path" ]] && show_file_identity "Active NVIDIA module" "$module_path"

  rpm -V "kmod-nvidia-$(current_kernel)" 2>&1 | tee -a "$LOG_FILE" || true
  nvidia-smi 2>&1 | tee -a "$LOG_FILE" || true
  log "Status-only mode complete. No rpm-ostree changes were staged."
}

main() {
  require_root "$@"

  if [[ "$MODE" == "status" ]]; then
    status_only "$@"
    exit 0
  fi

  preflight "$@"

  if pending_rpm_ostree_changes; then
    warn "rpm-ostree already has changes queued for next boot."
    reboot_notice_and_exit
  fi

  check_supported_boot_mode
  check_fedora_family
  fedora_version_id >/dev/null
  ensure_rpmfusion_repos
  ensure_kernel_args
  ensure_nvidia_packages
  ensure_build_tools
  ensure_akmods_keypair
  ensure_mok_enrolled
  ensure_akmods_keys_package_installed
  ensure_packaged_key_permissions
  build_signed_kmod_rpm

  if [[ "$LAYER_KMOD_RPM" == "yes" ]]; then
    layer_signed_kmod_rpm_if_needed
  else
    log "Skipping manual kmod RPM layering. akmod-nvidia plus akmods-keys should allow akmods to provide signed NVIDIA modules automatically."
  fi

  verify_module_signature_and_driver
  print_status

  if is_secure_boot_enabled; then
    log "Secure Boot is enabled and NVIDIA appears to be working."
  else
    warn "Secure Boot is disabled. Enable Secure Boot in firmware, boot Fedora, then rerun this script to verify."
  fi

  explain "Final recommendation

Keep akmods-keys installed while akmod-nvidia is installed.

Reason: akmods can automatically rebuild NVIDIA modules after a kernel or driver change. If akmods-keys is missing at that moment, it may rebuild unsigned modules. Secure Boot will then reject them and nvidia-smi will fail.

Do not manually layer kmod-nvidia-\$kernel RPMs unless using --layer-kmod-rpm as a recovery path. Manually layered kmod RPMs are tied to one exact kernel and may block future rpm-ostree upgrades.

Keep the original keypair under /etc/pki/akmods as well. If you lose the private key, future signed rebuilds require generating and enrolling a new key."
}

main "$@"
