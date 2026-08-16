# fedora-atomic-nvidia-secureboot-akmods

Resumable Fedora Atomic / rpm-ostree helper for NVIDIA proprietary drivers with Secure Boot enabled.

Created and maintained by Amarjit Bharath.

This project automates the awkward-but-currently-necessary flow for getting RPM Fusion `akmod-nvidia` working on Fedora Atomic variants with Secure Boot, MOK enrollment, signed NVIDIA kernel modules, and rpm-ostree deployment reboots.

It is intended for Fedora Atomic systems such as:

- Fedora Silverblue
- Fedora Kinoite
- Fedora Sway Atomic / Sericea
- Fedora Budgie Atomic
- Fedora COSMIC Atomic
- other Fedora rpm-ostree desktop variants

It is **not** intended for traditional Fedora Workstation unless you know exactly why you want this Atomic-specific workflow.

## Why this exists

NVIDIA’s proprietary kernel module is a third-party kernel module. With Secure Boot enabled, Linux will reject unsigned third-party kernel modules.

On normal Fedora Workstation, the common flow is:

1. Generate an akmods signing key.
2. Enroll the public key with MOK.
3. Let akmods sign NVIDIA modules using keys from `/etc/pki/akmods`.

On Fedora Atomic / rpm-ostree systems, the situation is more awkward. The akmods build/signing process may run in a deployment/build context where the normal host keys under `/etc/pki/akmods` are not visible in the way kmod signing expects.

The practical workaround is to create and layer a local RPM called `akmods-keys`, which places the signing key where the kmod signing macros can find it during akmods builds.

I made this after fighting through the Fedora Atomic + NVIDIA + Secure Boot setup and wanting a repeatable recovery path.

This script automates that process and verifies the result before trusting it.

## What the script does

The script is designed to be run repeatedly. It checks current state, performs the next required step, and stops whenever a reboot is needed.

It handles:

- Fedora Atomic / rpm-ostree detection
- UEFI / Secure Boot visibility checks
- RPM Fusion release package setup
- NVIDIA package setup for `akmod-nvidia` and `nvidia-smi`
- nouveau blacklisting and NVIDIA DRM modeset kernel args
- local akmods key generation or reuse
- MOK enrollment checks and reboot instructions
- local `akmods-keys` RPM creation
- key consistency checks across original, packaged, and active key files
- signed NVIDIA kmod RPM creation using akmods
- extraction and signature verification for generated `kmod-nvidia` RPMs
- automatic layering of a generated `kmod-nvidia` RPM only when no active, correctly signed module is found
- `--layer-kmod-rpm` to force a relayer for recovery even when a module already appears active
- active module signer, package integrity, and `nvidia-smi` checks
- stale or unsigned cached kmod RPM detection
- overwritten-module detection and repair path
- diagnostic-only `--status` mode

## Must know before running

### This is for Fedora Atomic / rpm-ostree

This script expects an OSTree-booted Fedora Atomic system. It checks for `/run/ostree-booted` and `rpm-ostree`.

For traditional Fedora Workstation, the normal RPM Fusion Secure Boot instructions are usually simpler and should generally be used instead.

### Secure Boot requires signed NVIDIA modules

If Secure Boot is enabled and the NVIDIA module is unsigned, loading will fail with errors like:

```text
modprobe: ERROR: could not insert 'nvidia': Key was rejected by service
Loading of unsigned module is rejected
```

The script checks this directly with:

```bash
modinfo -F signer nvidia
```

A blank signer means the active module is not signed.

### MOK enrollment is required

The public half of your local signing key must be enrolled through MOK.

When the script runs:

```bash
mokutil --import /etc/pki/akmods/certs/public_key.der
```

it will ask you to create a temporary password.

That password is **not** your Linux login password. It is only used once during the next reboot.

On reboot, use the blue MOK Manager screen:

```text
Enroll MOK
Continue
Yes
enter temporary password
Reboot
```

Then boot Fedora again and rerun the script.

### rpm-ostree means reboots are normal

Many steps only affect the next deployment. The script will stop and tell you to reboot when needed.

Run the same script again after reboot. It resumes by checking what is already done.

### Existing akmods keys

If `/etc/pki/akmods/certs/public_key.der` and `/etc/pki/akmods/private/private_key.priv` already exist, the script uses them.

If those canonical names are missing but exactly one matching akmods keypair exists, the script creates the canonical aliases and logs what it selected.

If multiple akmods keypairs exist, the script stops instead of guessing. Create explicit `public_key.der` and `private_key.priv` files or symlinks for the key you want to use, then rerun it.

### RPM Fusion release version

The script checks that the installed `rpmfusion-free-release` and `rpmfusion-nonfree-release` package versions match the current Fedora `VERSION_ID`.

If stale RPM Fusion release packages are present after a Fedora rebase, the script stops before staging more rpm-ostree changes.

### Local `akmods-keys` package validation

The script validates an installed `akmods-keys` package by checking its macro content and key files, not by trusting the package version.

It only reuses the installed package when `/etc/rpm/macros.kmodtool` points at the expected packaged key paths and the packaged public/private keys match the selected `/etc/pki/akmods` keypair.

The local RPM generated by this script currently uses version `0.0.2`, but that version is not the trust check.

## Security notes

### The private key has to be available for future automatic rebuilds

This is the main caveat.

The `akmods-keys` RPM contains your private MOK signing key. That is uncomfortable, but it is the practical tradeoff for automatic future NVIDIA/kernel rebuilds with Secure Boot enabled on Fedora Atomic.

If `akmod-nvidia` remains installed, `akmods` may automatically rebuild NVIDIA modules later after a kernel or driver change. If `akmods-keys` is missing at that time, the rebuilt modules may be unsigned, and Secure Boot will reject them.

So the practical rule is:

```text
Keep akmods-keys installed while akmod-nvidia is installed.
```

### Do not share the generated key or RPM

Do **not** upload, publish, attach, or share:

- `/etc/pki/akmods/private/private_key.priv`
- any private key under `/etc/pki/akmods/private/`
- the generated `akmods-keys-*.rpm`
- backups containing those files

The generated `akmods-keys` RPM contains the private signing key.

The packaged private key is intentionally readable by the local build/signing process. That is part of the Fedora Atomic workaround and is why the generated RPM must stay local.

### What is the actual risk?

If an attacker already has root while your private signing key is present, they could sign a malicious kernel module that your Secure Boot setup would trust.

For many personal workstation threat models, this is acceptable because root access already means the system is heavily compromised.

For high-security systems, shared machines, hostile multi-user environments, or machines where Secure Boot is expected to meaningfully contain root compromise, this approach may not be acceptable.

### Keeping Secure Boot enabled is still useful

This setup does not make Secure Boot pointless. It makes Secure Boot trust your locally signed NVIDIA module.

Secure Boot still rejects modules that are not signed by a trusted key. The risk is specifically that your local private signing key becomes sensitive and must be protected.

## Installation

Download or copy the script:

```bash
chmod +x fedora_atomic_nvidia_secureboot_setup.sh
sudo ./fedora_atomic_nvidia_secureboot_setup.sh
```

When the script asks for a reboot:

```bash
systemctl reboot
```

After booting back into Fedora:

```bash
sudo ./fedora_atomic_nvidia_secureboot_setup.sh
```

Repeat until the script reports that NVIDIA works.

Default path:

- install/check `akmod-nvidia`
- create/package `akmods-keys`
- enroll MOK
- run akmods
- verify signed generated kmod RPM
- layer the kmod RPM only if no active, correctly signed module is found yet
- verify active module after reboot if needed

## Diagnostic mode

To print current state without staging rpm-ostree changes:

```bash
sudo ./fedora_atomic_nvidia_secureboot_setup.sh --status
```

This checks and prints:

- rpm-ostree deployment state
- Secure Boot state
- kernel version
- kernel arguments
- RPM Fusion release packages
- NVIDIA packages
- akmods signing keys
- MOK enrollment test
- `akmods-keys` files
- key consistency checks
- cached `kmod-nvidia` RPMs
- signatures inside cached kmod RPMs
- active NVIDIA module path
- active module signer
- `rpm -V` results
- `nvidia-smi` output

`--status` mode should not stage rpm-ostree changes.

## Expected successful result

With Secure Boot enabled, a working system should show something like:

```bash
mokutil --sb-state
```

```text
SecureBoot enabled
```

```bash
modinfo -F signer nvidia
```

```text
fedora_...
```

```bash
nvidia-smi
```

```text
NVIDIA-SMI ... Driver Version: ...
```

A blank `modinfo -F signer nvidia` is bad when Secure Boot is enabled.

## Recovery notes

### Manually layer a generated kmod RPM

The default path only layers a generated `kmod-nvidia-$kernel` RPM when no active, correctly signed NVIDIA module is found for the running kernel (first run, or after a kernel/driver change). Once a working module is active, further runs skip layering and rely on `akmod-nvidia`/`akmods-keys` to keep it current.

`--layer-kmod-rpm` forces a relayer even when a module already appears active. Use it for recovery:

- when the active module looks wrong (unsigned, mismatched signer) but the script isn't detecting it on its own
- because layered `kmod-nvidia-$kernel` RPMs are tied to one exact kernel, forcing one can block future rpm-ostree upgrades

If that happens, remove the old exact package with:

```bash
sudo rpm-ostree upgrade --uninstall kmod-nvidia-<old-kernel-version>
```

or:

```bash
sudo rpm-ostree uninstall kmod-nvidia-<old-kernel-version>
```

Then reboot and rerun the script.

### NVIDIA worked, then broke after removing `akmods-keys`

Do not remove `akmods-keys` while keeping `akmod-nvidia` installed.

If NVIDIA breaks with Secure Boot enabled and you see:

```text
Key was rejected by service
Loading of unsigned module is rejected
```

check:

```bash
modinfo -F signer nvidia
rpm -V kmod-nvidia-$(uname -r)
```

If the signer is blank or `rpm -V` shows changed NVIDIA module files, akmods likely rebuilt or overwrote the signed modules without the signing key being available.

The script attempts to detect this and repair by removing the broken layered kmod from the next deployment. If automatic akmods recovery is not enough, rerun with `--layer-kmod-rpm` to manually layer a verified signed kmod RPM as a recovery path.

### Multiple cached kmod RPMs

The script lists cached `kmod-nvidia` RPMs for the current kernel and uses the newest one by modification time. It extracts and verifies module signatures before trusting it.

Unsigned or broken cached RPMs are moved to:

```text
/var/lib/atomic-nvidia-secureboot-setup/quarantine/akmods/nvidia/
```

## Files created or used

Original akmods keypair:

```text
/etc/pki/akmods/certs/public_key.der
/etc/pki/akmods/private/private_key.priv
```

Packaged key location used by the workaround:

```text
/etc/pki/akmods-keys/certs/public_key.der
/etc/pki/akmods-keys/private/private_key.priv
/etc/rpm/macros.kmodtool
```

Script state/logs:

```text
/var/lib/atomic-nvidia-secureboot-setup/
/var/lib/atomic-nvidia-secureboot-setup/setup.log
/var/lib/atomic-nvidia-secureboot-setup/quarantine/akmods/nvidia/
```

Review `setup.log` before sharing it publicly. It can include sensitive system and signing-key metadata.

Generated NVIDIA kmod RPMs:

```text
/var/cache/akmods/nvidia/
```

## Uninstall / cleanup

This is intentionally conservative.

If you are still using `akmod-nvidia`, keep `akmods-keys` installed.

If you decide to stop using NVIDIA akmods automation, you can remove packages with rpm-ostree, but be aware that future kernel/NVIDIA updates will not be automatically signed unless you reintroduce a signing workflow.

Typical cleanup of temporary build state only:

```bash
sudo rm -rf /var/lib/atomic-nvidia-secureboot-setup/akmods-keys-local
```

Do not delete `/etc/pki/akmods/private/private_key.priv` unless you understand that future signed rebuilds will require generating and enrolling a new key.

## References

- RPM Fusion Secure Boot guide
  https://rpmfusion.org/Howto/Secure%20Boot
  Documents akmods Secure Boot signing support and MOK enrollment for locally built kmods.

- RPM Fusion NVIDIA guide
  https://rpmfusion.org/Howto/NVIDIA
  Documents the RPM Fusion NVIDIA driver path and points Secure Boot users to the Secure Boot signing guidance.

- Fedora Silverblue issue: akmods does not sign compiled module when using rpm-ostree
  https://github.com/fedora-silverblue/issue-tracker/issues/499
  Tracks the Fedora Atomic/Silverblue rpm-ostree issue where akmods signing keys under `/etc/pki/akmods` are not visible in the expected signing context.

- silverblue-akmods-keys
  https://github.com/CheariX/silverblue-akmods-keys
  Prior art for packaging akmods signing keys on Silverblue/Kinoite-style systems so akmods can sign modules under Secure Boot.

## Disclaimer

This is an unofficial community project created and maintained by Amarjit Bharath.

It is not affiliated with, endorsed by, or supported by Fedora, Red Hat, RPM Fusion, NVIDIA, or any Fedora Atomic desktop project.

This script changes rpm-ostree deployments, installs NVIDIA driver packages, creates local signing keys, queues MOK enrollment, and packages a private signing key into a local RPM. Those actions can affect system boot, driver loading, Secure Boot trust, and future kernel module rebuilds.

Read the script before running it.

Use at your own risk. This project is provided without warranty under the MIT License.
