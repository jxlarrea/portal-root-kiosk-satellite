<h1 align="center">
    <img alt="Meta Portal Root and Provisioning for Kiosk Satellite" src="assets/banners/banner3.svg" width="100%" />
     <p></p>
     <p>Meta Portal Root and Provisioning for Kiosk Satellite</p>
     <p align="center">
    <a href="https://kiosksatellite.com"><img src="https://img.shields.io/badge/works_with-kiosk_satellite-blue?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA5MjQuNDQgOTU5LjU1Ij48cGF0aCBmaWxsPSIjZmZmIiBzdHJva2U9IiM1ZGEzYTYiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIHN0cm9rZS13aWR0aD0iNTIuMTUiIGQ9Ik0zOTAuMTYsNTAuNzVjNDIuNDEtMzIuODksMTAxLjcxLTMyLjg5LDE0NC4xMiwwbDMxMi44OSwyMjQuNzFjMzEuOTQsMjEuODUsNTEuMDksNTguMDEsNTEuMiw5Ni43MXY0NDMuNzNjMCw2NC45My01Mi42NCwxMTcuNTctMTE3LjU3LDExNy41N0gxNDMuNjRjLTY0LjkzLDAtMTE3LjU3LTUyLjY0LTExNy41Ny0xMTcuNTd2LTQ0My43M2MuMTEtMzguNywxOS4yNi03NC44Nyw1MS4yLTk2LjcxTDM5MC4xNiw1MC43NVoiLz48cGF0aCBmaWxsPSIjMThiY2YyIiBkPSJNMjQyLjI1LDUxMS41NWMwLTIyLjUyLDE4LjI1LTQwLjc3LDQwLjc3LTQwLjc3czQwLjc3LDE4LjI1LDQwLjc3LDQwLjc3djE3MC42N2MwLDIyLjUyLTE4LjI1LDQwLjc3LTQwLjc3LDQwLjc3cy00MC43Ny0xOC4yNS00MC43Ny00MC43N3YtMTcwLjY3aDBaIi8%2BPHBhdGggZmlsbD0iI2YyYjcwNSIgZD0iTTM2MS43Miw1MzMuMzVjLjAyLTIyLjUyLDE4LjI4LTQwLjc2LDQwLjgtNDAuNzQsMjIuNS4wMiw0MC43MywxOC4yNSw0MC43NCw0MC43NHYxMjcuMDVjLS4wMiwyMi41Mi0xOC4yOCw0MC43Ni00MC44LDQwLjc0LTIyLjUtLjAxLTQwLjczLTE4LjI1LTQwLjc0LTQwLjc0di0xMjcuMDVaIi8%2BPHBhdGggZmlsbD0iIzNmYmY1ZiIgZD0iTTQ4MS4xOSw0MzUuNjljLjAyLTIyLjUyLDE4LjI4LTQwLjc2LDQwLjgtNDAuNzQsMjIuNS4wMiw0MC43MywxOC4yNSw0MC43NCw0MC43NHYzMjIuMzdjLS4wMiwyMi41Mi0xOC4yOCw0MC43Ni00MC44LDQwLjc0LTIyLjUtLjAxLTQwLjczLTE4LjI1LTQwLjc0LTQwLjc0di0zMjIuMzdaIi8%2BPHBhdGggZmlsbD0iI2U4NjA0YyIgZD0iTTYwMC42NSw1MzAuNTFjLjAyLTIyLjUyLDE4LjI4LTQwLjc2LDQwLjgtNDAuNzQsMjIuNS4wMiw0MC43MywxOC4yNSw0MC43NCw0MC43NHYxMzIuNzRjLS4wMiwyMi41Mi0xOC4yOCw0MC43Ni00MC44LDQwLjc0LTIyLjUtLjAxLTQwLjczLTE4LjI1LTQwLjc0LTQwLjc0di0xMzIuNzRaIi8%2BPC9zdmc%2B&labelColor=444444&color=488284" alt="Made for Kiosk Satellite" /></a>
    <a href="https://buymeacoffee.com/jxlarrea"><img src="https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee"></a>
    </p>
</h1>

<p align="center">
Provision Meta Portal devices for the best possible
experience with <a href="https://github.com/jxlarrea/kiosk-satellite">Kiosk Satellite</a> using a root exploit.
All changes are persistent and survive reboots.
</p>

## Overview

The provisioner checks that the connected Portal has an exact supported model
and firmware build, briefly uses a root exploit during a controlled reboot,
applies the features you select, then verifies them across two normal boots.
Persistent features use focused configuration changes or small boot helpers.

> [!NOTE]
> This is not a persistent root exploit. It is a timed, surgical way to change otherwise inaccessible system settings and make the most of a Portal with Kiosk Satellite. All features applied by the provisioner are persistent and survive reboots.

> [!WARNING]
> I have tried to make the provisioner as safe and guarded as possible, but
> low-level system changes always carry a chance that something could go
> wrong. Back up anything important and proceed only if you accept that risk.
> You use this tool at your own risk.

## What the provisioning does

| Feature | What it does and why it helps |
| --- | --- |
| [Temporary root provisioning](#how-the-root-exploit-works) | Opens a short privileged window for selected changes, then returns the Portal to normal enforcing mode. |
| [Persistent wireless ADB](#enable-only-persistent-wireless-adb) | Keeps ADB available on port 5555 after setup, so future reboots no longer require USB activation. |
| [Non-expiring ADB authorization](#disable-adb-authorization-timeout) | Keeps computers you already approved authorized instead of forgetting their ADB keys after Android's timeout. |
| [Complete kiosk profile](#run-the-provisioner) | Applies the recommended Kiosk Satellite setup with one command. |
| [Kiosk Satellite installation](#install-kiosk-satellite) | Downloads, verifies and installs the latest compatible Kiosk Satellite release when the app is missing. |
| [Hardware audio processing control](#disable-hardware-echo-cancellation-and-noise-suppression) | Stops the Portal from suppressing microphone audio while its speaker is playing audio or music. |
| [Kiosk Satellite permissions](#grant-kiosk-satellite-permissions) | Enables the microphone, camera, location, storage, presence sensor, overlays, system settings, usage access and reliable background operation. |
| [Kiosk Satellite Device Owner](#make-kiosk-satellite-the-device-owner) | Gives Kiosk Satellite Android's strongest kiosk-management role. |
| [Persistent Kiosk Satellite home](#use-kiosk-satellite-as-the-home-screen) | Starts Kiosk Satellite at boot and keeps obsolete Meta screens out of the way. |
| [Firmware-update blocking](#disable-automatic-meta-firmware-updates) | Prevents an unexpected Meta update from breaking a known working setup. |
| [Meta remote-wipe blocking](#block-metas-known-remote-wipe-receivers) | Disables Meta's known remote factory-reset entry points while retaining local recovery options. |
| [Meta app debloat](#disable-unused-meta-applications) | Reduces background work from unused Meta apps, cloud clients and diagnostics. |
| [Meta-account removal](#remove-local-meta-accounts) | Removes obsolete local account data while retaining services needed by the camera and Portal. |
| [Presence optimization](#reduce-aiservice-cpu-use-while-preserving-presence-detection) | Lowers AIService CPU use while preserving full-view, LED-free person detection. |
| [Presence frame-rate cap](#optional-presence-analysis-frame-rate-cap) | Further reduces analysis work without limiting Kiosk Satellite's RTSP frame rate. |
| [Filtering Private DNS](#configure-dns) | Sends DNS to a chosen DNS-over-TLS resolver for network-level filtering. |
| [Network-provided DNS](#configure-dns) | Uses the DNS server supplied by the local network, including private LAN hostnames. |
| [Third-party app updates](#allow-kiosk-satellite-and-third-party-app-updates) | Lets correctly signed Kiosk Satellite and other non-Meta APKs update normally. |
| [Automatic Shizuku startup](#install-shizuku-with-automatic-startup) | Starts Shizuku locally after every boot for apps that need ADB-shell privileges. |
| [Read-only status](#status-report) | Reports the device, provisioning and runtime state without exploiting or rebooting. |
| [Dry-run planning](#dry-run-planning) | Shows required tools, actions and reboots before changing the Portal. |
| [Private backup bundles](#backup-bundles) | Saves diagnostics and reversible settings in a private, checksummed archive. |
| [Interrupted-run recovery](#interrupted-run-recovery) | Safely resumes a validated provisioning run after a host or power interruption. |
| [Exact-build safeguards](#supported-models) | Refuses kernel changes unless the model and full firmware fingerprint match. |
| [Automatic retry and verification](#running-and-troubleshooting) | Retries race-sensitive attempts and accepts changes only after two verified boots. |

## Requirements

### Host computer

- Linux x86_64 with Git, GNU Make, Python 3.9 or newer and Android Debug Bridge (`adb`)
- Android NDK r28.2 (`28.2.13676358`)
- A JDK plus Android SDK Platform 36 and Build Tools containing `aapt`, `zipalign`, `apksigner` and `d8`
- A USB data cable for initial stock-device setup
- Internet access when Kiosk Satellite or the pinned Shizuku APK must be downloaded

The provisioner uses only the Python standard library.

### Portal

- An exact model and firmware build listed under [Supported models](#supported-models)
- The initial on-screen setup (OOBE) completed so the Debug menu is available
- ADB enabled in the Portal's Debug menu and the host authorized over USB
- Wireless ADB enabled for the current boot with `adb -d tcpip 5555`
- Stable network, a stable IP address and external power for several reboots
- The physical camera cover open and camera/microphone privacy control off for presence features and the `kiosk` profile

Presence verification checks the live camera pipeline automatically. Nobody
needs to remain in view during the reboot sequence.

## Supported models

| Model | Codename | Android | Supported firmware fingerprint | Kernel | Status |
| --- | --- | --- | --- | --- | --- |
| Meta Portal Go | `terry` | 10 | `Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal 10-inch (1st generation) | `aloha` | 9 | `Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys` | `4.4.153+` | Tested |
| Meta Portal+ (1st generation) | `aloha` | 9 | `Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys` | `4.4.153+` | Tested |
| Meta Portal+ (2nd generation) | `cipher` | 10 | `Facebook/cipher_prod/cipher:10/QKQ1.210213.001/4051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal 10-inch (2nd generation) | `omni` | 10 | `Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal Mini | `omni` | 10 | `Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |
| Meta Portal TV | `ripley` | 9 | `Facebook/ripley_prod/ripley:9/PKQ1.191202.001/2041515800015050:user/prod-keys` | `4.4.153+` | Tested |

Support is exact-build specific. Other models and firmware versions
need their own verified target before the provisioner will accept them.
The `aloha` software family is shared by more than one first-generation form
factor. The original 10-inch Portal and 15.6-inch Portal+ share their firmware
and kernel port, but the provisioner keeps separate exact product-model guards
for `Portal` and `Portal+`.

## Possible supported devices

These models are candidates for future ports based on Meta's published kernel
sources and archived firmware. They are **not supported by the current build**.

No additional models are currently in the porting pipeline; Meta Portal TV
(`ripley`) moved to [Supported models](#supported-models).

To request support, open an issue with the retail model and this output. Do
not publish an ADB address, pairing code or account information.

```sh
adb shell getprop ro.product.model
adb shell getprop ro.product.device
adb shell getprop ro.build.fingerprint
adb shell uname -a
```

## Step-by-step installation

> [!WARNING]
> I have tried to make the provisioner as safe and guarded as possible, but
> low-level system changes always carry a chance that something could go
> wrong. Back up anything important and proceed only if you accept that risk.
> You use this tool at your own risk.

### 1. Install and configure the host tools

Install the tools listed under [Requirements](#requirements), then clone the
repository and point the build at your Android SDK. Adjust the Build Tools path
if your installed version differs.

```sh
git clone https://github.com/jxlarrea/portal-root-kiosk-satellite.git
cd portal-root-kiosk-satellite

export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
export NDK="$ANDROID_SDK_ROOT/ndk/28.2.13676358"
export ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-36/android.jar"
export BUILD_TOOLS="$ANDROID_SDK_ROOT/build-tools/37.0.0"
export D8="$BUILD_TOOLS/d8"
```

### 2. Prepare the Portal

Complete the Portal's initial on-screen setup before continuing. The Debug
menu and its ADB control are unavailable until the out-of-box experience
(OOBE) has finished.

Open the Portal's physical camera cover and turn off its camera/microphone
privacy control. The recommended profile installs
[Kiosk Satellite](https://github.com/jxlarrea/kiosk-satellite) from its latest
GitHub release when the app is missing, opens it once and activates its
device-admin receiver. An existing installation and its data are retained.

<a id="connect-to-the-portal"></a>
### 3. Connect to the Portal

Stock firmware disables ADB after every reboot. Open the Portal's Debug menu,
enable ADB, connect the USB data cable, authorize the host and run:

```sh
adb -d get-state
adb -d tcpip 5555

export PORTAL_IP=192.168.1.100  # replace with the Portal's address
adb connect "$PORTAL_IP:5555"
adb -s "$PORTAL_IP:5555" get-state
```

Both state checks must print `device`. Keep USB connected during the first
provisioning run.

The provisioner begins from a clean reboot. On an unprovisioned Portal, enable
ADB again in the Debug menu and rerun `adb -d tcpip 5555` after every reboot
until the provisioner prints `WIRELESS_ADB_OK`. Keep a second terminal ready
for this step. After the first successful exploit, wireless ADB survives normal
reboots and USB is no longer needed.

### 4. Confirm compatibility

```sh
adb -s "$PORTAL_IP:5555" shell getprop ro.product.device
adb -s "$PORTAL_IP:5555" shell getprop ro.build.fingerprint
```

Both values must exactly match the [supported model](#supported-models). The
provisioner checks them again before making any kernel change.

<a id="run-the-provisioner"></a>
### 5. Run the recommended profile

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" \
  --profile kiosk
```

The `kiosk` profile installs Kiosk Satellite when needed, then configures its
required permissions, Device Owner and HOME role. It also configures audio,
firmware and remote-wipe blocking, debloat, Meta-account removal, presence
optimization, third-party app updates and non-expiring ADB authorization. These
core features do not need to be added as individual flags.

Add only the extra features you want:

- `--presence-fps-cap 2` to reduce Meta's presence-analysis rate
- `--dhcp-dns` or `--privacy-dns HOSTNAME` to change DNS behavior
- `--shizuku` to install Shizuku with automatic startup

The Portal reboots several times and ends with `PROVISION_OK` plus two
different verification boot IDs. If you do not want the complete profile, use
the individual commands in the reference below to build a custom setup.

## Provisioning feature reference

The recommended `kiosk` profile already applies every feature labeled
**Included in the kiosk profile**. Their individual sections remain useful for
selective setups, technical details and rollback commands. Features labeled
**Optional add-on** require their own flag.

<a id="enable-only-persistent-wireless-adb"></a>
<details>
<summary><strong>Standalone setup:</strong> Enable only persistent wireless ADB</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --persistent-wireless-adb
```

This applies only wireless ADB persistence on TCP port 5555. It does not
enable audio changes, debloat, Device Owner, presence optimization, Shizuku,
or the other provisioning features. It also disables Android's authorization
timeout so computers you already approved do not lose access later. Wireless
ADB persistence is already installed automatically whenever another privileged
provisioning action runs; a new persistence install also disables the
authorization timeout.

On a stock Portal, continue manually enabling ADB in the Debug menu and running
`adb -d tcpip 5555` after each provisioning reboot until the command prints
`WIRELESS_ADB_OK`. Later reboots no longer require the USB host.

</details>
<p></p>

<a id="disable-adb-authorization-timeout"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Keep approved ADB computers authorized</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --disable-adb-auth-timeout
```

Android normally expires approved ADB host keys after a period of inactivity.
This sets `adb_allowed_connection_time` to `0`, which tells Android to retain
previously approved keys indefinitely. A new computer must still be approved on
the Portal; this does not disable ADB authentication. The provisioner saves the
original setting before changing it.

This standalone action uses ordinary ADB authority and does not run the root
exploit or reboot the Portal.

`--persistent-wireless-adb` applies this setting automatically. To restore the
saved timeout, run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-adb-auth-timeout
```

</details>
<p></p>

<a id="install-kiosk-satellite"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Install Kiosk Satellite</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --install-kiosk-satellite
```

When Kiosk Satellite is missing, the provisioner reads the latest release from
the official [Kiosk Satellite repository](https://github.com/jxlarrea/kiosk-satellite),
selects the APK for the Portal's CPU architecture, verifies the file against
the SHA-256 digest published by GitHub, installs it and opens it once. It does
not replace or update an existing installation, so its app data is preserved.
This standalone action uses ordinary ADB authority and does not reboot or run
the root exploit.

In the complete `--profile kiosk` flow, installation happens before the
provisioner activates `KioskAdminReceiver`, assigns Device Owner and grants
permissions.

</details>
<p></p>

<a id="disable-hardware-echo-cancellation-and-noise-suppression"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Disable hardware echo cancellation and noise suppression</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --audio
```

The Portal's microphone array passes through a DBMD7/STAX voice DSP before
Android receives it. This action installs a native watchdog inside Meta's
AIService and keeps these private DSP parameters at zero:

- `AEC_ENABLE` (`3001`)
- `NS_MODE` (`4001`), including residual-echo suppression

The change is system-wide, so every Android application receives audio without
those two processing stages. The watchdog reapplies the values after AIService
starts and repairs later firmware-side changes. The provisioner confirms both
readbacks on two boots. A later `--audio` run first checks the persistent
installation marker and the running watchdog. If both are healthy, an
audio-only command exits successfully without rebuilding, exploiting, or
rebooting; when combined with other actions, only the audio installation is
skipped.

Restore Meta's original AIService loader, remove the watchdog, and restore the
firmware's AEC and NS parameter defaults with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-audio
```

The restore uses the original loader saved during the first installation and
refuses to replace an unrelated file.

</details>

<a id="grant-kiosk-satellite-permissions"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Grant Kiosk Satellite permissions</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --kiosk-permissions
```

This grants Kiosk Satellite access to the microphone, camera, location and
shared storage; enables display-over-other-apps, system-settings and usage
access; grants the Portal-specific system-log access used by the built-in
person sensor; and exempts the app from battery optimization. The provisioner
restarts Kiosk Satellite after granting log access and verifies every grant.

This action does not enable or modify Android accessibility services. It uses
ordinary ADB shell authority and does not require the root exploit. The grants
survive reboots and correctly signed application updates. Android revokes the
runtime permissions if Kiosk Satellite's app data is cleared; rerun this action
after a data clear.

</details>

<a id="make-kiosk-satellite-the-device-owner"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Make Kiosk Satellite the Device Owner</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --device-owner
```

This gives Kiosk Satellite Android's Device Owner role for user 0. Device Owner
allows the kiosk to apply stronger device policies than an ordinary device
admin. The complete `--profile kiosk` installs the app when needed and
activates `KioskAdminReceiver` before this step. For a selective setup, run
`--install-kiosk-satellite` first or install the app yourself; the Device Owner
preflight activates the receiver.

Meta accounts normally cause Android's `dpm set-device-owner` command to reject
the operation. The privileged installer writes the Android 10 owner record
only after checking that no other Device Owner exists. It saves the original
policy state under `/data/local/tmp/portal-device-owner-backup` and verifies
both DevicePolicyManager and `ro.device_owner=true` after reboot. There is no
automated Device Owner removal action in the provisioner.

</details>

<a id="use-kiosk-satellite-as-the-home-screen"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Use Kiosk Satellite as the home screen</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --kiosk-home
```

This uses Kiosk Satellite's Device Owner authority to register its
disabled-by-default `HomeAlias` as Android's persistent HOME activity. Kiosk
Satellite then starts directly after boot and receives every Home press. This
also prevents Meta's `AlohaInvalidOwnerHomeActivity` from covering the kiosk
after local Meta accounts are removed. Kiosk Satellite's built-in crash-loop
fuse releases the HOME role automatically if the app repeatedly fails to
start. During provisioning and reboot verification, the provisioner repairs
the HOME selection automatically if Meta's launcher has reclaimed it.

Kiosk Satellite must already be Device Owner. The complete `--profile kiosk`
applies the Device Owner record first and then configures HOME. Release the role
and return to Android's remaining launcher resolution with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-kiosk-home
```

</details>

<a id="disable-automatic-meta-firmware-updates"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Disable automatic Meta firmware updates</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --disable-updates
```

This disables Meta's two OTA user-interface packages and installs a local
MobileConfig override setting `firmware_ota_update_enable=false`. Shared update
infrastructure remains installed, but the native OTA daemon stays idle and
does not discover or install firmware.

The provisioner verifies the disabled packages and requires Meta's own service
to report the value from the local override on two boots. It refuses to replace
an unrelated existing override. The original file state is recorded under
`/data/local/tmp/portal-ota-backup`.

Restore that exact override state and re-enable both OTA packages with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --enable-updates
```

</details>

<a id="block-metas-known-remote-wipe-receivers"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Block Meta's known remote-wipe receivers</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --block-remote-wipe
```

Meta's privileged `com.facebook.alohaservices.deviceadmin` package contains a
factory-reset receiver and a cloud-notification remote-wipe receiver. This
action disables only those two components. The rest of the package remains
enabled, and hardware or recovery-menu factory resets remain available.

The provisioner records the original state of each receiver, applies the
change through Android's Package Manager, and verifies that both receivers
remain disabled across two boots. It does not claim to block every possible
privileged Android reset path; it blocks the two known Meta remote-wipe entry
points present in the supported firmware.

Restore both receivers to their individually saved states with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-remote-wipe
```

</details>

<a id="disable-unused-meta-applications"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Disable unused Meta applications</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --debloat
```

The conservative debloat profile disables these packages for user 0:

- Meta Analytics
- Messenger
- WhatsApp
- Portal Feed
- Superframe
- Meta Contacts

It also disables the matching cloud and background components inside retained
Meta packages. The exact inventories for every supported model are listed
below: 196 are disabled on the tested Portal Go, Portal Mini,
second-generation Portal 10-inch and second-generation Portal+ firmware, and
194 are disabled on the original first-generation Portal. The tested
first-generation Portal+ has a smaller installed package set and disables 39.
Component-level targeting removes unused
work without disabling the camera, audio, presence, media, app-management,
identity, launcher, or WebView packages that the Portal and Kiosk Satellite
still need.

On every tested model, two firmware-owned MQTT entry points are deliberately
retained because each self-enables before use; disabling either caused a
service restart loop during testing: `RegisteredMqttSystemBroadcastReceiver` in
`com.facebook.aloha.system.device` and `MqttService` in
`com.facebook.alohaservices.alohausers`. The remaining MQTT components are
disabled. To stop the retained core client from reaching Meta, apply a
source-specific router rule for the Portal or block `mqtt-mini.facebook.com`,
`graph.facebook.com`, and `facebook.com` with the only DNS resolver advertised
to the device. Android's opportunistic Private DNS can use any advertised
resolver that accepts DNS over TLS, so a public fallback resolver can bypass a
local DNS block list. Fixed-IP rules are brittle because Meta rotates these
names across its address space. The component list is maintained in
`tools/meta_debloat_components.py`.

<details>
<summary>Meta Portal Go, original Portal 10-inch, Portal Mini, Portal 10-inch (2nd generation) and Portal+ (2nd generation): up to 196 disabled components</summary>
<p></p>

On Portal Go firmware `5051355900018050`, Portal Mini and Portal 10-inch
firmware `3051355900018050`, and Portal+ firmware `4051355900018050`, the
provisioner disables the same 196 components. The two intentionally retained
MQTT components are excluded from this inventory.

The original 10-inch Portal uses this inventory too. Its tested factory image
contains 194 of the entries; the two CNS health-monitor components are absent,
so the provisioner records them as absent instead of trying to disable them.

**Background workers (143)**

- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.app.cameraeditor/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.aloha.app.cameraeditor/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.aloha.app.cameraeditor/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.system.services/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.aloha.system.services/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.aloha.system.services/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.aloha.system.services/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.aloha.system.services/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.aloha.system.services/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.system.services/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.system.services/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.periodicwork.PeriodicWorkGuardReceiver`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaappmanager/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.periodicwork.PeriodicWorkAlarmReceiver`
- `com.facebook.alohaappmanager/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaappmanager/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaappmanager/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.periodicwork.PeriodicWorkJobService`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaappmanager/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.common.downloadmanager.impl.DownloadIdleService`
- `com.facebook.alohaappmanager/com.facebook.aloha.app.appmanager.appmanager.scheduler.background.SchedulerJobService`
- `com.facebook.alohaappmanager/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaappmanager/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaappmanager/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.bugreporter/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.bugreporter/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaapps.bugreporter/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.launcher/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.launcher/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.launcher/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.launcher/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.launcher/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.launcher/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.launcher/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.launcher/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.personaluser/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.personaluser/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.personaluser/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.personaluser/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.personaluser/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaservices.abilitymanager/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaservices.abilitymanager/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaservices.alohausers/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaservices.alohausers/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaservices.alohausers/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.alohausers/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaservices.player2/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaservices.player2/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaservices.player2/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaservices.player2/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.alohaservices.player2/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaservices.player2/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaservices.player2/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaservices.player2/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.portal.aiservice/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`

**Bug reporting (16)**

- `com.facebook.aloha.system.services/com.facebook.aloha.system.services.bugreporter.PillViewService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.MannerModeBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.BugReportSystemBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.BugReportNonSystemBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.PortalTVReportScreenLauncherReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.TraceBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.SmartCameraBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.bugreporter.core.scheduler.AlarmsBroadcastReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.gui.BugReporterGuiService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.receiver.PushNotificationReceiver`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.core.ReportIntentService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.core.UploadStreamService`
- `com.facebook.alohaapps.bugreporter/com.facebook.bugreporter.core.scheduler.LollipopBugReportService`
- `com.facebook.alohaapps.bugreporter/com.facebook.alohacommon.bugreporterlib.AppLogsService`
- `com.facebook.alohaapps.bugreporter/androidx.work.impl.background.systemjob.SystemJobService`
- `com.facebook.alohaapps.bugreporter/com.facebook.aloha.system.bugreporter.bishop.BishopSupportService`

**Diagnostics (15)**

- `com.facebook.aloha.app.cameraeditor/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.aloha.cnshealthmonitor/com.facebook.aloha.cnshealthmonitor.CNSHealthMonitorBroadcastReceiver`
- `com.facebook.aloha.cnshealthmonitor/com.facebook.aloha.cnshealthmonitor.CNSHealthMonitorService`
- `com.facebook.aloha.system.device/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.aloha.system.services/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.aloha.wifidiagnostic/com.facebook.aloha.wifidiagnostic.WifiDiagnosticBootReceiver`
- `com.facebook.aloha.wifidiagnostic/com.facebook.aloha.wifidiagnostic.WifiDiagnosticService`
- `com.facebook.alohaappmanager/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.bugreporter/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.launcher/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.settings/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaservices.abilitymanager/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaservices.alohausers/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaservices.player2/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.portal.aiservice/androidx.work.impl.diagnostics.DiagnosticsReceiver`

**Firebase (12)**

- `com.facebook.aloha.app.cameraeditor/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.aloha.app.cameraeditor/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.aloha.app.cameraeditor/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.aloha.app.cameraeditor/com.google.firebase.provider.FirebaseInitProvider`
- `com.facebook.aloha.system.device/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.aloha.system.device/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.aloha.system.device/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.aloha.system.device/com.google.firebase.provider.FirebaseInitProvider`
- `com.facebook.alohaservices.alohausers/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.alohaservices.alohausers/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.alohaservices.alohausers/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.alohaservices.alohausers/com.google.firebase.provider.FirebaseInitProvider`

**MQTT (8)**

- `com.facebook.aloha.app.cameraeditor/com.facebook.push.mqtt.service.MqttPushHelperService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.multiusermqtt.MultiuserMqttService`
- `com.facebook.aloha.app.cameraeditor/com.facebook.mqtt.service.MqttServiceV2`
- `com.facebook.aloha.app.cameraeditor/com.facebook.mqttlite.MqttService`
- `com.facebook.alohaservices.alohausers/com.facebook.push.mqtt.receiver.BootCompleteBroadcastReceiver`
- `com.facebook.alohaservices.alohausers/com.facebook.mqtt.service.MqttServiceV2`
- `com.facebook.alohaservices.alohausers/com.facebook.multiusermqtt.MultiuserMqttService`
- `com.facebook.alohaservices.alohausers/com.facebook.push.mqtt.service.MqttPushHelperService`

**Push notifications (2)**

- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationBootReceiver`
- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationService`

</details>
<p></p>
<details>
<summary>Meta Portal+ (1st generation): 39 disabled components</summary>
<p></p>

On firmware `1041515800015050`, the provisioner disables 39 components.

**Background workers (30)**

- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.aloha.system.device/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.alohaapps.settings/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.alohaapps.settings/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.HighPriUploadRetryReceiver`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerServiceReceiver`
- `com.facebook.portal.aiservice/com.facebook.analytics.appstatelogger.AppStateIntentService`
- `com.facebook.portal.aiservice/com.facebook.reportaproblem.base.bugreport.BugReportUploadService`
- `com.facebook.portal.aiservice/com.facebook.delayedworker.DelayedWorkerService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.ConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.service.LollipopUploadSafeService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.Analytics2UploadService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.LollipopUploadService`
- `com.facebook.portal.aiservice/com.facebook.conditionalworker.LollipopConditionalWorkerService`
- `com.facebook.portal.aiservice/com.facebook.analytics2.logger.legacy.uploader.AlarmBasedUploadService`

**Diagnostics (3)**

- `com.facebook.aloha.system.device/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.alohaapps.settings/androidx.work.impl.diagnostics.DiagnosticsReceiver`
- `com.facebook.portal.aiservice/androidx.work.impl.diagnostics.DiagnosticsReceiver`

**Firebase (4)**

- `com.facebook.aloha.system.device/com.google.firebase.iid.FirebaseInstanceIdReceiver`
- `com.facebook.aloha.system.device/com.google.firebase.components.ComponentDiscoveryService`
- `com.facebook.aloha.system.device/com.google.firebase.messaging.FirebaseMessagingService`
- `com.facebook.aloha.system.device/com.google.firebase.provider.FirebaseInitProvider`

**Push notifications (2)**

- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationBootReceiver`
- `com.facebook.alohasdk.pushnotification/com.facebook.alohasdk.pushnotification.PushNotificationService`

</details>
<p></p>
Before changing package state, the provisioner saves the exact enabled,
disabled, or absent state of every package in
`/data/local/tmp/portal-debloat-backup-v1.tsv` and every targeted component in
`/data/local/tmp/portal-debloat-components-backup-v1.tsv`. Restore those saved
states with:
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-bloat
```

Both commands verify the retained camera, AIService, Kiosk Home, and WebView
paths across two reboots.

</details>

<a id="remove-local-meta-accounts"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Remove local Meta accounts</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --remove-meta-accounts
```

This removes the Portal-specific proxy SSO, platform-login, and private-owner
accounts from Android AccountManager and Meta's local identity databases. It
then disables their three user-account authenticator components so firmware
cannot immediately recreate the accounts. The hardware-identity authenticator
and shared `alohausers` package stay enabled because camera startup,
MobileConfig, and other Portal services depend on them.

The original account type and name inventory is saved at
`/data/local/tmp/portal-meta-accounts-before-v1.tsv` and copied into the host
log directory. Tokens and full database contents are not backed up, so this
action has no automated restore. Repeated runs are safe: once the accounts are
gone and the authenticators are disabled, the tool only verifies the state.

Removing the final Meta owner account can make Portal firmware select its
obsolete invalid-owner HOME screen. Use `--kiosk-home` after Kiosk Satellite is
Device Owner, or use `--profile kiosk`, to keep the account warning from taking
focus.

Meta's production Debug page also builds its ADB row from the signed-in owner
profile. After the local Meta accounts are removed, that page may appear empty
even though ADB remains enabled and wireless ADB remains available. To open the
firmware's full Debug page from an authorized ADB computer, run:

```sh
adb -s "$PORTAL_IP:5555" shell am start \
  -a com.facebook.aloha.system.settings.DEBUG_TAB
```

</details>

<a id="reduce-aiservice-cpu-use-while-preserving-presence-detection"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Reduce AIService CPU use while preserving presence detection</summary>
<p></p>

Run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --optimize-presence
```

Kiosk Satellite reads AIService's `Notify people presence` log to use the
Portal's person detector without activating an application camera and its
on-screen camera LED. This profile keeps that detector, AIService's camera
client, tracking, and pose estimation active while disabling four downstream
Smart Camera workloads:

- background segmentation
- liveness scoring
- color-based re-identification
- face-recognition-based re-identification

Disabling Meta's background detector by itself lets Smart Camera leave the
pose pipeline on a narrow region of interest, which severely reduces presence
coverage. The profile also sets `enable_hardware_cropping=false`. AIService
then processes the uncropped camera source, preserving the Portal's full field
of view without running the background-detector worker.

Open the Portal's physical camera cover and make sure its camera/microphone
privacy control is off before running this action. Meta intentionally stops
the AIService camera client while either hardware privacy control disables the
camera, so presence verification cannot pass in that state.

The provisioner requires an active AIService camera client, an allowed CAMERA
AppOp, live analysis and region-of-interest frame delivery, a loaded frame
processor, populated pose-estimator metrics, all five settings loaded as
false, and hardware cropping absent from the active camera request on every
verification boot. Those checks cover the same retained path
that updates AIService's world model and emits `Notify people presence`, so the
two-reboot verification can run unattended. An actual presence event is
reported as additional evidence when one occurs, but it is not required for a
successful run. On the tested Portal Go, the original cropped optimization
averaged 22.1% of one core but reduced the usable field of view. The corrected
full-scene profile measured 35.5% in a five-minute sample, compared with 47.8%
before optimization. Workload affects these figures, so treat them as a guide
rather than a fixed saving.

The original settings-file state is stored under
`/data/local/tmp/portal-presence-backup`. Restore it with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-presence-profile
```

The installer and restore action use atomic file replacement, preserve the
app's ownership and SELinux label, and refuse to overwrite an unrelated edit.

</details>

<a id="allow-kiosk-satellite-and-third-party-app-updates"></a>
<details>
<summary><strong>Included in the kiosk profile:</strong> Allow Kiosk Satellite and third-party app updates</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --allow-app-updates
```

Meta registers `com.facebook.appverifier` as Android's package-verification
agent. It rejects APKs whose certificates are outside Meta's private allowlist,
including correctly signed Kiosk Satellite releases, with
`INSTALL_FAILED_VERIFICATION_FAILURE`. This action saves the existing Android
setting and verifier-package state, sets `package_verifier_enable=0`, and
disables Meta's verifier package for user 0. The package state is the durable
control if Meta later rewrites the Android setting. The provisioner verifies
both states on two separate boots.

This action is independent of Shizuku. It allows updates installed through the
normal Android confirmation screen, Kiosk Satellite Device Owner, the optional
update helper, or Shizuku. Android continues to require a matching application
signature for updates and continues to reject version downgrades. Meta's
verifier package remains installed and can be restored to its saved state.

Restore the saved Android setting and verifier-package state with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-app-verifier
```

</details>

<a id="optional-presence-analysis-frame-rate-cap"></a>
<details>
<summary><strong>Optional add-on:</strong> Presence-analysis frame-rate cap</summary>
<p></p>

The full-scene profile keeps Meta's analysis pipeline busy at its firmware
rate. To reduce that remaining load, cap only its pose-analysis callback. Two
frames per second is the tested balance for room-presence detection:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --presence-fps-cap 2
```

Valid values are 1 through 10. This option automatically includes the tested
full-scene presence profile. It writes Meta's own analysis-throttle settings
and installs a small local boot helper that applies them after each reboot,
then stops. Applying the setting briefly opens Meta's hidden AI settings
activity and immediately returns to the configured Home app.

Android blocks an ordinary background app from opening that activity. The
provisioner therefore adds the one-shot activation to its narrowly scoped UID
1000 boot helper. That helper waits for Android and AIService to settle, opens
the hidden activity, returns to Home, and exits when no persistent helper task
remains. It does not depend on Shizuku, ADB, another computer, or network access
after installation. Both presence rollback commands remove the activation
configuration; the shared helper remains only if another feature still uses
it.

The cap is downstream of camera capture. Tests on Portal Go retained the
camera's normal `[8, 30]` target range while Meta logged a 2 FPS analysis rate.
A first-generation Portal+ also retained its full field of view and live pose
pipeline at 2 FPS across two reboots. Kiosk Satellite RTSP uses a separate
Camera2 capture and encoder path, so it remains free to stream at its configured
frame rate. A live Portal Go test decoded 56 RTSP frames over 9.98 seconds,
about 5.5 FPS from the configured roughly 6 FPS stream, while Meta analysis
remained at 2 FPS. The provisioner verifies the applied analysis rate, full
field of view, camera request, pose pipeline, and helper activation on two
boots.

Remove only the cap and helper while keeping the full-scene optimization:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-presence-fps
```

`--restore-presence-profile` also removes the cap and helper before restoring
the complete original presence configuration.

</details>

<a id="configure-dns"></a>
<details>
<summary><strong>Optional add-on:</strong> Configure local or filtering DNS</summary>
<p></p>

To resolve private LAN zones through the DNS servers advertised by the active
network, run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --dhcp-dns
```

This disables Android's opportunistic Private DNS mode. Android then uses the
DNS servers and search domain supplied by DHCP and IPv6 router advertisements.
It does not force a particular server address, so the router must advertise
the intended local resolver. In `dumpsys connectivity`, `defaultIPv4DNS` is
only the firmware's fallback when a network supplies no resolver; the
`DnsAddresses` field in the connected network's `LinkProperties` is the active
server list. `--status` reports both lists separately.

Alternatively, configure a specific DNS-over-TLS resolver:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --privacy-dns dns.example.net
```

Replace `dns.example.net` with the DNS-over-TLS hostname of a resolver you
control or trust. The provisioner configures Android's strict Private DNS mode;
the resolver supplies the block list. This can reduce connections to unwanted
Meta endpoints without modifying system certificates or installing a broad
root firewall. Confirm that the resolver permits the services Kiosk Satellite
needs before applying it fleet-wide.

The first DNS action saves both original Android settings. Restore them with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-privacy-dns
```

</details>

<a id="install-shizuku-with-automatic-startup"></a>
<details>
<summary><strong>Optional add-on:</strong> Install Shizuku with automatic startup</summary>
<p></p>

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku
```

This downloads the pinned official Shizuku release on the host computer,
verifies its SHA-256 digest, and installs it with a small Portal boot helper.
The Portal itself does not need internet access for this step. Meta's required
APK certificate verifier accepts only Meta-approved signing certificates, so
the provisioner temporarily disables the verifier package around the two
local installs, restores the package's original enabled state, waits for
Package Manager to save it, and checks the result after reboot. The separate
`--allow-app-updates` action controls whether later third-party updates are
accepted.

Supported Portals run Android 9 or 10, where upstream Shizuku cannot
automatically start ADB mode after boot. The helper solves that limitation
entirely on the device:
it receives Android's normal boot broadcast, connects to the Portal's existing
ADB daemon at `127.0.0.1:5555`, authenticates with a key generated for that
Portal, and runs Shizuku's own starter. The temporary-root action authorizes
only that public key. The host's ADB private key is never copied to the Portal.

Shizuku runs as Android user `shell` (UID 2000), which is the normal Shizuku
ADB privilege level; it is not a persistent UID-0 root service. Once
installation completes, no host computer or network connection is needed for
startup. Wireless ADB must remain enabled locally because the helper uses its
loopback listener. The two-boot verifier requires `shizuku_server` to run as
`shell` after both ordinary reboots.

To use a Shizuku APK you downloaded yourself, run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku --shizuku-apk ./shizuku.apk
```

Remove the manager, boot helper, running server, and the helper's authorized
ADB key with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --remove-shizuku
```

</details>

## Inspection, backups and recovery

### Status report

Print a read-only JSON report without exploiting or rebooting the Portal:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --status
```

The report includes exact target support, boot and SELinux state, Kiosk
Satellite version, permissions and Device Owner state, audio and OTA markers,
remote-wipe protection, debloat and account status, the live presence pipeline,
Private DNS, Shizuku package and server state, and the last provisioning
manifest.

### Dry-run planning

Preview an action or the full profile without changing the device:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --profile kiosk --dry-run
```

The plan identifies required build outputs, host tools, exploit use, estimated
minimum reboots, and the current state.

### Backup bundles

Create a private diagnostic and configuration archive before making changes:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --backup ./backups
```

`--backup` may also accompany a provisioning command. The resulting mode-0600
archive contains status, relevant Android service dumps, reversible device
snapshots, and a SHA-256 manifest. It can contain account names and device
configuration, so store it as sensitive data.

### Interrupted-run recovery

Every mutating run writes a state manifest at
`/data/local/tmp/portal-provision-state-v1.json`. It records the exact target,
firmware fingerprint, selected actions, Git revision, artifact hashes, state,
and verification boot IDs. If power or the host fails during a run, reconnect
ADB and resume the pending action set with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --recover
```

Recovery first removes stale staged files. It resumes only a validated pending
manifest; for a completed run or a device with no manifest, it prints status
and exits without changing the configuration.

## Technical details and troubleshooting

<a id="how-the-root-exploit-works"></a>
<details>
<summary><strong>How the root exploit works</strong></summary>
<p></p>

The project adapts GhostLock,
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), to a
specific Portal kernel. The provisioner confirms the complete device identity,
reboots into a clean state, derives randomized kernel addresses and starts the
exploit through a staged native library. Temporary kernel read/write access
gives only that process the credentials needed to perform the selected work.

The device then reboots normally with SELinux enforcing. The exploit does not
install `su`, a root shell or a root daemon. Features that must survive reboot
use narrow configuration changes or dedicated helpers with only the privileges
they need. The provisioner verifies the requested state on two normal boots.

Kernel exploitation is race-sensitive, so a missed attempt can reboot or
briefly freeze the Portal. The provisioner retries from a clean boot. Exact
model and firmware checks prevent it from using one build's kernel layout on
another device.

</details>

<a id="running-and-troubleshooting"></a>
<details>
<summary><strong>Running and troubleshooting</strong></summary>
<p></p>

The default maximum is 12 exploit attempts. Change it with `--attempts N`,
where `N` is between 1 and 100. A failed race normally causes a clean reboot
and another attempt. Before `WIRELESS_ADB_OK` has appeared, re-enable ADB in
the Portal's Debug menu and run `adb -d tcpip 5555` after every reboot. If the
Portal remains unresponsive, power-cycle it, restore USB and wireless ADB, and
rerun the same command; completed provisioning actions are designed to be
repeatable.

Use `--skip-build` only when the required outputs have already been built and
have not changed. Every root-backed action requires both the selected exploit
library and `exploit-sentinel/build/portal-exploit-sentinel.apk`. The
provisioner installs that no-permission package temporarily, confirms that
`run-as` accepts it, and removes it automatically. Display every available
option with:

```sh
python3 tools/provision_portal.py --help
```

Each successful run verifies the requested state on two distinct boots. Read
the final `PROVISION_OK` line and keep the attempt directory when diagnosing a
failure.

</details>

## Support the project

If this project breathed new life into your Meta Portal, consider supporting
my work through [Buy Me a Coffee](https://buymeacoffee.com/jxlarrea). Your
support helps me obtain more Portal models, test additional firmware and keep
improving the tools that make these devices useful again.

<p align="center">
  <a href="https://buymeacoffee.com/jxlarrea"><img src="https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee"></a>
</p>
