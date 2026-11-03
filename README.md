# Bluetooth keyboard in UEFI setup

Work towards a UEFI driver that makes a BLE keyboard (here a Microsoft
Bluetooth Ergonomic Keyboard on a MediaTek MT7922) usable in firmware setup.
The design is in `~/Downloads/Bluetooth Keyboard in UEFI Setup.md`.

Since Nov 1, the implementation is in **Rust** (`rust/`), using `uefi` 0.41
and the TrouBLE BLE host (`trouble-host` 0.8). The earlier C/EDK2 code
(`BtKbPkg/`, with NimBLE) stays as a reference; EDK2 is still used for
tooling (UEFI shell, OVMF builds).

## Status

| Milestone | State |
| --- | --- |
| 1. Bring-up probe (`bt-hci-probe.efi`) | Works on the real MT7922 through QEMU/OVMF: firmware already loaded, Bluetooth on, HCI queries, clean handoff (211 ms) |
| 2. LE scan (`bt-le-scan.efi`, TrouBLE) | Done: the fourth run saw the bonded keyboard: directed advertising to this PC, then undirected with the HID UUID. Earlier runs:<br>- The second wedged the controller until a mains power cycle (see below).<br>- The third ended in a TrouBLE panic on a malformed event, probably data lost on cancelled reads in QEMU. Fixed with an async interrupt transfer, event validation and a panic handler that returns to the shell. |
| 3. Connect + encrypt with the exported LTK | Done (Nov 1): connected, encrypted with the exported legacy key, read the Report Map and decoded typing in report protocol ("hello uefi"). Boot protocol doesn't work on this keyboard. TrouBLE's queues were enlarged after bursts lost notifications; confirmed with fast typing (82 of 82 delivered). |
| 4. Driver (`bt-kb-dxe.efi`) | Shell done on hardware (Nov 1): loaded from the shell, the driver made the Bluetooth keyboard a console keyboard, the wake keys were replayed, and the OS hand-off left Linux a working controller (setup 173 ms). Since then: started by a USB notify the moment the controller appears, refuses a second load, and remembers the keyboard's layout between boots (`BtKbGatt`). Offline, as a Driver#### at boot, its F2 opens OVMF's boot menu. **Done in OVMF on the real controller and keyboard (Nov 2):** loaded at boot, ready 0.65 s in; an F2 on the Bluetooth keyboard during the countdown opened the boot menu, delivered 180 ms after the keyboard connected (remembered layout); setup worked; Reset handed the controller back and Linux took over (setup 181 ms). |
| 5. Real board (AMI Aptio) | **The firmware loads the driver at every boot (Nov 2)**, from a Driver#### entry with the firmware's full device path (it ignores efibootmgr's short form). AMI's USB stack works, and AMI signals BeforeExitBootServices: the driver hands the controller back when Linux starts. **Del on the Bluetooth keyboard gets into AMI setup, and typing works there.** The 4–6 s stalls of the first session (TrouBLE 0.8 handles only Encryption Change v1, the controller sends v2) are fixed and confirmed after a cold boot: one connection for the whole session. **Warm reboots failed because of AMI's Fast Boot**, which was on before the project: a fast boot skips Driver#### entries, so the driver never ran (22:52: boot loader after 10.7 s, against 14–15 s in full boots). With Fast Boot off, a warm reboot ran the driver (23:15): keys flowed into Limine, and the boot record (`BtKbLastBoot`), which survives boots that end early, worked. Next: Del after a warm reboot, the idle reconnect, a reset from setup, one Windows boot. |

## Layout

```
rust/                   Cargo workspace
  mtk-bt/               no_std: firmware parser, WMT channel, upload, on/off, reset; host tests + simulator
  uefi-bt/              UEFI: HCI interface discovery, UsbIo transport, HCI I/O with diagnostics,
                        async event pipe (pipe.rs), TSC clock, app helpers (bring-up, hand-off,
                        recovery), panic handler (emergency.rs, feature "panic-handler"), and
                        (feature "embassy") TrouBLE glue: time driver, critical section,
                        validating bt-hci transport
  bt-hci-probe/         milestone 1 app
  bt-le-scan/           milestone 2 app
  bt-kb-probe/          milestone 3 app: connect, encrypt with the exported key, boot protocol, key reports
  bt-kb-dxe/            milestone 4: the UEFI driver (binding, timer, TrouBLE session, Simple Text Input)
  bt-kb-log/            `btlog` in the UEFI shell: prints the driver's log and variables as text
  ebs-test/             calls ExitBootServices and powers off, to test the driver's OS hand-off
BtKbPkg/                C/EDK2 reference implementation (MtkBtLib, NimBLE port, BtHciProbe, BtLeScan)
edk2/                   edk2-stable202608 (submodule)
scripts/                build, test and QEMU helpers
tools/                  locally built NASM and QEMU (libusb, GTK), the Arch OVMF package (not in git)
qemu/                   scratch ESPs and serial logs (not in git)
```

## Commands

```sh
scripts/build-rust.sh              # host tests + Rust UEFI apps
scripts/qemu-smoke.sh [app.efi]    # OVMF + UEFI shell, no Bluetooth device
scripts/qemu-hw-probe.sh           # REAL CONTROLLER: milestone 1 probe
scripts/qemu-hw-scan.sh [-t 60]    # REAL CONTROLLER: milestone 2 scan (passive)
sudo scripts/export-bond.sh [ADDR] # copy the keyboard's bond from BlueZ to qemu/keys/ (user-only); ADDR defaults to
                                   #   KEYBOARD_ADDR in private/local.env, without either it lists BlueZ's LE bonds
scripts/qemu-hw-kb.sh [-t 90]      # REAL CONTROLLER: milestone 3, connect to the keyboard and show key reports
LIVE=1 scripts/qemu-hw-kb.sh       # the same, showing the output in the terminal as it happens
scripts/qemu-driver-test.sh        # driver, offline: self-test typing, no-device load + second load, panic,
                                   #   ExitBootServices, F2 hotkey at boot (Driver####), boot load without a device,
                                   #   the board's diagnostics boot on a GPT disk, measured boot (TPM=1), a changed
                                   #   firmware image, Secure Boot refusals (SB=1), bonds, the sealed bond (TPM=1)
                                   #   (ONLY="1 7" runs some)
SB=1 TPM=1 scripts/qemu-driver-test.sh  # the same with Secure Boot on (test keys) and a TPM 2.0 (swtpm)
scripts/tpm-host-test.sh           # the driver's TPM code (seal, unseal, refusals) against swtpm on the host
scripts/eventlog.py driver FILE    # a TCG event log: where bt-kb-dxe loaded, separators, PCR 7 as it saw it
scripts/eventlog.py predict FILE 2,7 --spare 8   # the PCR values the driver unseals with, and the policy digest
scripts/bond-digest.py FILE.bond   # the digest a driver build pins for a bond (build-rust.sh pins qemu/keys/*.bond)
scripts/qemu-hw-driver.sh [180]    # REAL CONTROLLER: driver loaded in the shell (QEMU window); end with ebs-test.efi or reset
scripts/qemu-hw-boot.sh [240]      # REAL CONTROLLER: driver loaded at boot (Driver####, QEMU window, driver log in the
                                   #   terminal); press F2 on the keyboard for the boot menu, try setup, end with Reset.
                                   #   FRESH=1: new NV store; WINDOW= LIVE=1: serial console in the terminal instead
scripts/qemu-hw.sh "<cmd>" ...     # REAL CONTROLLER: any shell commands
sudo scripts/board-install.sh      # REAL BOARD: driver + firmware image + bond to \EFI\btkb\, Driver#### entry; signs the
                                   #   driver with sbctl's db key, or DB_KEY/DB_CERT (a file or pkcs11: URI); with Secure
                                   #   Boot on, refuses what doesn't verify (--dry-run shows the steps, --remove undoes it)
scripts/secureboot-setup.sh        # REAL BOARD: the CachyOS sbctl flow as a checklist: what's done, what to run next;
                                   #   never enrolls keys or changes anything (--dry-run: just the steps; sudo: more checks)
sudo scripts/tpm-seal.sh           # REAL BOARD: seal the bond to the TPM from this boot's event log (after a boot with
                                   #   the driver; --dry-run, --if-needed, --no-fallback); scripts/systemd/ has a unit
                                   #   that reseals at boot after a PCR change
scripts/board-log.sh               # REAL BOARD: the driver's log of this boot, a timeline since the CPU reset (driver
                                   #   loaded, keyboard connected, hotkeys, boot loader, OS), this and the previous
                                   #   boot's one-line records (BtKbLastBoot), its variables, Linux's setup; for a
                                   #   boot without a driver log, when the boot loader started (Fast Boot hint)
sudo scripts/board-diag.sh         # REAL BOARD: next boot only, a UEFI shell in \EFI\btkb\ saves diagnostics, gives the
                                   #   driver entry the firmware's full device path, loads the driver; `btlog` there shows
                                   #   its log, `linux` saves the log and starts Limine; --collect afterwards copies the
                                   #   results to board/ (--dry-run, --remove)
scripts/build.sh, scripts/test.sh  # the C/EDK2 reference build and its host tests
scripts/scrub.py check [--history] # private identifiers in tracked files (or in everything a push publishes);
                                   #   apply FILE replaces them, install-hooks guards commits (see Private data)
```

The hardware scripts pass USB device `0e8d:0616` through to OVMF. They power
the adapter off in BlueZ first, so no connection is live when QEMU takes the
controller. Afterwards they wait for Linux to set it up again and power BlueZ
back on. Bluetooth is down on the host while QEMU runs, the keyboard included. The device node must be writable once:
`sudo setfacl -m u:$USER:rw /dev/bus/usb/BBB/DDD` (the script prints the path).
No script uploads firmware unless `-upload` is passed explicitly. The exported
bond is copied onto the scratch ESP only for hardware runs and deleted from it
afterwards; delete `qemu/keys/` when you no longer need it.

## Private data

Hardware identifiers in this repository are placeholders, among them the
keyboard's Bluetooth address `C0:00:00:00:00:01`, the controller's
`02:00:00:00:00:02` and the host name `myhost`. The real values are kept
out of git:

- **`private/`** (git-ignored): `scrub-map.tsv` lists each real value with
  its placeholder; `local.env` holds local settings such as the keyboard
  address for `export-bond.sh`. `private/README.md` explains both.
- **`scripts/scrub.py`** reads that map. `install-hooks` adds pre-commit and
  commit-msg hooks that refuse a commit containing a real value, `apply FILE`
  replaces the values in a file (a design-doc snapshot, say), and
  `check --history` checks every file and message a push would publish.
  Without a map, as in a fresh clone, it checks nothing.
- **No address in the code:** `bt-kb-probe` and `bt-le-scan` take the
  keyboard from the bond file next to them, as the driver does.
- **Bonds:** exported keyboard bonds hold the link key and stay in
  `qemu/keys/`, also git-ignored. On the board, the driver moves the bond
  into a variable the OS can't read and deletes the file (see
  [Security](#security)).

## Controller wedge (Nov 1)

- **What happened:** the keyboard was still connected when QEMU took the controller. Key presses during the run put data on the ACL pipe, which the scan app didn't read. The host stack's first `HCI_Reset` then never completed, and the app hung until QEMU's 300 s timeout.
- **Recovery:** after that the chip didn't answer on USB at all. A port power cycle and a reboot didn't help; only a mains power cycle did.
- **After the power cut:** Linux re-uploaded the firmware, which took 20.5 s.
- **Changes since:**
  - The apps read the ACL pipe from the start, drain anything queued, and send their own `HCI_Reset` before the host stack starts.
  - A watchdog ends a stuck setup after 10 s, and MediaTek crash dumps (`0xFC6F`) are detected.
  - On failure the apps print the last 48 packets. With `-recover` they fall back to the MT7922 subsystem reset before QEMU releases the device.
  - The scripts power BlueZ off before the handover.
- **Old design doc:** `notes/design-doc.before-wedge-notes.md` is the copy from before these notes were added.

## QEMU test environment

- **ESP:** a FAT32 image on virtio-blk, built with mtools. The emulated SATA disk (`fat:rw:` or an image) made OVMF hang or time out now and then.
- **Driver log:** goes to QEMU's debug console at port 0x402, saved as `driver.log` next to the serial log.
- **Live output** (`LIVE=1`): `scripts/live-filter.py` passes the serial console through byte by byte (keys echo as typed, setup screens render) and drops only OVMF's terminal-resize request. Keys typed in the host terminal before QEMU starts are flushed, so they can't reach the guest's serial console.
- **Window** (`WINDOW=1`, the default in `qemu-hw-driver.sh` and `qemu-hw-boot.sh`): the guest's screen in a GTK window, the driver's log live in the terminal. Keys reach the guest only from the Bluetooth keyboard (no PS/2 controller, serial console to the log file). There's no menu bar or working close button, and Ctrl+C in the terminal is caught: all of these would end QEMU while the driver holds the controller.
- **Driver at boot:** `add_driver_option` (in `common.sh`) boots the shell once to run `bcfg driver add`, giving a variable store whose Driver#### points at `PciRoot(0x0)/Pci(0x2,0x0)/\bt-kb-dxe.efi`, which is the ESP in every QEMU run here. `-boot menu=on,splash-time=N` gives OVMF a boot countdown with F2/Esc as boot-menu hotkeys.
- **Secure Boot** (`SB=1`, in `qemu-driver-test.sh` and the `qemu-hw-*` scripts): Arch's `OVMF_CODE.secboot.4m.fd` (Secure Boot, SMM, TPM 2.0) on q35 with SMM and a secure flash. The variable store gets throwaway test keys (PK, KEK, db, in `qemu/sb/keys/`) enrolled with `virt-fw-vars`, and Secure Boot on. Every image put on an ESP comes from `qemu/sb/signed/`, signed with the test db key by `sbsign`. Without sbsigntools, the images' Authenticode hashes are enrolled in db instead (`SB_MODE=hash`), which tests the same enforcement. `virt-fw-vars` comes from the `virt-firmware` package or a venv in `tools/venv-fw`.
- **TPM** (`TPM=1`): swtpm as a TPM 2.0, attached as `tpm-crb` (`TPM_DEVICE=tpm-tis` for TIS), state in the run's `tpm/` directory. `tpm_host_start` in `common.sh` serves the same state over TCP to tpm2-tools on the host (`TPM2TOOLS_TCTI=swtpm:…`), for provisioning between runs. tpm2-tools only ever talk to swtpm here, never to the machine's TPM.
  - **Hangs:** about one boot in ten with a TPM hangs in the firmware (Nov 3). QEMU's TPM emulation takes ~15 s for one command, and the guest later stalls for good in a delay loop. It happens without the driver too, with `tpm-crb` and `tpm-tis` alike, and with swtpm's state on tmpfs. `qemu-driver-test.sh` retries a TPM boot that times out (at most twice, from the same variable store and TPM state) and says so: `(TPM boot hung, retrying …)`.
- **Event log:** `btlog -eventlog FILE` writes the firmware's TCG event log (crypto-agile, the format of Linux's `binary_bios_measurements`) to the ESP; `scripts/eventlog.py` reads and replays it.
- **Self-test keys:** `bt-kb-dxe.selftest` may contain `{f2}`, `{esc}`, `{enter}`, `{tab}`, `{bs}`, arrows (`{up}` …) and `{wait:MS}`.

## Known risks

- **Short control transfers:** `EFI_USB_IO_PROTOCOL` doesn't report the received length, and EDK2's UsbBusDxe returns `EFI_DEVICE_ERROR` with a clean USB status for any short control IN transfer. Every WMT event poll is short. The transport reports that as success plus a "short" flag, and the WMT code zero-fills the buffer to tell "no event yet" from an event. AMI's own USB stack still needs checking.
- **ACL pipe:** events come through an asynchronous interrupt transfer, but the ACL pipe is still read with 1 ms synchronous bulk transfers. In QEMU those can lose data when a transfer is cancelled. That's fine while ACL data is only drained, but connections (milestone 3) need a better way; UEFI's USB I/O has no async bulk transfer.
- **Event throughput:** the async pipe gets one 16-byte packet per firmware timer tick, about 100 packets/s with a 10 ms tick. Scans therefore use duplicate filtering (`-dups` turns it off).
- **Wedge recovery untested:** the MT7922 subsystem reset (`-recover`) is Linux's recovery after a firmware crash. Whether it revives a controller that has stopped answering HCI is untested.
- **Security:** see [Security](#security) for the threat model, what the driver does about it, and what remains.

## Security

### Threat model

- **Root (or an administrator in Windows) can always read the keyboard's
  link key** from BlueZ (`/var/lib/bluetooth`) or Windows. Hiding the key
  from them is not a goal.
- **Goals:**
  1. Root can't make the firmware run different pre-boot code, or trust a
     different keyboard, without a key that isn't on this machine.
  2. No plaintext link key (LTK) at rest outside the encrypted root file
     system. Before the hardening, the `.bond` file sat on the FAT ESP.
  3. With a TPM, the stored key is sealed: useless off this machine, and
     not unsealable once the OS is running.
  4. Nothing received before the link is encrypted is ever delivered as a
     keystroke.
  5. An attacker in radio range without the LTK can't inject keys; at worst
     they can deny service.

### What each stage protects against

| Stage | Protects against | State |
| --- | --- | --- |
| 0. Test harness | Nothing by itself: Secure Boot (OVMF with SMM, test keys, signed images) and a TPM 2.0 (swtpm) in the QEMU runs, so the later stages can be tested before they reach the board. The driver logs PCR 7, which separators were already measured and its own load event when it starts, and `btlog -eventlog` saves the event log for `scripts/eventlog.py`. | Done (Nov 3): Secure Boot in sign and hash mode, the TPM with swtpm. QEMU's TPM emulation hangs about one boot in ten, also without the driver; the harness retries those. |
| 1. The link (`uefi-bt/src/tap.rs`) | **Goal 4:** reports that arrive before encryption are dropped and counted, not replayed once the link is encrypted. **Goal 5:** the driver never pairs; it refuses LE Enable Encryption with any key but the bonded one, and drops Security Manager (SMP) packets both ways. Without that, TrouBLE 0.8 starts a fresh Just Works pairing when the bonded key fails, so a device answering with the keyboard's address could pair and type. | Done (Nov 3); host tests |
| 2. Secure Boot and the firmware image | **Goal 1**, as far as Secure Boot reaches: with your own keys enrolled (sbctl), the firmware runs bt-kb-dxe only if your db key signed it, and refuses a replaced or tampered driver; the boot goes on without it. The MT7922 firmware image next to the driver, which Secure Boot doesn't cover, must match the SHA-256 the driver was built with, or the driver refuses it before parsing it. | Done offline (Nov 3): the Secure Boot tests pass with signed images (sbsign) and with hashes in db |
| 3. Bonds (`bt-kb-dxe/src/bondstore.rs`) | **Goal 1** for the keyboard: a build trusts only the bonds whose digests it was built with, so a bond file dropped on the ESP for another device is ignored. **Goal 2** without a TPM: the driver moves a trusted bond file into a variable the OS can't read or write (`BtKbBond`, no RUNTIME_ACCESS) and deletes the file from the ESP. No variable the OS can read holds key material. | Done offline (Nov 3) |
| 4. TPM sealing (`uefi-bt/src/seal.rs`, `bt-kb-dxe/src/sealed.rs`) | **Goal 3:** the bond sealed to the TPM with a policy over PCR 2, PCR 7 and a spare PCR as the driver sees them: useless on another machine or after a TPM clear, and neither the OS nor anything else that runs after the driver can unseal it. Unsealed over a salted session with an encrypted, HMAC-checked answer; the host stack never holds the key. | Done offline (Nov 3): against swtpm on the host, and in OVMF with swtpm (eight boots). Not yet on the board. |

- **When keys count:** the tap treats the link as encrypted only after an
  Encryption Change (v1 or v2) with status 0x00 and encryption on. It must
  be for the connection to the bonded address and address type, with this
  PC as the central, and follow an LE Enable Encryption with the bonded
  key on that connection.
- **The host stack's word alone doesn't count:** TrouBLE 0.8 reports a
  resumed bond with the same PairingComplete event as a fresh pairing. The
  session goes on once the tap has seen the encryption with the bonded
  key, and ends if the host stack reports one the tap didn't see.
- **Pre-encryption reports:** those that arrive on the encrypted link
  before the report layout is known are kept and delivered once it is.
  Those that arrive before encryption are dropped. Since HCI events and ACL
  data travel on different USB endpoints, a report sent just after
  encryption can still overtake its Encryption Change event. Such a report,
  usually the key that woke the keyboard, is lost too.
- **Opt-in: `insecure-replay-unencrypted`.** Building the driver with
  `cargo build -p bt-kb-dxe --features insecure-replay-unencrypted` brings
  back the old behaviour: pre-encryption reports are delivered once the
  link is encrypted. An unencrypted LE link has no integrity protection,
  so anyone in radio range can inject into that window. For experiments
  only; the driver logs a warning at every start when built this way.

### Secure Boot (stage 2)

- **Setup:** `scripts/secureboot-setup.sh` walks through the CachyOS wiki's
  flow and checks each step: `sbctl create-keys`; `sbctl enroll-keys
  --microsoft --firmware-builtin` (without `--firmware-builtin` on ASUS and
  Gigabyte boards); Limine with an enrolled config
  (`ENABLE_ENROLL_LIMINE_CONFIG=yes`, a b2sum on the splash path,
  `limine-enroll-config`, `limine-update`). It enrolls nothing itself.
- **The driver:** the firmware checks Driver#### images against db itself,
  so `board-install.sh` signs `bt-kb-dxe.efi` and `btlog.efi` like the boot
  loader. With sbctl's keys it uses `sbctl sign -s`, which records the
  files, so sbctl's hook and `sbctl sign-all` keep re-signing them. With
  Secure Boot on, it stops if a file doesn't verify, or if the signing
  certificate isn't in the firmware's db. With Secure Boot off, it
  installs with a warning.
- **The firmware image:** Secure Boot doesn't cover files next to the
  driver. The build pins the MT7922 image's SHA-256 (`BT_KB_FIRMWARE`,
  set by `build-rust.sh`; `bt-kb-dxe/build.rs`). The driver refuses any
  other image before parsing it, and so does `board-install.sh`. After a
  linux-firmware update, rebuild and reinstall. Embedding the image instead
  would have grown the driver by 517 KB for the same guarantee.
- **Keys off the machine:** sbctl keeps PK, KEK and db unencrypted in
  `/var/lib/sbctl/keys`. Root can sign anything with them, and the firmware
  runs it, so against root (goal 1) they must not stay on the machine.
  Move them to removable media, or keep db on a PKCS#11 token. Then sign
  with the key mounted: `DB_KEY=/media/key/db.key DB_CERT=/media/key/db.pem
  sudo -E scripts/board-install.sh`, or `DB_KEY='pkcs11:…'` for a token,
  through sbsign's engine.
  - **The price:** sbctl's pacman hook can't re-sign the kernel and Limine
    after updates. Until you sign them with the key, the next boot fails
    Secure Boot.
  - **Microsoft's keys:** with `--microsoft` enrolled (needed for Windows
    and for GPU option ROMs), anything Microsoft signed runs too, so goal 1
    also rests on a current dbx.

### Bonds (stage 3)

- **Trusted bonds:** a driver build trusts only the bonds it was built
  with. `build-rust.sh` passes the digests of `qemu/keys/*.bond` in
  `BT_KB_BOND_DIGESTS` (`scripts/bond-digest.py` computes them).
  - **The digest:** SHA-256 of a domain tag and the whole bond: identity
    address and type, adapter, LTK, key type and size, EDIV, Rand. It
    reveals nothing about the key.
  - **Why it holds:** anyone who can write the ESP can drop a bond file,
    but only a driver signed with the db key can trust it.
  - **Why digests, not signed bonds:** I chose this over Ed25519-signed
    bonds. There's one root of trust (the db key) instead of a second
    offline key, and no asymmetric crypto or signature parsing in the
    firmware.
  - **The price:** re-pairing means rebuilding and re-signing the driver.
  - **Offline tests:** they build the driver into `rust/target/offline-test/`,
    trusting a throwaway test bond with a public, made-up key. A
    production build must never trust that bond: anyone could then type.
- **No plaintext key on the ESP:** `board-install.sh` puts the bond file
  next to the driver. At the next boot the driver copies it into
  `BtKbBond`, NV+BS without RUNTIME_ACCESS, so Linux and Windows can
  neither read nor write it. Once the copy reads back right, the driver
  overwrites the file with zeros and deletes it. Later boots read the
  variable and check it against the build again.
  - **Why overwrite:** a plain delete only frees the FAT directory entry,
    and the key stays in the ESP's free clusters. FAT has no
    copy-on-write, so the overwrite lands in the file's own clusters.
    `board-install.sh` overwrites the bond files it removes, too
    (`shred`). Offline case 11 checks the whole ESP image, free space
    included; with a plain delete the key is still there.
  - **Re-pairing:** export the new bond, rebuild, reinstall; the new file
    replaces the stored bond.
  - **Untrusted files:** they are logged and left alone.
- **Removing:** the OS can't delete a boot-services-only variable, so
  `board-install.sh --remove` takes two steps.
  1. It deletes any bond file and leaves `bt-kb-dxe.forget`. At the next
     boot the driver then deletes `BtKbBond` and the marker, and stops.
  2. Run after that boot, it removes the rest.
  - **`--force`:** removes everything at once. The stored bond then stays
    in NVRAM until a UEFI shell deletes it:
    `dmpstore -d BtKbBond -guid 5223227b-ac96-454e-9bca-f15199748a3c`.
- **Variables the OS can see:** efivarfs files are world-readable in Linux.
  The driver writes only these with RUNTIME_ACCESS, and none holds key
  material:
  - **`BtKbLog`:** the log. It never prints the key (`ExportedBond`'s
    `Debug` leaves it out) or typing; only F-keys, Esc and Delete are
    named.
  - **`BtKbLastBoot`:** the boot record.
  - **`BtKbBoots`:** the counter.
  - **`BtKbGatt`:** handles, report layout, keyboard address.
  - **`BtKbPanic`:** a panic message. Fixed text from the code; none of
    the driver's panics formats key material.
  - **Test:** offline case 11 checks this after a boot with a stored bond.
    No variable with RUNTIME_ACCESS and nothing in the log contains the
    test key, in either byte order; `BtKbBond` does.
- **Key copies in memory:** the driver wipes its copy of the key at
  BeforeExitBootServices, because the OS gets boot services memory as it
  is. The guard's copy goes at the hand-off, and TrouBLE never has one
  (see stage 4).

### TPM sealing (stage 4)

- **What's sealed:** the bond's 42-byte record, under the storage root key
  at 0x81000001. That's systemd's key; `tpm-seal.sh` creates it from the
  same template if it's missing. `bt-kb-dxe.sealed` on the ESP holds only
  the sealed object's public and private parts, the expected PCR values,
  the policy digest and the bond's digest; nothing in it is secret. The
  record reaches `tpm2_create` through a pipe.
- **The policy:** one TPM2_PolicyPCR over PCR 2, PCR 7 and the spare PCR
  (8, or `BT_KB_SPARE_PCR` at build time), with the values they have while
  the driver runs.
  - **PCR 2** holds the driver's own load measurement, and its separator
    comes after the driver, in EDK2 and on this board. No OS ever sees that
    value, with the driver or without it, and no other Driver#### does.
  - **PCR 7** is the Secure Boot state: SecureBoot, PK, KEK, db, dbx and,
    with Secure Boot on, the db entry that verified the driver. On this
    board its separator also comes after the driver (seen with Secure Boot
    off). EDK2 measures it before any image runs.
  - **The spare PCR** must be zero. The driver extends it on every boot
    with a TPM, right after it tried to unseal, and logs that as an
    EV_EFI_ACTION. Nothing that runs later can unseal: an app started from
    setup, the boot loader, the OS. Its number is a build setting, so
    whoever can write the ESP can't make the driver skip it.
  - **Where the values come from:** `scripts/eventlog.py predict` replays
    this boot's event log up to the driver's load event. In place of the
    logged image hash it uses that of the driver the next boot runs
    (`eventlog.py pehash`: the Authenticode hash firmware measures).
    `tpm-seal.sh` checks the policy digest against `tpm2_policypcr`'s, and
    refuses values the TPM has right now.
  - **Why not PCR 7 before its separator alone:** with this board's order
    it would hold, but in EDK2 PCR 7's separator comes first. And PCR 7
    doesn't change when the driver is left out. An image signed with the
    same db key run as a Driver#### (Limine, say) would see the same PCR 7,
    and could start an OS before the separators. PCR 2 and the spare PCR
    close that.
- **The session:** a policy session salted with an ECDH secret for the
  storage key (P-256), so someone reading the TPM's bus learns nothing.
  Unseal carries the command HMAC, and the answer comes back XOR-encrypted
  with the session key and is HMAC-checked. The random numbers mix
  RDSEED/RDRAND, the firmware's RNG and the TPM's. The unsealed record must
  still be a bond the build trusts (stage 3).
- **When unsealing fails** (a dbx or key update, a firmware update, a new
  option ROM, a TPM clear), the driver:
  - logs why and which PCRs changed;
  - records it in `BtKbLastBoot` ("unseal failed: …");
  - uses its boot-services copy (stage 3).

  `tpm-seal.sh --if-needed` then reseals from that boot's event log, and
  the next boot unseals again. `scripts/systemd/bt-kb-reseal.service` runs
  it at every boot. `board-install.sh` reseals right away for a new driver
  build.
- **`--no-fallback`:** the stage 3 copy is a plaintext key in the
  firmware's variable store. The OS can't read it, but whoever dumps the
  SPI flash can. `tpm-seal.sh --no-fallback` writes `fallback=no`. The
  driver then deletes `BtKbBond` and imports no bond file, and
  `board-install.sh` stops copying one, so the key is only in the sealed
  object. The price: after a PCR change, one boot without the Bluetooth
  keyboard, until the reseal.
- **No TPM:** stage 3, as before.
- **The host stack never holds the key:** TrouBLE gets a stand-in. The
  link guard puts the real key into LE Enable Encryption on its way to the
  controller, and the transport wipes the packet. The driver runs at every
  boot, so this matters: an OS booted from a USB stick gets the
  boot-services memory, and finds no copy there.
- **Tests:**
  - **`scripts/tpm-host-test.sh`:** the driver's unseal code against
    libtpms (swtpm) on the host. It unseals and the answer's HMAC checks.
    A changed PCR, a corrupted private part and another storage key are
    refused with the right reasons. Nothing stays loaded in the TPM.
  - **Offline case 12 (`TPM=1`):** eight boots of the driver in OVMF. It
    is sealed from the first boot's event log, and the driver unseals it.
    From the shell, after the separators, it's refused: by PolicyPCR's
    value check, and without it by the policy. A dbx entry changes PCR 7:
    the copy is used, and `--if-needed` reseals. A corrupted seal fails
    cleanly. Without a TPM the copy is used. `fallback=no` deletes it, and
    a failed unseal then leaves no key.
  - **Known answers:** KDFa, KDFe and the policy digest are checked against
    independent implementations (Python's hmac and hashlib,
    `tpm2_policypcr`).

### Residual risks

- **A keystroke in firmware no longer proves physical presence.** Anyone
  who has the LTK can type into setup from radio range.
- **Legacy pairing:** this keyboard bonds with LE legacy pairing. An
  attacker who recorded the original pairing can recover the LTK offline
  (as with crackle), and then counts as the keyboard.
- **Radio-facing parsing in firmware:** HCI events and ACL data from the
  radio are parsed in pre-boot firmware: by the driver, TrouBLE and bt-hci.
  Rust keeps that memory-safe, and events are validated before TrouBLE
  sees them, but a parser panic still restarts the machine (denial of
  service).
- **The board's order with Secure Boot on:** the policy needs the driver
  to load before the PCR 2 and PCR 7 separators that count. That holds in
  EDK2 (PCR 2) and on this board with Secure Boot off (both). `tpm-seal.sh`
  notes any selected PCR whose separator comes before the driver: check its
  output once Secure Boot is on.
- **The fallback copy:** with `fallback=yes` (the default), the key also
  sits in the firmware's variable store, readable from a dumped flash chip
  (see `--no-fallback`).
- **An active attacker on the TPM bus** who can also write the ESP could
  slip the driver a storage key of their own and learn the salt. The
  driver checks the storage key against the name recorded at sealing, on
  the ESP. A passive bus reader learns nothing, and an AMD fTPM has no bus.
- **Firmware already running:** firmware code that runs between the
  driver's load and its PCR extend could unseal. It is trusted firmware,
  measured or not.
- **Copies outside the driver:** the controller and the firmware's USB
  buffers see the key in LE Enable Encryption, and RAM can be read in a
  cold-boot attack.
- **Old copies on disk:** bond files deleted before the overwrite (Nov 3)
  may still sit in the ESP's free space: `board-install.sh` replaced the
  file with `rm` at every reinstall. A flash disk can also keep remapped
  blocks out of reach of any software. Re-pairing the keyboard once
  everything is set up makes all of them useless.
- **Building on this machine:** the driver is built where root rules. Root
  could change what gets built (the trusted bond digests, say) before you
  sign it with an off-machine key. Signing protects only what you meant to
  sign if the build itself can be trusted.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

Not covered by this:

- **Submodules** keep their own licenses: EDK2 (`edk2/`) is BSD-2-Clause-Patent, and NimBLE (`BtKbPkg/Library/NimbleLib/mynewt-nimble`) is Apache-2.0.
- **`BtKbPkg/Library/NimbleLib/Port/include/syscfg/syscfg.h`** is a modified copy of NimBLE's configuration header and stays under Apache-2.0 only, as its header says.
- **The MediaTek firmware image** isn't part of this repository; the scripts take it from the system's linux-firmware package.
- **Built binaries** also contain the Rust crates they depend on, under those crates' own licenses (mostly MIT OR Apache-2.0; `cargo metadata` lists them).
