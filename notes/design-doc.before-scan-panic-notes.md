# Bluetooth Keyboard in UEFI Setup

Nov 1, 2026 · @Dávid Balatoni

## Short answer

Yes, a custom EFI driver can make a Bluetooth keyboard usable in firmware setup, but it is a big project. The UEFI spec already defines Bluetooth protocols (Bluetooth Host Controller, Bluetooth IO and config protocols, plus BLE since UEFI 2.7). Almost no consumer firmware ships a Bluetooth stack, so most of it would be written or ported by us.

The implementation is in Rust (`uefi` crate plus the TrouBLE BLE host), chosen on Nov 1 so the code that parses untrusted radio input in pre-boot firmware is memory-safe.

On this machine the internal MediaTek MT7922 is a good first target, so the proof of concept doesn't need a separate dongle. Its firmware upload is just chunked vendor commands over USB endpoint 0, and the chip keeps its firmware through power-off. The keyboard supports HOGP boot protocol, so the HID layer can reuse UsbKbDxe's 8-byte report handling.

## Target machine

Measured on myhost on Nov 1, 2026.

| Item | Value |
| --- | --- |
| Board and firmware | ASRock A620I Lightning WiFi, AMI BIOS 4.43 (2026-06-24) |
| Secure Boot | Off, setup mode (no PK). An unsigned `Driver####` loads for now. |
| Controller | MediaTek MT7922, USB `0e8d:0616` on port 1-10, Bluetooth 5.4, public address `02:00:00:00:00:02` |
| USB interface 0 | Class E0/01/01. EP `0x81` interrupt IN (16 B), `0x82` bulk IN and `0x02` bulk OUT (512 B). |
| USB interface 1 | Isochronous (voice). Not needed. |
| Keyboard | Microsoft Bluetooth Ergonomic Keyboard (`045E:0817`), BLE, static random address `C0:00:00:00:00:01`, bonded |
| Keyboard GATT | HID service with Protocol Mode, Report Map, Boot Keyboard Input (`0x2A22`, notify) and Boot Keyboard Output (`0x2A32`) |
| Host privacy | BlueZ privacy is off, so the keyboard knows the host by its public address |
| Other OS | Windows Boot Manager is first in BootOrder; Limine boots Linux. The ESP is `nvme0n1p1`, mounted at `/boot`. |

## Driver stack

The driver sits on top of the firmware's existing USB support and ends by exposing a normal text-input device. Most internal laptop and desktop Bluetooth chips (Intel AX/BE series, Realtek, MediaTek) are attached over USB. Firmware already has an xHCI driver, so the stack builds on `EFI_USB_IO_PROTOCOL`.

&#91;embedded content: driver stack · 7 layers, 3 new\]

A key press travels up from the controller to the setup UI; the three highlighted layers are what the driver adds.

1. **HCI over USB transport.** Control endpoints carry commands, the interrupt endpoint carries events, and bulk endpoints carry ACL data. UEFI drivers get no interrupts. The xHCI driver already services `UsbAsyncInterruptTransfer` from its own timer, so the driver adds a periodic timer event that runs the Bluetooth stack and polls bulk IN; UEFI has no async bulk transfers.
2. **Controller firmware loading.** This is the nasty part. Intel, Realtek and MediaTek chips often come up without usable firmware and need a firmware or patch blob uploaded first, as Linux's `btintel`, `btrtl` and `btmtk` do. Intel's bootloader handshake is the hardest; MediaTek's is plain chunked vendor commands (see [MT7922 firmware upload](#mt7922-firmware-upload)). The driver can read the blob from the ESP at runtime instead of embedding it.
3. **Host stack.** L2CAP plus one of two keyboard profiles:
   - **Classic HID:** L2CAP on PSM 0x11/0x13, fairly simple once connected.
   - **BLE HOGP:** ATT/GATT plus SMP for pairing and encryption. Most modern keyboards are BLE, including ours.

   Port a stack built to run without an OS rather than writing one. NimBLE (Apache-2.0, BLE only) and BTstack (no-OS friendly; free for personal, non-commercial use only, commercial use needs a BlueKitchen licence) are the realistic C candidates. In Rust, TrouBLE (`trouble-host`, Apache-2.0/MIT, from the embassy project) covers central, scanning, GATT client and a security manager. We use TrouBLE: the keyboard is BLE, and a Rust stack keeps the radio-facing parsers memory-safe. NimBLE was ported first, in C, and is kept as a fallback.
4. **Expose the keyboard to firmware.** Install `EFI_SIMPLE_TEXT_INPUT_PROTOCOL` and the `_EX` variant on a handle with a device path. ConSplitter merges it into `ConIn`, which HII-based setup screens read. In current EDK2, ConSplitter only takes handles carrying the `gEfiConsoleInDeviceGuid` tag, and ConPlatform adds that tag only for devices listed in `ConIn`, so the driver installs the tag itself. Map HID usages to EFI scan codes and Unicode, as `UsbKbDxe` does.
5. **Clean handoff.** Before `ExitBootServices`, reset the controller and release it so the OS driver starts from a clean state. Do it in the `BeforeExitBootServices` event group, where USB transfers still work (see [Handoff at ExitBootServices](#handoff-at-exitbootservices)).

## MT7922 firmware upload

This follows Linux `btmtk_usb_setup()` and `btmtk_setup_firmware_79xx()` in `drivers/bluetooth/btmtk.c` (current master). The whole sequence runs over endpoint 0, so in UEFI every step is a synchronous `UsbControlTransfer`.

### USB primitives

| Purpose | bmRequestType | bRequest | wValue | wIndex | Data |
| --- | --- | --- | --- | --- | --- |
| HCI command | `0x20` | `0x00` | 0 | 0 | Standard HCI command packet |
| WMT event poll | `0xC0` | `0x01` | `0x0030` | 0 | IN, 64 bytes. Returns 0 bytes until the event is ready. |
| Chip register read | `0xC0` | `0x63` | reg >> 16 | reg & 0xFFFF | IN, 4 bytes LE |
| UHW register read | `0xDE` | `0x01` | reg >> 16 | reg & 0xFFFF | IN, 4 bytes LE |
| UHW register write | `0x5E` | `0x02` | reg >> 16 | reg & 0xFFFF | OUT, 4 bytes LE |

### WMT framing

- **Command:** HCI vendor command `0xFC6F`. The parameters are a 5-byte WMT header `{dir = 0x01, op, dlen (LE16) = payload + 1, flag}` followed by the payload. HCI caps parameters at 255 bytes, so a payload is at most 250 bytes, which is also the upload chunk size.
- **Reply:** there is no Command Complete. Poll endpoint 0 until it returns vendor event `0xE4` with a WMT header whose `op` matches. Linux waits 500 µs between empty polls and gives up after 10 s.
- **Ops used:** `0x01` patch download, `0x06` function control. FUNC_CTRL replies may carry a big-endian 16-bit status after the header.
- **Short replies:** every event poll is a short control transfer: 0 bytes while nothing is pending, 7 bytes for the replies seen so far. EDK2's UsbBusDxe reports a short control IN as `EFI_DEVICE_ERROR` with no USB error bits, even though the data arrived. Treat that combination as success.
- **Measured on myhost** (through QEMU and OVMF):
  - A loaded section answers `E4 05 02 01 01 00 02`.
  - FUNC_CTRL is acked with `E4 05 02 06 01 00 00`, with no status word.
  - Every reply was ready on the first poll.

### Sequence

1. **Identify the chip.** Read register `0x70010200` and expect `0x7922`. Linux reads `0x80000008` first to rule out the MT7663. Register `0x80021004` gives the variant: the file is `BT_RAM_CODE_MT7922_1_<(value & 0xFF) + 1>_hdr.bin`, which here is `_1_1`.
2. **Parse the file.** It has a 32-byte header, then a 64-byte global descriptor with the section count at offset 12, then one 64-byte map per section. Each map holds the type, file offset and size, then a 52-byte "bin info" block (load address, download size, key index, mode, CRC). Check every offset against the file size.
3. **Query each section** with a non-zero download size: patch download, flag 0, payload = `0x00` + the 52-byte bin info block. The reply's flag means:
   - 0: needs a download.
   - 1: busy. Sleep 100 ms and retry, up to 20 times.
   - 2: already loaded. Skip the section.
4. **Upload.** Send the section in chunks of up to 250 bytes from its file offset, using patch download with flag 1 on the first chunk, 2 on the middle ones and 3 on the last. Wait for the WMT event after every chunk.
5. **Wait** 100–120 ms for the firmware to activate.
6. **Set the endpoint reset option.** UHW write `0x74011890 = 0x00010001`.
7. **Turn Bluetooth on.** FUNC_CTRL, flag 0, payload `0x01`.
8. **Continue with standard HCI.** Send `HCI_Reset`, then `Read_BD_ADDR`, which should return `02:00:00:00:00:02`, then LE setup.

- **Shutdown:** Linux's `btmtk_usb_shutdown()` sends FUNC_CTRL with payload `0x00`.
- **Recovery:** after a WMT timeout, do the MT7922 subsystem reset from `btmtk_usb_subsys_reset()` and restart from step 1. Linux retries once. The reset steps are:
  1. Set bits `0x2020` in `0x70002610`.
  2. Write `0x74011890 = 0x00010001`.
  3. Set bit 0 in `0x70002610`.
  4. Wait 100 ms.
  5. Poll bit 8 of `0x70002510` (reset done) for up to 1 s.
  6. Write `0x74000024 = 0xFF`.
  7. Read the chip ID again.

### This firmware file

`BT_RAM_CODE_MT7922_1_1_hdr.bin` from `linux-firmware-mediatek 1:20261019-1` is 517,398 bytes after unpacking the `.zst` (it barely compresses). The header gives build `20260724143815`, platform `ALPS`, and HW and SW version `0x008a`.

| Section | File offset | Download size | Load address | Chunks |
| --- | --- | --- | --- | --- |
| 0 | `0x120` | 80,128 B | `0x00900000` | 321 |
| 1 | `0x13A20` | 436,864 B | `0x0091C000` | 1,748 |
| 2 | `0x7E4A0` | 0 (118-byte info section) | n/a | Not sent |
| Total | | 516,992 B | | 2,069 chunks + 2 queries |

### What the boot logs show

Linux took 178–190 ms for MediaTek setup on all 10 boots in the journal. Four of those came straight after a power-off (Oct 17→18, Oct 18→24, Oct 25→29, Oct 29→30). That time includes the fixed 100 ms activation wait, and 2,069 round trips can't fit in the remaining ~90 ms. So both section queries answered "already loaded" every time, which means the card keeps its firmware in soft-off, presumably on standby power.

- **Usual case for the driver:** two queries and FUNC_CTRL, about 0.2 s.
- **Full upload:** only after a loss of mains power (PSU switch, unplug, outage). Measured on Nov 1 after a mains power cycle: Linux's setup took **20.5 s**, about 10 ms per 250-byte chunk. My earlier estimate of 1–3 s was wrong by an order of magnitude. A driver can't hold up boot for that, so after power loss the keyboard would arrive about 20 s late, long after the setup hotkey window.
- **Version pinning, observed:** from Oct 18 until the Nov 1 power cycle, every boot reported AOSP extensions v0.96, although linux-firmware was updated on Oct 24. After the power cycle Linux uploaded its current file (build 20260724) and the controller reports AOSP v1.00. So the chip had been running an older build for weeks, uploaded before Oct 18 by an older linux-firmware or by Windows. Whoever uploads first after power loss fixes the version, because Linux skips sections that are already loaded. Keep the ESP copy in step with `linux-firmware` (a pacman hook) so the UEFI driver doesn't pin an old build.

### Controller wedge (Nov 1)

The second hardware scan left the MT7922 dead until mains power was removed.

- **Timeline:**
  - **19:25:10:** the keyboard reconnected to Linux.
  - **19:25:29:** QEMU took the controller, with that link still live inside it.
  - **During the run:** key presses on the keyboard produced data on that link, and nothing read the controller's ACL pipe; the apps only read it once connections existed.
  - **The hang:** WMT commands on endpoint 0 still worked, but the host stack's first `HCI_Reset` never got its Command Complete. The stack has no timeouts, so the app hung.
  - **19:30:29:** the 300 s QEMU timeout killed it. The kernel's port reset found a device that no longer answered.
- **Recovery:** a USB port power cycle and a warm reboot didn't help; only a mains power cycle did.
- **Likely cause (not proven):** the controller held its events back behind the unread ACL data. The first scan worked with no keyboard traffic.
- **Changes made:**
  - The ACL pipe is now read from the moment the interface is opened.
  - Anything queued is drained, and our own `HCI_Reset` (reading ACL while it waits) runs before the host stack starts.
  - A watchdog ends a stuck setup after 10 s.
  - MediaTek crash dumps on the ACL pipe (handle `0xFC6F`; debug handles `0x05FF`, `0x05FE`, `0x2EFD`) are detected.
  - The hand-off can fall back to the MT7922 subsystem reset (`-recover`) before QEMU releases the device, the same order Linux uses after a firmware crash.
  - The hardware scripts power BlueZ off first, so no link is live at handover.

## Module layout

Build **one driver image with three parts**, split at the UEFI spec's Bluetooth protocol boundaries, plus shell apps for bring-up. A single image means one `Driver####` entry, one file to sign later and one FFS file to embed with UEFITool. The protocol definitions (`BluetoothHc.h`, `BluetoothLeConfig.h`, `BluetoothAttribute.h`) already exist in the UEFI spec and EDK2's MdePkg, so the internal interfaces need no new GUIDs.

Since Nov 1 the code is a Rust workspace (`~/Projects/bt-uefi-keyboard/rust`). The first version was C on EDK2 with NimBLE (`BtKbPkg/`, kept as a reference). EDK2 stays useful for tooling: the UEFI shell, OVMF, and packing the driver into an FFS file.

```
rust/
├── mtk-bt/        no_std: firmware parser, WMT channel, upload, on/off, reset; host tests + simulator
├── uefi-bt/       UEFI: HCI interface discovery, UsbIo transport, HCI I/O, TSC clock, app helpers;
│                  feature "embassy": time driver, critical section, bt-hci transport for TrouBLE
├── bt-hci-probe/  milestone 1 app
├── bt-le-scan/    milestone 2 app (TrouBLE scan)
└── (next)         bt-kb-probe (milestone 3), then the driver: UsbHc / LeBus / HidKb
```

### Handles and protocols

| Handle | New protocols | Installed by | Consumed by |
| --- | --- | --- | --- |
| USB interface 0 of `0e8d:0616` (created by the USB bus driver) | `EFI_BLUETOOTH_HC_PROTOCOL` | UsbHc | LeBus |
| Same handle | `EFI_BLUETOOTH_LE_CONFIG_PROTOCOL` | LeBus | Test apps; a pairing UI later |
| One child per connected bonded peer: parent path + `BluetoothLE` node (`MSG_BLUETOOTH_LE_DP` 0x1E, address and type) | Device path, `EFI_BLUETOOTH_ATTRIBUTE_PROTOCOL` | LeBus | HidKb |
| Same child | `EFI_SIMPLE_TEXT_INPUT_PROTOCOL`, `_EX`, `gEfiConsoleInDeviceGuid` tag | HidKb | ConSplitter |

### Binding 1: UsbHc

UsbHc consumes `EFI_USB_IO_PROTOCOL` and produces `EFI_BLUETOOTH_HC_PROTOCOL`.

- **Supported():** VID `0x0E8D` with interface class E0/01/01. Linux matches all MediaTek Bluetooth parts the same way, with `USB_VENDOR_AND_INTERFACE_INFO(0x0e8d, 0xe0, 0x01, 0x01)`.
- **Start():** drain the event and ACL pipes, run the MediaTek sequence above, drain again, send `HCI_Reset` (reading ACL while waiting), then install the HC protocol.
- **Watchdog and recovery:** every command has a timeout. If the controller stops answering or sends a crash dump, do the MT7922 subsystem reset, then re-run Start(). Never let a USB port reset hit a hung controller; on Nov 1 that left it dead until mains power was removed.
- **Sending:** `SendCommand` is the class control transfer and `SendACLData` is a bulk OUT on `0x02`.
- **Events:** use `UsbAsyncInterruptTransfer` on `0x81`. EDK2's xHCI driver calls back at `TPL_NOTIFY`, so the callback only copies bytes into a ring buffer. Reassemble packets from the HCI header lengths, not from transfer boundaries, as btusb does.
- **Incoming ACL data:** `EFI_USB_IO_PROTOCOL` has no async bulk transfer; UsbBusDxe rejects async transfers on non-interrupt endpoints. Instead, poll `0x82` from the timer tick with a short `UsbBulkTransfer` timeout and a 512-byte buffer. Start polling as soon as the interface is opened, before any HCI command, and never stop: the controller can hold back events while ACL data waits (see [Controller wedge](#controller-wedge-nov-1)). Hand dumps on handle `0xFC6F` to recovery instead of the host stack. The MT7922 reports 32 LE ACL buffers of 251 bytes, so one LE ACL packet always fits in one bulk packet. EDK2's XhciDxe returns success for a transfer that completes while it is being aborted. AMI uses its own USB stack, so check this behaviour on the board.

### Binding 2: LeBus

LeBus consumes `EFI_BLUETOOTH_HC_PROTOCOL` and produces `EFI_BLUETOOTH_LE_CONFIG_PROTOCOL` plus the child handles.

- **Execution model:** there are no threads and no interrupts. TrouBLE is async, so a polling executor drives its futures:
  - In the apps, `embassy_futures::block_on` busy-polls them, and the transport tries the USB endpoints once per poll.
  - In the driver, one periodic timer event at `TPL_CALLBACK` (5–10 ms) polls the futures once per tick, and USB data arrives through async interrupt transfers.

  embassy-time runs on the TSC clock. The critical section is a no-op because nothing preempts the host.
- **Bonds:** they come from the bond variable as TrouBLE `BondInformation` entries (identity plus LTK). Nothing is written back except to RAM.
- **Connecting:** put the bonded identity addresses in the controller's filter accept list and run `LE Create Connection` with the accept-list policy, using the public address as our own address. The keyboard only advertises after a key press, so the first keystroke wakes it and is probably lost.
- **Encryption:** start encryption with the stored LTK through TrouBLE's security manager; there is no pairing. Still to check: whether it handles a legacy-pairing key (EDIV/Rand) from the central side. When the encryption change succeeds, create the child handle and call `ConnectController(child, NULL, NULL, TRUE)`, as UsbBusDxe does for hot-plugged devices.
- **Attribute protocol:** `SendRequest` takes raw ATT PDUs. Implement it as a shim onto TrouBLE's GATT client (read request, write request, write command) that builds the response PDU. `GetServiceInfo` returns the discovered database.

### Binding 3: HidKb

HidKb consumes `EFI_BLUETOOTH_ATTRIBUTE_PROTOCOL` and produces Simple Text Input (Ex).

1. Find HID service `0x1812` and its Protocol Mode (`0x2A4E`), Boot Keyboard Input (`0x2A22`, with CCCD `0x2902`) and Boot Keyboard Output (`0x2A32`) characteristics.
2. Write Protocol Mode = `0x00` (boot) and the boot input CCCD = `0x0001`.
3. Pass notifications to HidBootKbLib and push the results into a key FIFO. `SetState` writes the LED byte to `0x2A32`.
4. Install `SimpleTextIn`, `SimpleTextInEx` and the `gEfiConsoleInDeviceGuid` tag.

- **Hard-coded handles for the probe app:** BlueZ object paths for this keyboard name declaration handles, and the value handles are one higher. That gives Protocol Mode `0x0014`, Boot Input `0x004C` (CCCD `0x004D`) and Boot Output `0x004F`. BtKbProbe can use these to skip discovery; the driver should discover them.
- **Why install the tag:** in current EDK2, ConPlatformDxe only tags a text input handle whose device path is in the `ConIn` variable. Its short-form matching covers only USB class and WWID nodes, and ConSplitter binds only tagged handles. Without the tag, a new BLE handle would never reach ConIn. The alternative, adding the full path to `ConIn` in NVRAM, is persistent and fragile. AMI's console code may behave differently.

### Loading and connecting

- **Install from Linux:**

  ```sh
  sudo install -D BtKbDxe.efi /boot/EFI/BtKb/BtKbDxe.efi
  sudo zstd -d /usr/lib/firmware/mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin.zst \
       -o /boot/EFI/BtKb/BT_RAM_CODE_MT7922_1_1_hdr.bin
  sudo efibootmgr --driver --create --disk /dev/nvme0n1 --part 1 \
       --loader '\EFI\BtKb\BtKbDxe.efi' --label 'BT keyboard'
  ```

- **Self-connect:** the entry point installs the bindings, then calls `RegisterProtocolNotify` on `gEfiUsbIoProtocolGuid` and runs `ConnectController` on matching interfaces, both those that exist now and those that appear later. With fast boot, platforms connect only the ConIn devices, so nothing else would connect the Bluetooth interface.
- **Firmware blob:** read it from the driver's own volume (`LoadedImage->DeviceHandle`, `\EFI\BtKb\`) only when a section needs downloading. That keeps the blob out of the build and the repo. For the UEFITool route, add it as a raw FFS section instead.

### Handoff at ExitBootServices

- **Where to hook:** register on `EFI_EVENT_GROUP_BEFORE_EXIT_BOOT_SERVICES` (`gEfiEventBeforeExitBootServicesGuid`). Boot services still work there, so USB transfers are allowed; EDK2 signals the group once, before anything shuts down. The plain ExitBootServices event is the wrong place, for two reasons:
  - the spec forbids memory allocation there, directly or indirectly, and USB transfers allocate;
  - EDK2's xHCI driver halts the controller in its own callback for that event.
- **Steps:**
  1. Set Protocol Mode back to Report (`0x01`) and the boot input CCCD to 0.
  2. Send `HCI_Disconnect` with reason `0x15` (power off).
  3. Stop scanning and connecting.
  4. Send `HCI_Reset`.
  5. Send WMT FUNC_CTRL `0x00`, as Linux does at shutdown.
  6. Cancel the async interrupt transfer.

  Leave the firmware loaded.
- **If the firmware never signals the group:** nothing breaks. Linux re-runs MediaTek setup on every open (`HCI_QUIRK_NON_PERSISTENT_SETUP`) and sends `HCI_Reset` during init, which drops our link.

## Pairing

Pair in the OS and hand the driver the existing keys instead of building a pairing UI in firmware. The driver would read the classic link key or BLE LTK from an EFI variable written by the OS side. That is the same key-sharing problem bt-sync already solves for dual-boot, so EFI could become a third consumer of those keys.

### Bond variable

- **Staging:** the OS-side exporter (a bt-sync output) writes `BtKbBondsNew` with NV+BS+RT attributes. When the driver loads, it moves the contents into `BtKbBonds` (NV+BS only) and deletes the staging copy. This matters because efivarfs files on this machine are world-readable (`-rw-r--r--`), while a variable without the RT attribute is hidden from the OS. The LTK is then exposed only until the next boot.
- **Layout, version 1:**
  - Header: `{UINT32 Version; UINT32 Count; UINT8 ControllerAddr[6]}`.
  - Then one entry per bond: `{UINT8 PeerAddr[6]; UINT8 PeerAddrType; UINT8 Flags (SC, authenticated, IRK present); UINT8 EncKeySize; UINT8 Ltk[16]; UINT16 Ediv; UINT64 Rand; UINT8 Irk[16]}`.
  - The driver ignores all bonds if `ControllerAddr` doesn't match the controller's BD_ADDR.
- **Source on Linux:** `/var/lib/bluetooth/02:00:00:00:00:02/C0:00:00:00:00:01/info` (root only; I haven't read it). Use the `[LongTermKey]` group, which is the key BlueZ uses as central (Key, Authenticated, EncSize, EDiv, Rand), and `[IdentityResolvingKey]` if present. With Windows in BootOrder, export from whichever OS paired last; keeping those in sync is what bt-sync already does.

## Gotchas for using it in the setup UI

Getting the driver loaded before setup, and past Secure Boot, is as hard as the Bluetooth part.

| Issue | What happens | Workaround |
| --- | --- | --- |
| Loading order | Loaded as a `Driver####` entry (`bcfg driver add` in the UEFI shell, or `efibootmgr` driver options). BDS processes these before the boot manager and setup, but vendor firmware varies. | Disable "fast boot" modes, which may skip driver options. Have the driver connect the Bluetooth interface itself. |
| Entering setup | The F2/Del hotkey window often closes before the driver has connected the keyboard. | Use reboot-to-firmware (`systemctl reboot --firmware-setup`, OsIndications). |
| First keystroke | BLE keyboards advertise only after a key press, so the first key wakes the keyboard and is usually lost. | Press any key once before typing. |
| Console registration | ConSplitter ignores a text input device that lacks the `gEfiConsoleInDeviceGuid` tag. ConPlatform only adds the tag for devices listed in `ConIn`. | Install the tag in the driver. |
| Secure Boot | shim/MOK does not cover `Driver####` entries. | Sign with own Secure Boot keys enrolled in `db`. On myhost Secure Boot is currently off, in setup mode. |
| Vendor setup UIs | Some AMI/Insyde graphical setups read input in non-standard ways and may ignore a new ConIn device. | Test on the actual machine. |
| OS handoff | USB I/O is not allowed in the plain `ExitBootServices` event, and the xHCI driver halts the controller there. | Hand off in `BeforeExitBootServices`. Linux recovers even if that never fires. |
| Firmware flashing | Embedding the driver in the firmware image (UEFITool) avoids load-order issues. | Carries brick risk; keep a recovery path. |
| Controller wedge | A hung MT7922 that then got a USB port reset stayed dead through a reboot until mains power was removed (Nov 1). | Read the ACL pipe from the start, reset early, use timeouts and a watchdog, and do the subsystem reset before anything resets the port. |
| Cold start | After mains power loss the firmware upload takes about 20 s. | Don't block boot; the keyboard arrives late after power loss. |

## Build and test loop

- **Tools:** Rust via rustup with the `x86_64-unknown-uefi` target. QEMU 11.1.3 is built locally and OVMF comes from Arch's `edk2-ovmf` package (both under `tools/`). EDK2 `edk2-stable202608` is checked out for the UEFI shell and the C reference.
- **Build and test:** `scripts/build-rust.sh` runs the host tests and builds the apps. `scripts/qemu-smoke.sh <app>` runs an app in OVMF without the controller. `scripts/qemu-hw-probe.sh` and `scripts/qemu-hw-scan.sh` pass the real controller through.
- **QEMU with the real controller passed through:**

  ```sh
  cp /usr/share/edk2/x64/OVMF_VARS.4m.fd .
  qemu-system-x86_64 -machine q35 -m 2G \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.4m.fd \
    -drive format=raw,file=fat:rw:esp \
    -device qemu-xhci -device usb-host,vendorid=0x0e8d,productid=0x0616 \
    -serial stdio
  ```

  - **Lost keyboard:** QEMU detaches btusb while the VM runs, so the host loses Bluetooth and this keyboard. Keep a wired keyboard handy.
  - **Permissions:** QEMU needs access to the USB device node (root or a udev rule).
  - **Upload path:** the firmware will already be loaded. The subsystem reset should force a fresh upload; this is untested.
  - **Console path:** OVMF uses EDK2's ConPlatform and ConSplitter, which is the tagged case above. AMI setup still needs a test on the board.

## Milestones

1. **BtHciProbe.efi in QEMU:** find the interface, read chip ID `0x7922`, run the section queries (expect "already loaded"), turn FUNC_CTRL on, send `HCI_Reset` and print BD_ADDR. Done Nov 1 on the real controller through QEMU/OVMF:
   - Both sections were already loaded, so nothing was uploaded.
   - Version: HCI 5.4, LMP subversion `0x2606`, manufacturer `0x0046`.
   - BD_ADDR `02:00:00:00:00:02`, name "MTK MT7922 #1".
   - The whole run took 209 ms.
2. **bt-le-scan.efi:** bring the BLE host up and run an LE scan. Press a key and `C0:00:00:00:00:01` should show up. Done Nov 1 with TrouBLE on the real controller:
   - TrouBLE's own controller init worked through our USB transport.
   - A 30 s passive scan saw 1,444 reports from 43 devices.
   - The keyboard wasn't seen, because nobody pressed a key on it during the scan. That part is still to do.
   - The earlier milestone 1 run was the C probe; the Rust probe gave byte-identical traffic in 211 ms.
3. **BtKbProbe.efi:** connect, encrypt with the exported LTK, switch to boot protocol and print the reports. This checks the keys and the bulk-IN polling.
4. **BtKbDxe.efi in OVMF:** keys work in the shell and in OVMF's setup UI (UiApp). After the handoff, a Linux guest in the same VM still brings Bluetooth up.
5. **Real board:** add the `Driver####` entry, enter setup with `systemctl reboot --firmware-setup`, check that AMI setup reads the keyboard, and check that Linux and Windows still bring up Bluetooth afterwards.
6. **Cold path:** switch the PSU off, then time the full upload in the driver. For comparison, Linux took 20.5 s on Nov 1.

## Cheaper alternatives

If the goal is just a wireless keyboard that works in setup, hardware solves it with zero code.

- **HID proxy mode dongles.** Some Bluetooth chips (older CSR/Broadcom, as Macs used) enumerate as a plain USB HID keyboard until an OS driver switches them to HCI mode. Firmware sees a normal USB keyboard.
- **Keyboards with a 2.4 GHz USB receiver** (Logitech Bolt/Unifying and similar) work in firmware out of the box.

## Prior work

The design is proven in commercial firmware since 2014–2015, but no open-source UEFI implementation turned up. The open options are bare-metal Bluetooth stacks to port.

| Work | Kind | What it covers | Relevance |
| --- | --- | --- | --- |
| [AMI: Implementing A Bluetooth Stack on UEFI](https://uefi.org/sites/default/files/resources/2014_UEFI_Plugfest_AMI.pdf) (UEFI Plugfest, Oct 2014) | Talk on a closed implementation | USB BT driver, bus management (L2CAP, SDP, PIN, security), HID profile, BT keyboard/mouse drivers, EFI drivers producing Simple Text Input (Ex) and Simple Pointer, plus a setup UI for pairing. Classic HID, not BLE. | Same layering as our design |
| [AMI Aptio V Bluetooth keyboard support](https://www.ami.com/?p=9439) (2015) | Commercial firmware | Bluetooth keyboard and pointing device in BIOS setup, first shipped on the Intel Compute Stick | Proof it works in production firmware |
| [Apple Mac firmware](https://discuss.haiku-os.org/t/dual-boot-on-imac-8-1/13190) | Closed firmware | Magic Keyboard works in firmware after pairing in macOS once | Same "pair in OS, reuse keys" idea |
| UEFI protocols in EDK2 MdePkg: [BluetoothHc.h](https://qemu.googlesource.com/edk2/+/refs/heads/PreMemMeasurePPI/MdePkg/Include/Protocol/BluetoothHc.h), [BluetoothIo.h](https://qemu.googlesource.com/edk2/+/refs/heads/StructurePcd/MdePkg/Include/Protocol/BluetoothIo.h), [BluetoothConfig.h](https://git.radix-linux.su/Tianocore/edk2.git/plain/MdePkg/Include/Protocol/BluetoothConfig.h) | Open headers only (Intel, 2015) | Host Controller and IO protocols (UEFI 2.5), Configuration protocol (UEFI 2.7); `BluetoothLeConfig.h` and `BluetoothAttribute.h` cover BLE (UEFI 2.7) | Interfaces to implement against; no open implementation found |
| [Intel community: UEFI driver for AX200](https://community.intel.com/t5/Wireless/UEFI-Driver-for-AX200-Bluetooth-device/td-p/1233896) (2020) | Vendor answer | Intel has no UEFI Bluetooth driver; drivers target Windows and Linux only | Controller support must come from us |
| [BTstack](https://github.com/bluekitchen/btstack) | Open source, C | Runs without an RTOS, HCI over USB, libusb-intel port with Intel 8260/8265 firmware download (\~400 kB) | Classic and BLE; free for personal, non-commercial use only, commercial use needs a BlueKitchen licence |
| [NimBLE](https://github.com/apache/mynewt-nimble) | Open source, C (Apache-2.0) | BLE host with GAP, GATT and SMP; OS abstraction layer (NPL) with a `dummy` template; pluggable HCI transport | Ported first (C, builds freestanding in EDK2); kept as a fallback |
| [TrouBLE](https://github.com/embassy-rs/trouble) | Open source, Rust (Apache-2.0/MIT) | Async BLE host (`trouble-host` 0.8): central, scan, GATT client/server, L2CAP CoC, security manager incl. legacy pairing; `bt-hci` transports | Chosen host stack; runs on the MT7922 through our UsbIo transport |
| [uefi-rs](https://github.com/rust-osdev/uefi-rs) | Open source, Rust (MIT/Apache-2.0) | UEFI apps and drivers; `UsbIo` with control, interrupt and bulk transfers | Base for all our UEFI code |
| [bluetooth-nostd](https://awesome.ecosyste.ms/projects/github.com%2Fsuhteevah%2Fbluetooth-nostd) | Open source, Rust (Apache-2.0/MIT) | no\_std HCI, L2CAP, GATT, GAP, HID boot-protocol parsing, trait-based HCI-over-USB transport | Reference for a uefi-rs route; very new, no SMP or firmware loading mentioned |
| [Burble](https://www.lib.rs/crates/burble) | Open source, Rust | User-mode BLE stack talking to the controller over USB via libusb; lists Intel AX210/AX211 | Reference for USB and HCI layers |
| Linux `drivers/bluetooth/btmtk.c` | Open source, C (GPL-2.0) | MediaTek WMT protocol, firmware upload, subsystem reset, shutdown | Reference for the MT7922 sequence; reimplement from the description, don't copy GPL code |
| [US20170249160A1](https://patents.google.com/patent/US20170249160A1/en) | Patent | UEFI firmware doing automatic first-time Bluetooth pairing in pre-boot | Check before publishing anything beyond personal use |

## Effort estimate

A proof of concept is a few weekends; a robust driver is a much larger project.

- **Proof of concept:** the internal MT7922 (firmware usually already loaded), BLE only, pre-shared keys, boot protocol. A few weekends for someone comfortable with EDK2.
- **Robust driver:** cold-start firmware upload, reconnect handling and a clean OS handoff. Intel and Realtek controllers would each need their own entry in the vendor table.

## Open questions

- Does the keyboard advertise with its static address or with resolvable private addresses? If `[IdentityResolvingKey]` is present and it uses RPAs, load the IRK into the controller's resolving list.
- Does AMI setup accept a tagged Simple Text Input device that appears late?
- Does AMI's USB stack handle a timed-out bulk read the way EDK2's does?
- Does AMI's USB stack copy back only the received bytes of a short control transfer? The WMT event poll relies on it.
- Does the MT7922 subsystem reset clear the loaded firmware, so the upload path can be tested without cutting power? Does it recover a controller that has stopped answering HCI?
- Was the Nov 1 wedge really unread ACL data holding back events? A run with a live, busy link would tell, but it risks another mains power cycle.
- Why does each upload chunk take about 10 ms? If it's the chip's write time, the cold start can't get much faster than 20 s.
- Does AMI 4.43 signal `BeforeExitBootServices`? A 2026 build probably implements UEFI 2.8 or later, but I haven't verified it.

Possible next steps:

- [x] Sketch the EDK2 module layout
- [x] Identify the machine's BT chip and whether it needs a firmware upload
- [x] Milestone 1: MT7922 bring-up probe, in `~/Projects/bt-uefi-keyboard`. It is tested against a simulated MT7922 and has run on the real controller through QEMU/OVMF (EDK2's USB stack), first in C, then in Rust (`bt-hci-probe.efi`).
- [x] Switch to Rust (uefi-rs + TrouBLE)
- [ ] Milestone 2: `bt-le-scan.efi` scanning works; still to do: see the keyboard advertise (press a key during the scan). The first attempt wedged the controller (see [Controller wedge](#controller-wedge-nov-1)); the apps and scripts are hardened.
- [ ] Run `BtHciProbe.efi` from a UEFI shell on the board itself, to test AMI's USB stack
- [ ] OS-side bond exporter for the bond variable (bt-sync)
