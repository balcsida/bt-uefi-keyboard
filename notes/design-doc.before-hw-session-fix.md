# Bluetooth Keyboard in UEFI Setup

Nov 1, 2026 · @Dávid Balatoni

## Short answer

Yes, a custom EFI driver can make a Bluetooth keyboard usable in firmware setup, but it is a big project. The UEFI spec already defines Bluetooth protocols (Bluetooth Host Controller, Bluetooth IO and config protocols, plus BLE since UEFI 2.7). Almost no consumer firmware ships a Bluetooth stack, so most of it would be written or ported by us.

The implementation is in Rust (`uefi` crate plus the TrouBLE BLE host), chosen on Nov 1 so the code that parses untrusted radio input in pre-boot firmware is memory-safe.

**Status (Nov 2):** it works in OVMF (EDK2 firmware in QEMU) with this PC's real controller and keyboard. Loaded at boot, the driver let an F2 on the Bluetooth keyboard open the boot menu, drove the setup screens, and handed the controller back on reset and at OS start.

On the real board's AMI firmware (milestone 5), the keyboard typed in a UEFI shell. The firmware now loads the driver at every boot, and the driver hands the controller back when Linux starts. The Bluetooth keyboard gets into AMI setup with Del and works there. The 4–6 s stalls of the first setup session were a gap in the host stack (Encryption Change v2). The fix was confirmed on the board the same evening: one connection for the whole session, no stalls. Two warm reboots after that failed: the board had AMI's Fast Boot on, and a fast boot skips driver entries, so the driver never started. With Fast Boot off, the driver runs in warm reboots too (Nov 2, 23:15).

On this machine the internal MediaTek MT7922 is a good first target, so the proof of concept doesn't need a separate dongle. Its firmware upload is just chunked vendor commands over USB endpoint 0, and the chip keeps its firmware through power-off. The keyboard supports HOGP boot protocol, so the HID layer can reuse UsbKbDxe's 8-byte report handling.

## Target machine

Measured on myhost on Nov 1, 2026.

| Item | Value |
| --- | --- |
| Board and firmware | ASRock A620I Lightning WiFi, AMI BIOS 4.43 (2026-06-24) |
| Secure Boot | Off, setup mode (no PK). An unsigned `Driver####` loads for now. |
| Controller | MediaTek MT7922, USB `0e8d:0616` on port 1-10, public address `02:00:00:00:00:02`. Reports Bluetooth 5.3 (HCI revision `0x2414`, LMP subversion `0x2607`) with the current linux-firmware build; the older build it ran until Nov 1 reported 5.4 (`0x1620`, `0x2606`). |
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

### Scan panic (Nov 1, second attempt)

With the fixes above, the probe ran cleanly. Nothing was left queued at either drain, as expected after BlueZ's power-off. The 60 s scan ended after about 30 s:

- **The panic:** TrouBLE `unwrap!`ped an event with code `0x05` (Disconnection Complete) of the wrong size and panicked.
- **Likely cause (not proven):** the apps read the event endpoint with 1 ms synchronous transfers that time out and get cancelled thousands of times a second. QEMU's USB passthrough drops a packet that arrives while its transfer is being cancelled. Losing the first 16-byte piece of a multi-packet advertising report makes the next piece look like a new event with a random code and length.
- **Shutdown:** uefi-rs's panic handler waits 10 s and then shuts the machine down (ResetSystem). So the hand-off never ran, and the controller was left on and scanning.
- **Linux's recovery:** Linux's first setup found the firmware still loaded, but vendor command `0xfd98` timed out. Linux then ran its MediaTek reset (subsystem reset plus a USB reset), which drops the firmware, and re-uploaded it in 20.4 s. No wedge this time: the chip still answered on USB.
- **Changes made:**
  - Events now arrive through an asynchronous interrupt transfer (16-byte packets into a lock-free ring), so nothing is cancelled.
  - Every event is checked with bt-hci's parsers (the ones TrouBLE `unwrap!`s) and dropped if malformed.
  - Our own panic handler cancels the transfer, hands the controller back and returns to the shell.
  - The scan uses the controller's duplicate filtering, which keeps the event rate low.

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
- **Events:** use `UsbAsyncInterruptTransfer` on `0x81`, never short synchronous reads that time out and get cancelled; QEMU drops data in that race. EDK2's xHCI driver calls back at `TPL_NOTIFY`, so the callback only copies bytes into a ring buffer. Reassemble events from the HCI header lengths, not from transfer boundaries, as btusb does.
  - **Packet size:** ask for one max-size packet (16 bytes) per transfer, as btusb does. A larger transfer can hold back an event whose length is a multiple of 16 until the next event arrives.
  - **Throughput:** EDK2 re-queues the transfer on its timer tick, so throughput is one packet per tick: about 100 packets/s with a 10 ms tick. That is plenty for a connected keyboard, but not for unfiltered scanning, so scan with duplicate filtering.
  - **Unloading:** cancel the transfer before the driver unloads, or the USB stack calls into freed memory.
- **Incoming ACL data:** `EFI_USB_IO_PROTOCOL` has no async bulk transfer; UsbBusDxe rejects async transfers on non-interrupt endpoints. Instead, poll `0x82` from the timer tick with a short `UsbBulkTransfer` timeout and a 512-byte buffer. Start polling as soon as the interface is opened, before any HCI command, and never stop: the controller can hold back events while ACL data waits (see [Controller wedge](#controller-wedge-nov-1)). Hand dumps on handle `0xFC6F` to recovery instead of the host stack. The MT7922 reports 32 LE ACL buffers of 251 bytes, so one LE ACL packet always fits in one bulk packet. EDK2's XhciDxe returns success for a transfer that completes while it is being aborted. AMI uses its own USB stack, so check this behaviour on the board.

### Binding 2: LeBus

LeBus consumes `EFI_BLUETOOTH_HC_PROTOCOL` and produces `EFI_BLUETOOTH_LE_CONFIG_PROTOCOL` plus the child handles.

- **Execution model:** there are no threads and no interrupts. TrouBLE is async, so a polling executor drives its futures:
  - In the apps, `embassy_futures::block_on` busy-polls them, and the transport tries the USB endpoints once per poll.
  - In the driver, one periodic timer event at `TPL_CALLBACK` (5–10 ms) polls the futures once per tick, and USB data arrives through async interrupt transfers.

  embassy-time runs on the TSC clock. The critical section is a no-op because nothing preempts the host.
- **Robustness:** TrouBLE `unwrap!`s typed HCI events, and a panic in firmware is fatal: uefi-rs's handler shuts the machine down. So:
  - Validate every event with bt-hci's parsers before the stack sees it.
  - Install our own panic handler, which stops the USB transfers, hands the controller back and disables the driver.
  - Put a watchdog on stack setup.
- **Bonds:** they come from the bond variable as TrouBLE `BondInformation` entries (identity plus LTK). Nothing is written back except to RAM.
- **Connecting:** put the bonded identity addresses in the controller's filter accept list and run `LE Create Connection` with the accept-list policy, using the public address as our own address.
  - **Address:** the keyboard advertises with its identity address, so no resolving list is needed.
  - **Waking it:** it only advertises after a key press, first with directed advertising to this PC, then undirected. So the first keystroke wakes it and is probably lost.
- **Encryption:** start encryption with the stored LTK through TrouBLE's security manager; there is no pairing. TrouBLE's `legacy-pairing` feature handles this keyboard's legacy key with EDIV/Rand; this worked on Nov 1.
- **Reconnecting:** the keyboard disconnects by itself after about a minute without traffic, so the driver must reconnect on its next key press: accept list, encrypt, resubscribe. When the encryption change succeeds, create the child handle and call `ConnectController(child, NULL, NULL, TRUE)`, as UsbBusDxe does for hot-plugged devices.
- **Attribute protocol:** `SendRequest` takes raw ATT PDUs. Implement it as a shim onto TrouBLE's GATT client (read request, write request, write command) that builds the response PDU. `GetServiceInfo` returns the discovered database.

### Binding 3: HidKb

HidKb consumes `EFI_BLUETOOTH_ATTRIBUTE_PROTOCOL` and produces Simple Text Input (Ex).

1. Use **report protocol**: this keyboard accepts boot protocol but sends nothing in it (milestone 3).
   - **Layout:** parse the Report Map (`0x2A4B`) for the keyboard input report's layout (`uefi-bt/src/hid.rs`).
   - **Keys:** find its Report characteristic (`0x2A4D`) through the Report Reference descriptors.
   - **LEDs:** use the matching output report.
   - **CCCDs:** turn notifications on only if they are off, and leave them as found: the keyboard stores them per bonded host, and Linux relies on them.
2. Keep Protocol Mode at report (`0x01`, the default after connecting).
3. Decode notifications with the parsed layout, map the usages to EFI keys (as UsbKbDxe does), and push the results into a key FIFO. `SetState` writes the LED byte to the keyboard's output report.
   - **Key-ups:** never drop a notification. A lost key-up means a stuck, auto-repeating key, so size the stack's queues for bursts.
   - **Layout:** usages are key positions. Setup UIs assume a US layout, so on this Hungarian keyboard the accented keys arrive as US punctuation. That is the same as a USB keyboard in firmware.
4. Install `SimpleTextIn`, `SimpleTextInEx` and the `gEfiConsoleInDeviceGuid` tag.

- **Handles on this keyboard** (confirmed by discovery on Nov 1): Protocol Mode `0x0014`, keyboard input report `0x001A` (CCCD `0x001B`), LED output report `0x0032`, Report Map `0x004A`, Boot Input `0x004C` (CCCD `0x004D`). The driver should discover them rather than hard-code them.
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

## The driver as built (bt-kb-dxe, Nov 1)

`rust/bt-kb-dxe` is the first resident version. It's a single UEFI boot service driver (PE subsystem 11, about 415 KB), simpler than the three-binding plan above.

- **Binding:** one driver binding for MediaTek E0/01/01 interfaces, plus ComponentName2, so `drivers` in the shell shows "Bluetooth LE keyboard (MediaTek MT7922)".
  - **Start():** drains the controller and checks that both firmware sections are loaded. It **never uploads**: after a power cut it gives up until the OS has used Bluetooth once. Then Bluetooth on, HCI_Reset, and a check that the controller's address matches the bond. That takes about 0.3 s.
  - **Self-connect:** the entry point connects interfaces that already exist. A UsbIo protocol notify connects later ones the moment the USB bus driver installs them. EDK2's UsbBusDxe only connects drivers to the devices the boot manager asks for (keyboards, the boot disk), so without the notify the Bluetooth interface would wait for a later ConnectAll, if one comes at all.
  - **One copy:** the running copy tags its image handle; a second load returns `EFI_ALREADY_STARTED` and unloads itself.
- **Execution:** one timer at TPL_CALLBACK, re-armed after each tick (about every 10 ms). Each tick:
  - drains the async event ring;
  - does one 1 ms bulk read for ACL data (every 100 ms while no keyboard is connected);
  - polls the TrouBLE future until the inbox is empty;
  - repeats held keys.
- **Keys** come straight off the HCI link, not through TrouBLE:
  - The tick watches LE Connection Complete, Encryption Change and Disconnection Complete for the bonded address.
  - It decodes ATT notifications on the keyboard's input report handle once the link is encrypted.
  - Notifications that arrive before encryption is seen, or before the first discovery finished, are stashed and replayed. So the wake key and keys typed during connection setup aren't lost.
- **TrouBLE's part:** connection (accept list), encryption with the stored key, one-time GATT discovery (Report Map, input report, LED output report, all cached as handles), the notification switch only if it's off, LED writes, and parameter requests.
- **Diagnostics in the log** (Nov 2), for the hotkey runs:
  - connection attempts that end without a connection, with their status;
  - "still waiting for the keyboard" at 5, 10, 20 and 40 s, until the first connection;
  - the key notifications the firmware registers on the device (OVMF: F2, Esc and Enter, the boot hotkeys and the continue key);
  - every F-key, Esc and Delete delivered, with how many key notify functions ran (typing is never logged);
  - the first reports on handles other than the keyboard report, with their bytes. If F2 on this keyboard sends a media function, it shows up there.
- **Remembered layout** (added Nov 2): after the first discovery, the handles and the decoded report layout go into the NV variable `BtKbGatt` (30 bytes, versioned, every field range-checked when read back). It is written only when it changes.
  - At the next start the driver decodes keys as soon as the link is encrypted, instead of waiting for the 2–3.5 s discovery.
  - Once per start it reads the input report's Report Reference descriptor to confirm the record. On a mismatch it forgets the record and discovers again.
  - The log line "first key report decoded N ms after the keyboard connected" measures the effect.
- **Console:** Simple Text Input and Simple Text Input Ex with UsbKbDxe's semantics, on a child handle (USB interface path + BluetoothLE node), tagged ConsoleInDevice:
  - a 32-key FIFO;
  - partial keys only when exposed;
  - Ctrl+letter conversion;
  - repeat after 500 ms, then every 20 ms;
  - key notify callbacks;
  - SetState syncing the lock keys, with LED writes.
- **Leaving:** the hand-off (HCI_Disconnect to the keyboard, HCI_Reset, function off; the subsystem reset if the controller doesn't answer) runs at BeforeExitBootServices, at a reset (reset notification), and on fatal errors such as a firmware crash dump.
- **Logging:** never to the console. Lines go to a RAM ring, flushed to the volatile variable `BtKbLog` (vendor `5223227b-ac96-454e-9bca-f15199748a3c`). Under a hypervisor only, they also go to QEMU's debug console at port 0x402.
- **Boot record** (Nov 2): a one-line summary of the boot in the NV variable `BtKbLastBoot`, because the volatile log dies with any reset. It holds when the driver loaded, bring-up, connections, first keys, the encryption event version, disconnects, hotkey-like keys with counts, 15 s healthy, failures, and the OS start. The next boot logs it as "previous boot: …", with a note if that boot never reached an OS.
  - **Write budget:** milestones at most every 2 s; counts alone wait for heartbeats at 30, 60, 120 s, …; at most 40 writes per boot, plus the OS start. A normal boot without a key press writes once.
  - **Never in the reset notification**, as with the log (OVMF's power-off failed with writes there). A setup session ending in Save & Exit therefore keeps its record as of the last milestone or heartbeat.
- **Links left from before** (Nov 2): the controller keeps LE links across host resets (on Nov 1 a keyboard link outlived Linux handing the controller to QEMU). Bring-up sends HCI_Disconnect (reason 0x15) before its HCI_Reset, for the handle of any ACL data still queued and for 0x0200, the handle this controller gives the first LE link (Linux too: `/sys/class/bluetooth/hci0:512`). A reset alone would end such a link silently, and the keyboard would wait out its supervision timeout before advertising again. Cost when there is no such link: one Command Status ("Unknown Connection Identifier").
- **Panics:** the message is stored in the NV variable `BtKbPanic`, the controller is handed back, a one-line notice appears on screen, and the machine resets.
- **Boot-loop guard:** the NV counter `BtKbBoots` counts driver starts. It is cleared at OS hand-off or after 15 s of trouble-free running (written only if it isn't zero already). At 3, the driver doesn't load, so the machine always boots.
- **Files next to the driver:** the firmware image (for the section check) and a `*.bond` file. Optional: `bt-kb-dxe.selftest` (offline self-test) and `bt-kb-dxe.timelimit` (test sessions power off after N seconds).

### Offline tests (`scripts/qemu-driver-test.sh`)

All of these run in OVMF without the controller:

1. **Self-test:** the driver types `echo SELFTEST: typed by bt-kb-dxe, Shift+1 gives !` and `reset -s` into the shell through its own keymap → FIFO → Simple Text Input → ConSplitter path. The shell runs both.
2. **Normal load without the device:** the binding installs and the shell keeps working. A second `load` unloads itself again.
3. **Deliberate panic:** the notice is shown, the message is found in the NV store, and the machine resets.
4. **`ebs-test.efi`:** calls ExitBootServices; the driver's "an OS is starting" handler runs before the power-off.
5. **Hotkey at boot** (Nov 2): the driver is loaded from a Driver#### option (added with `bcfg driver add` in a first boot). The self-test presses F2 during OVMF's boot countdown (`-boot menu=on,splash-time=8000`), and the boot manager's hotkey opens the boot menu.
   - This shows the boot manager's hotkey service registers on our Simple Text Input Ex as it appears (a protocol notify) and that our key notify callbacks fire.
   - The self-test then picks the ESP's shell with `{down}{enter}`.
6. **Loaded at boot, no controller:** the driver loads from Driver####, its USB notify sees the emulated USB keyboard arrive, the boot goes on to the shell, and the OS hand-off runs.
7. **The board's diagnostics boot** (Nov 2), on a GPT disk so device paths end in `HD(1,GPT,…)` as on the board.
   - An outer shell starts the one in `\EFI\btkb\` (on the board, BootNext does). Its `startup.nsh` saves the diagnostics and loads the driver (`Success`, and resident afterwards).
   - `linux` is typed over QMP into the emulated keyboard. The driver entry becomes `PciRoot(0x0)/Pci(0x2,0x0)/HD(1,GPT,…)/\EFI\btkb\bt-kb-dxe.efi`.
   - The system's Limine 12.9.6, started from the shell, chainloads `ebs-test.efi` in place of Linux, and the driver's hand-off runs.
   - This case found the subdirectory bug.

An earlier manual check (Nov 2) loaded the self-test driver from the shell, typed `exit`, and pressed Enter in the boot menu. OVMF's setup front page (UiApp) appeared, driven by keys from our driver.

Tally: 14 runs of the four-case suite (56 boots) plus 21 runs of the panic case alone.
- **Confirmed failure:** one panic run hung after the message was stored and the notice shown; the reset never happened.
- **Unexplained timeout:** one early suite run timed out with its output lost, so it may be the same thing.
- **Everything else** passed.

The panic hang's cause is unknown; it may be the same OVMF behavior as with variable writes during a reset. The boot-loop counter covers this on real hardware: a machine that hangs here gets power-cycled, and after 3 such boots the driver stays off. The six-case suite (Nov 2) passed on its first run.

**Panic hang located (Nov 2, suite run 10):** it happened again in case 3. The driver logged "calling ResetSystem (cold) at TPL CALLBACK" 5 s after the notice, and nothing followed. In self-test mode the driver registers no reset notification, so after that call no code of ours runs. The hang is inside OVMF's ResetSystem or in QEMU, whose cold reset is a write to port 0xCF9 with the keyboard-controller reset as fallback. Offline only; nothing to change in the driver.

### Test-environment findings

- **Flaky emulated SATA disk:** with QEMU's emulated SATA disk, `fat:rw:` or a real image alike, OVMF now and then hung at its first screen output or timed out reading files, with or without our code. The ESP is now a FAT32 image on virtio-blk; no such failure since.
- **Debug port:** an isa-debugcon at port 0xE9 looked like the cause at first. That was probably the same disk flakiness, but the driver now uses 0x402.
- **Writes during reset:** two variable writes inside the reset notification made OVMF's power-off fail in about half the runs: the callback returned, then nothing happened. With no writes there, 8 of 8 runs passed. Hence the 15 s rule for clearing the boot counter.
- **Live display** (found in the first hardware session): the shell echoes each key as a cursor-positioning sequence with no newline. The old line-based output filter (`sed`) therefore showed typing only after Enter, and its escape stripping turned Backspace into a space. `scripts/live-filter.py` now passes bytes through as they arrive and drops only OVMF's terminal-resize request, so setup screens render too.
- **Buffered host keys:** keys typed in the host terminal before QEMU starts reach the guest's serial console. An F2 there would open the boot menu and fake a hotkey result, so the script flushes the terminal's input first.
- **Window** (Nov 2): the boot countdown, logo and boot menu exist only on the graphical screen, which `-nographic` hides. QEMU was rebuilt with GTK. The interactive hardware scripts now open a window by default (`WINDOW=1`), and the terminal shows the driver's log as it is written.
  - **Keys from the Bluetooth keyboard only:** the window's machine has no PS/2 controller (`i8042=off`), and the serial console only writes the log. A USB tablet keeps a click in the window from grabbing the mouse.
  - **No abrupt ends:** no menu bar (its Quit and Reset would bypass the driver's hand-off) and no working close button (`window-close=off`). QEMU runs in its own session, and Ctrl+C in the terminal only prints a reminder.
  - **Checked offline:** screenshots over QMP show the logo with the countdown bar, then the boot menu, then setup; the GTK window itself ran in a headless KWin.

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
| First keystroke | BLE keyboards advertise only after a key press, so the first key wakes the keyboard. It isn't lost: this keyboard sends it once the link is encrypted, and the driver replays what arrived during setup. In the first session the wake keys `mj` reached the shell about 2.4 s late. | Wake it with Shift to avoid typing anything. The remembered layout should cut the delay to about 0.5 s. |
| Host stack and Encryption Change v2 | TrouBLE 0.8 unmasks Encryption Change v2 but handles only v1. With a v2 report, it never registers the encryption: the session timed out every 10 s and dropped a working link (Nov 2, board). | The driver rewrites v2 into v1 before TrouBLE sees it, and also trusts the controller's own report. |
| AMI Fast Boot | A fast boot boots the last boot option directly and skips Driver#### entries, so the driver never runs and the Bluetooth keyboard is dead until the OS (Nov 2, 22:52). This board had Fast Boot on before the project. | Disable Fast Boot in setup. It saves little here: Limine then takes about 3 s longer to connect devices. |
| Driver#### path | This AMI firmware ignores a driver entry with efibootmgr's default short path (`HD(…)/\EFI\…`), although it boots Boot#### entries in that form. | Use a full device path: the UEFI shell's `bcfg driver add` (`scripts/board-diag.sh`) or `efibootmgr --full-dev-path` (`scripts/board-install.sh`). |
| Keyboard layout | Firmware maps keys by US position, as the firmware's own USB keyboard driver does. On this Hungarian keyboard `-` gives `/`, and Y and Z swap. | Kept on purpose: a setup password must come out the same as from a wired keyboard. |
| Console registration | ConSplitter ignores a text input device that lacks the `gEfiConsoleInDeviceGuid` tag. ConPlatform only adds the tag for devices listed in `ConIn`. | Install the tag in the driver. |
| Secure Boot | shim/MOK does not cover `Driver####` entries. | Sign with own Secure Boot keys enrolled in `db`. On myhost Secure Boot is currently off, in setup mode. |
| Vendor setup UIs | Some AMI/Insyde graphical setups read input in non-standard ways and may ignore a new ConIn device. | Test on the actual machine. |
| OS handoff | USB I/O is not allowed in the plain `ExitBootServices` event, and the xHCI driver halts the controller there. | Hand off in `BeforeExitBootServices`. Linux recovers even if that never fires. |
| Firmware flashing | Embedding the driver in the firmware image (UEFITool) avoids load-order issues. | Carries brick risk; keep a recovery path. |
| Controller wedge | A hung MT7922 that then got a USB port reset stayed dead through a reboot until mains power was removed (Nov 1). | Read the ACL pipe from the start, reset early, use timeouts and a watchdog, and do the subsystem reset before anything resets the port. |
| Cold start | After mains power loss the firmware upload takes about 20 s. | Don't block boot; the keyboard arrives late after power loss. |

## Build and test loop

- **Tools:** Rust via rustup with the `x86_64-unknown-uefi` target. QEMU 11.1.3 is built locally (with libusb for passthrough and, since Nov 2, GTK for a window) and OVMF comes from Arch's `edk2-ovmf` package (both under `tools/`). EDK2 `edk2-stable202608` is checked out for the UEFI shell and the C reference.
- **Repository privacy (Nov 3):** the git history was rewritten so that hardware identifiers are placeholders: the keyboard's address is `C0:00:00:00:00:01`, the controller's `02:00:00:00:00:02`, and the host name `myhost`. This document keeps the real values.
  - **`private/`** in the repo (git-ignored) holds `scrub-map.tsv` (real value → placeholder, with disk, partition and network IDs added for the future), `local.env` (the keyboard address for `export-bond.sh`), and a bundle of the history from before the rewrite.
  - **`scripts/scrub.py`:** pre-commit and commit-msg hooks refuse real values. Snapshots of this document go into `notes/` through `scripts/scrub.py apply`. `check --history` covers everything a push would publish.
  - **Tools:** `bt-kb-probe` and `bt-le-scan` now take the keyboard from the bond file next to them.
  - **Publishing (Nov 3):** the GitHub repository with the old history was renamed to `bt-uefi-keyboard-old`, to be deleted. A fresh private `bt-uefi-keyboard` got the scrubbed history (44 signed commits). A force-push wouldn't have been enough, because GitHub keeps force-pushed commits reachable, for example through the repository's activity view.
- **License (Nov 3):** MIT OR Apache-2.0, the Rust ecosystem's usual dual license, which most of the crates the driver uses have too. It was BSD-2-Clause-Patent before, EDK2's license, taken when the project started as an EDK2 package. Code upstreamed to EDK2 would need that license again; the author can grant it.
  - **Exception:** `BtKbPkg/Library/NimbleLib/Port/include/syscfg/syscfg.h` is a modified copy of NimBLE's and stays Apache-2.0 only. The EDK2 and NimBLE submodules keep their own licenses.
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
   - The earlier milestone 1 run was the C probe; the Rust probe gave byte-identical traffic in 211 ms.
   - **Keyboard seen** in the third scan (Nov 1, 20:22), after the [wedge](#controller-wedge-nov-1) and [panic](#scan-panic-nov-1-second-attempt) fixes:
     - On key presses it sent directed advertising (ADV_DIRECT_IND) to this PC at about −47 dBm.
     - It also sent undirected ADV_IND carrying the HID service UUID and appearance `0x03C1` (keyboard).
     - The 60 s passive scan with duplicate filtering got 99 reports from 49 devices.
     - The async event pipe carried 260 packets, with at most 163 bytes buffered, no overflows and no errors.
     - No malformed events, a clean hand-off, and Linux's setup afterwards took 181 ms.
3. **bt-kb-probe.efi:** connect, encrypt with the exported LTK, switch to boot protocol and print the reports. This checks the keys and the bulk-IN polling.
   - **Bond import:** TrouBLE 0.8 imports bonds with `add_bond_information`.
   - **Encryption:** as central it encrypts from a stored bond with `LE Enable Encryption`; legacy keys (EDIV/Rand) need its `legacy-pairing` feature.
   - **Keys:** `scripts/export-bond.sh` (run with sudo) copies the BlueZ bond into a user-only file under `qemu/keys/` and prints only the key type.
   - **This keyboard's key** (exported Nov 1): legacy pairing, authenticated, 16 bytes, with EDIV and Rand set, plus an IRK. So TrouBLE needs `legacy-pairing`, and the bond variable must carry EDIV and Rand (its layout already does). The IRK isn't needed because the keyboard advertises with its identity address.
   - **The app:** `bt-kb-probe.efi` imports the bond and connects through the controller's accept list. It encrypts with `LE Enable Encryption`, switches the keyboard to boot protocol and prints the 8-byte reports.
     - **Restore:** at the end it turns notifications off and puts the keyboard back into report protocol before disconnecting.
     - **Address check:** it refuses to run if the controller's address doesn't match the bond.
     - **Display:** reports are decoded with a US layout; on a QWERTZ keyboard Y and Z show swapped.
   - **First hardware runs** (Nov 1, 20:36 and 20:4x):
     - **What worked:** connecting and **encrypting with the exported legacy key** (`EncryptedAuthenticated`), and GATT discovery. Handles match BlueZ's: Protocol Mode `0x0014`, Boot Keyboard Input `0x004C` with CCCD `0x004D`.
     - **Report mode:** the wake key arrived as an 11-byte report-mode notification on `0x001A` (`00 06 00 …`: no modifiers, key `0x06`). That's because the keyboard keeps Linux's notification settings per bonded host.
     - **Boot mode:** the keyboard accepted the switch (Protocol Mode read back `0`) and the boot CCCD write, but no boot report arrived.
     - **Other traffic:** a battery level notification (`0x0010` = 57%), and a connection parameter request (25–45 ms, latency 4, timeout 2 s), accepted, giving 35 ms.
     - **Idle disconnect:** about 60 s later the keyboard disconnected on its own ("remote user terminated").
   - **Done Nov 1, in report protocol** (run at 20:5x with report and boot protocol back to back): the keyboard typed into the UEFI app through our stack, decrypted with the key exported from Linux. 87 reports were decoded, among them "hello uefi".
     - **Report Map:** 325 bytes. The keyboard input is report ID 1, 11 bytes: modifier bits, then 10 key slots, on `0x001A`. The LED output report (also ID 1) is at `0x0032`.
     - **Other input reports:** IDs 16, 39, 44, 45, 46 and 47.
     - **Boot protocol:** accepted but silent. Protocol Mode read back `0` and the boot CCCD write succeeded, but during a 25 s typing phase nothing arrived on any handle. **The driver uses report protocol.**
     - **TrouBLE's defaults are too small:** a 1-slot GATT notification queue dropped the second of two reports 1–2 ms apart (key-ups, a two-key rollover). In a driver that means stuck keys. Its 16-buffer packet pool also ran out (`OutOfMemory`) while keys were typed during connection setup. Now set to 32 notification slots, 64 buffers and a 32-slot L2CAP receive queue. Confirmed on hardware (Nov 1, fast rolling typing): 82 of 82 notifications reached the decoder, 15 of them with two or three keys held, and no `OutOfMemory`.
     - **Settings left as found:** the keyboard stores CCCDs per bonded host, and Linux's report notifications were already on. The probe leaves them as found.
4. **bt-kb-dxe.efi in OVMF:** keys work in the shell and in OVMF's setup UI (UiApp). After the handoff, a Linux guest in the same VM still brings Bluetooth up.
   - **Shell: done Nov 1, 23:35** (`LIVE=1 scripts/qemu-hw-driver.sh`). The driver, loaded from the shell, turned the Bluetooth keyboard into a console keyboard. `echo hello` typed on it ran in the shell, and `ebs-test.efi` ended the session through the OS hand-off. From the driver's log:
     - **Bring-up:** both firmware sections already loaded; controller ready in 211 ms.
     - **Connection:** the keyboard connected 0.28 s after the driver started waiting, and encryption took another 0.16 s.
     - **Discovery:** finished 2.2 s after encryption. TrouBLE discarded two early notifications ("unexpected PDU during MTU exchange"), but the driver's own tap had them.
     - **Wake keys:** three reports that arrived during setup were replayed: the wake keys `mj` ended up in front of the first `echo`.
     - **Hand-off:** the boot-loop counter cleared after 15 s. At ExitBootServices, 42 s in, the disconnect and hand-off took 0.1 s, after 76 key reports. Linux's setup afterwards took 173 ms (no re-upload).
   - **Loaded at boot: first run Nov 2** (`scripts/qemu-hw-boot.sh`, then in the terminal). OVMF's boot manager loaded the driver from a Driver#### option.
     - **Start:** the USB notify connected the driver to the controller 0.34 s after it loaded, and the controller was ready at 0.55 s, before the boot countdown began.
     - **Hotkey: not tested.** The keyboard first connected 24.3 s after the driver started, long after the 12 s countdown. The shell had started by then, and the first keys the driver got were typed in it. In the terminal, the countdown was invisible: OVMF draws it only on the graphical screen, so there was no cue for when to press F2.
     - **Layout:** discovery took 2.4 s again, and the layout was stored in `BtKbGatt`. The next run starts with it.
     - **Reset hand-off: works on hardware.** `reset` typed in the shell ran the driver's reset notification: keyboard disconnected and controller handed back in 0.11 s, after 99 key reports. QEMU then exited (`-no-reboot`), and Linux's setup took 180 ms (no re-upload).
   - **Hotkey, setup and Reset: done Nov 2** (`scripts/qemu-hw-boot.sh`, second run, now with the window and a 20 s countdown). Milestone 4 is complete.
     - **Start:** the controller was ready 0.65 s after the driver loaded (bring-up 214 ms), with the layout remembered from the first run. The boot manager registered F2, Esc and Enter on the device.
     - **Hotkey:** the keyboard connected 4.9 s after the driver started, woken by an F2 press, and the link was encrypted 0.16 s later. The first key report was decoded 180 ms after the connection (2.4 s without the remembered layout), and it was F2: the boot manager's key notify ran and the boot menu opened. Most likely the press that woke the keyboard was itself the hotkey.
     - **Remembered layout:** confirmed against the keyboard 0.25 s after the connection.
     - **F-keys:** F2 arrives as the keyboard page's F2. The only other report was the battery level (handle `0x0010`, `0x39` = 57 %).
     - **Setup and Reset:** setup was driven with the Bluetooth keyboard. "Reset" on its front page ran the reset hand-off (0.11 s, after 29 key reports), and Linux's setup afterwards took 181 ms.
5. **Real board:** add the `Driver####` entry, enter setup with `systemctl reboot --firmware-setup`, check that AMI setup reads the keyboard, and check that Linux and Windows still bring up Bluetooth afterwards.
   - **Install:** `sudo scripts/board-install.sh` copies the driver, the firmware image (from linux-firmware) and the bond to `\EFI\btkb\` on the ESP, then adds a Driver#### entry with efibootmgr. `--remove` undoes both.
   - **Read back:** `scripts/board-log.sh` (no sudo needed) after booting Linux prints the driver's log of that boot (`BtKbLog` is volatile but readable until the next reset), its variables, and Linux's controller setup time.
   - **Order:** first a normal boot into Linux (bring-up on AMI's USB stack, hand-off at ExitBootServices), then setup via `systemctl reboot --firmware-setup`, left through Boot Override into Linux so the log survives. Then the hotkey, with a longer Setup Prompt Timeout, and one Windows boot.
   - **Checked:** `/boot` is root-only (`fmask=0077`), efibootmgr 18 supports Driver#### (`-r`), no Driver#### entries exist yet, and `OsIndicationsSupported` has BOOT_TO_FW_UI.
   - **First boot with the driver installed (Nov 2, 19:51): the firmware didn't start it.** No `BtKb*` variable existed afterwards, not even `BtKbBoots`, which the driver writes first thing. Linux set the controller up as usual (186 ms).
     - **Firmware:** AMI, UEFI 2.11. The firmware's boot timeout is 1 s.
     - **Entries:** every Boot#### entry uses efibootmgr's short, partition-only device path (`HD(1,GPT,…)/\EFI\…`), and the firmware boots those. Driver0000 has the same form.
     - **Main suspect:** in EDK-era boot managers, Boot#### paths are expanded from that short form, but Driver#### paths go straight to LoadImage, which can't resolve them. Otherwise, this firmware ignores Driver#### entirely.
     - **Ruled out:** the image is NX-compatible, its sections are page-aligned, and none is both writable and executable (checked against Limine and the UEFI shell, which this board runs).
   - **Bug found while preparing the diagnostics:** loaded from a subdirectory (`\EFI\btkb\`), the driver stopped at once with "listing \EFI\btkb\ failed: path error". uefi-rs rejects the trailing separator as an empty path component when listing the directory for `*.bond`; every earlier test had the driver at the root. Fixed with `app::listing_path`. This alone didn't cause the board result, since the driver would still have written `BtKbBoots` and its log.
   - **First diagnostics boot (Nov 2, 20:13): the keyboard worked in a UEFI shell on the board's own USB stack.** `scripts/board-diag.sh` booted the board once (BootNext) into a UEFI shell in `\EFI\btkb\`, and the shell loaded the driver. Results in `board/diag-20261102-201700/`:
     - **Firmware:** UEFI 2.11, American Megatrends `0x00050029`.
     - **Driver entry:** confirmed not started. `drivers` listed no bt-kb-dxe before the shell loaded it; the entry still had efibootmgr's short path.
     - **Load:** `Success`, image at `0x140000000` (above 4 GB).
     - **Bring-up on AMI's USB stack:** "firmware: 2/2 sections already loaded", controller ready in 215 ms (211–214 ms under OVMF). The controller sits at `PciRoot(0x0)/Pci(0x2,0x1)/Pci(0x0,0x0)/Pci(0xC,0x0)/Pci(0x0,0x0)/USB(0xD,0x0)`. So AMI handles the short control transfers of the WMT event poll, and the timed-out bulk reads of the ACL pipe, well enough.
     - **Console:** AMI's console splitter ("AMI Console Splitter Text In Driver") bound the device at once. Key notifications registered on it: Ctrl+Alt+Del in eight modifier combinations, F9, Pause, a null key, and the shell's Ctrl+C.
     - **Typing:** the user typed in the shell with the Bluetooth keyboard. The first connection "took a long time"; the cause is unknown, because the volatile log was lost (see below).
     - **Afterwards:** discovery had finished (`BtKbGatt` now in the board's NVRAM), the boot counter was cleared after 15 s, and Linux set the controller up in 187 ms.
     - **Log lost:** the shell was left with a reset instead of `linux`, which wipes the volatile `BtKbLog`. Only the log right after loading survived, in `vars-after.txt`. The driver entry stayed unchanged, since `linux.nsh` never ran.
   - **Changes for the second diagnostics boot:**
     - **Entry replaced automatically:** `startup.nsh` replaces the driver entry before loading the driver, with `bcfg driver add` from the firmware's own device path (`PciRoot(0x0)/Pci(0x1,0x2)/Pci(0x0,0x0)/NVMe(0x1,…)/HD(1,GPT,…)/\EFI\btkb\bt-kb-dxe.efi`). The slow information commands now run after the load.
     - **`btlog`:** a shell command (`rust/bt-kb-log`, copied as `btlog.efi`) that prints the driver's variables as text: the log, the boot counter, the last crash, whether a layout is remembered. Printable ASCII only, since any OS can write them.
     - **`linux`:** saves the log (`btlog >a diag\btlog.txt`) before it starts Limine.
     - **Timing lines:** the driver logs one line at each milestone (until connected, connection setup, while connected, first 15 s, at hand-off). It has the timer tick count and largest gap, the empty and data-carrying ACL reads with their average and maximum durations, the events read, and the event pipe's high-water mark, overflows and errors.
     - **Reinstall keeps the entry:** `board-install.sh` keeps an existing driver entry, so it can't undo the full path.
   - **Second diagnostics boot (Nov 2, about 20:32):** the shell replaced the driver entry with the firmware's own full device path and loaded the driver (bring-up 207 ms, remembered layout).
     - **Typing:** the keyboard "worked instantly", the user reported.
     - **Log lost:** the session ended with a reset instead of `linux`, so its log was lost again. The snapshot `startup.nsh` took ends at 217 ms, because the information commands ran in under a second, before the next flush.
   - **Loaded at boot by the firmware: done (Nov 2, 20:34).** In the next normal boot, the firmware loaded the driver from the full-path Driver0000.
     - **Proof it was the firmware:** BootCurrent was Limine, and the log lacks the UEFI shell's Ctrl+C key notify, which every shell-loaded log has.
     - **Bring-up:** the controller's USB interface already existed when the driver loaded (AMI enumerates USB first), and the controller was ready 229 ms after the driver loaded.
     - **Normal boot:** nobody pressed a key, so the driver waited. 5977 ms after it loaded, Linux's start triggered the hand-off ("Handoff: HCI_Reset + function off: ok"). **So AMI signals BeforeExitBootServices.** The boot counter was cleared, and Linux's setup took 191 ms.
     - **Timeline**, from Limine's timestamps (`LoaderTimeInitUSec`, `LoaderTimeExecUSec`) and the driver's log: the driver loaded about 11.3 s after the CPU reset. The firmware started Limine at 15.18 s, and Limine started Linux at 17.23 s. That gives the driver about 3.9 s before the firmware moves on to the boot loader. With a key pressed repeatedly, keys should flow about 1 s after the driver loads, so the setup hotkey may work even with the default 1 s prompt (see [Open questions](#open-questions)).
     - **AMI's timer and USB:** the tick was asked for every 5 ms and fired every 10 ms (577 ticks in 5.75 s), so AMI's timer period is 10 ms. The largest gap between ticks was 64 ms. An empty 1 ms ACL read took 1.4 ms (55 reads, one per 100 ms while idle). The event pipe never held more than 14 bytes, with no overflows or errors.
   - **Changes after these boots:**
     - **Load origin and time:** the driver's first line now says how it was loaded (by the firmware, or from a UEFI shell, detected by the shell protocol) and the time since the CPU reset (TSC). The OS hand-off line has that time too.
     - **`board-log.sh` timeline:** it prints a timeline of the boot (driver loaded, controller ready, keyboard connected, first key, hotkey-like keys, boot loader started, OS started), and runs without sudo: the variables are mode 644.
     - **`--collect`:** it labels which boot each log comes from.
     - **Fresh installs:** `board-install.sh` creates new entries with `efibootmgr --full-dev-path`. The firmware's own path has the same nodes as Linux's view: PCI `00:01.2/04:00.0`, and the NVMe EUI-64 in sysfs byte order (the shell prints it reversed). Untested; `board-diag.sh` remains the fix.
   - **Setup with the Bluetooth keyboard: works, with stalls (Nov 2, 20:54).** The user tapped Del from power-on and used AMI setup with the Bluetooth keyboard. The firmware started the boot loader only at 56.6 s instead of the usual 15.2 s, so setup was open for about 40 s.
     - **The stalls:** "from time to time it stopped accepting keys for a few seconds, then sent all the keys pressed meanwhile."
     - **What the log shows:** every connection followed the same cycle.
       - The keyboard connected, the controller reported the link encrypted after 0.16 s, and keys flowed through the driver's tap.
       - TrouBLE never registered the encryption, so the session's wait ended after 10 s with "no encryption within 10 s" and disconnected the keyboard (reason 0x16, local host).
       - Then the session backed off: 2, 4, then 6 s.
       - The keyboard kept the presses made meanwhile and sent them all after reconnecting.
     - **TrouBLE's queues filled:** with the session stuck before starting its GATT client, nothing read TrouBLE's ATT queue. Every key report also went there, and the packet pool ran out: a dozen `OutOfMemory` warnings per connection.
     - **Log truncated:** those warnings pushed the start of the log out of the 3800-byte ring.
     - **Timer and USB under setup:** ticks every 6–7 ms (10 ms during boot), gaps up to 12 ms (81 ms while the boot loader loaded), empty ACL reads 1.4 ms, no pipe overflows or errors.
   - **Cause: TrouBLE 0.8 and Encryption Change v2.**
     - **The gap:** TrouBLE unmasks Encryption Change v2 (event `0x59`, event mask page 2) during init, but its event handler and security manager only handle v1 (`0x08`) and Encryption Key Refresh Complete.
     - **The effect:** when a Bluetooth 5.3 controller reports encryption with v2, TrouBLE's pairing state machine stays in "waiting for bonded encryption". No `Encrypted` or `PairingComplete` event is posted, and no warning is logged. That matches the board log exactly: no errors, just the timeout.
     - **Rejected alternative:** a `RequestConnectionParams` answered inside the wait loop could block it too, but the event counts in the timing lines show only the Command Status and the Encryption Change during connection setup.
     - **Unexplained:** every QEMU session (and the first diagnostics boot on the board) did see encryption, so the controller apparently sent v1 there. The driver now logs the variant it sees.
   - **Fixes (Nov 2, 21:10):**
     - **v2 → v1:** the driver rewrites Encryption Change v2 into v1 before the host stack sees it (`uefi_bt::link::encryption_change_as_v1`; host tests). The two differ only in v2's trailing key size.
     - **Controller's word counts:** the session also ends its wait 0.5 s after the controller reported the link encrypted (the tap's view, `Shared::encrypted`), logging that the host stack missed it. It polls TrouBLE's security level too, and holds connection parameter requests until encryption, so nothing can block the wait.
     - **Working links stay up:** GATT trouble on a link whose keys work (layout known) no longer disconnects. The session logs it and keeps answering connection events; only LED updates stop. After a link that carried keys, the session waits for the next connection at once; the backoff (1, 2, 4, 8 s) is only for links that never worked.
     - **Key reports stay out of TrouBLE:** ATT notifications are read by the tap alone and no longer queued in TrouBLE, which has no subscriber for them (its controller-to-host flow control is off, so nothing needs acknowledging). This ended the `OutOfMemory` flood and the "unexpected PDU during MTU exchange" warnings.
     - **Log:** a 1600-byte head keeps the start (how and when the driver loaded, bring-up). A 4300-byte ring keeps the newest lines and starts at a complete line. A message repeated in a row is written twice, then counted (`uefi_bt::logbuf`; host tests). Duplicate key-notify registrations aren't logged.
     - **`board-log.sh` timeline:** shows every connection, disconnection (with reason) and first key, and which encryption event the controller sent.
   - **First reboot with the fix (Nov 2, 21:22): didn't work.** The user rebooted 16 s after installing it; after that, "a complete shutdown" and power-on worked. What the journal and the variables show:
     - **No Linux boot** between the reboot at 21:22:48 and the cold boot at 22:00:04. That boot stopped somewhere before Linux, and its volatile log died with it. This led to the boot record (above).
     - **Boot counter:** the next boot logged "start 1 of at most 3". So the driver either never ran in that boot, or ran at least 15 s without trouble. It didn't hang during bring-up, which would have left the counter at 1.
     - **No crash:** `BtKbPanic` is absent.
     - **Clean shutdown before it:** bluetoothd terminated normally ("Terminating", "Exit"), which powers the adapter off and disconnects the keyboard. So a link surviving that reboot is unlikely.
     - **Open:** what the screen showed (setup without keys, Limine's menu, a hang, Windows), and how the boot ended.
   - **Setup after a cold boot, with the fix: works (Nov 2, 22:00).** The driver loaded 9.49 s after reset (about 1.5 s earlier than in warm boots), and the controller was ready 0.22 s later.
     - **Connection:** the keyboard connected 0.24 s after the driver started waiting (Del tapped from power-on). The controller reported **Encryption Change v2**, which the driver passed on as v1, and the host stack confirmed the encryption 2 ms later.
     - **Keys:** the first key 214 ms after connecting. 23 Del presses were delivered, with no key notify run for any of them: AMI registers Del only with Ctrl+Alt, so it polls for its setup key.
     - **Setup:** the firmware started the boot loader at 30.0 s (15.2 s without setup), so setup was open for about 20 s.
     - **No stalls:** one connection for the whole 24 s session, 172 key reports (171 notifications kept from the host stack), no `OutOfMemory`, no session timeout. The log's repeat counting folded the Del lines.
     - **Hand-off:** at the OS start, as before. Linux's setup took 186 ms.
     - **Timer under setup:** ticks every 7 ms, gaps up to 26 ms (74 ms while the boot loader loaded).
     - **Not covered:** a pause of over a minute (the keyboard's idle disconnect and the reconnect), and setup reached after a warm reboot.
   - **Changes after these boots:**
     - **Boot record** and **closing links left from before** (see [The driver as built](#the-driver-as-built-bt-kb-dxe-nov-1)).
     - **Key notify lines:** they now show the unicode character and toggle state. AMI registered each Ctrl+Alt+Del combination twice with descriptions that looked identical, so the difference is in one of those.
     - **Longer log lines:** up to 512 bytes, so a boot record fits on one line.
   - **Warm reboot with Del (Nov 2, 22:52): the driver didn't run.** The user tapped Del, setup didn't open, and Linux started. The boot-record build wasn't installed yet (no sudo in that session), so the ESP still had the 21:13 build, the one that worked at 22:00.
     - **No trace:** no `BtKbLog` at all, and `BtKbBoots` still at the 0 the 22:00 boot left. The firmware never started the driver; the Driver0000 entry was unchanged.
     - **A different firmware path:** the boot loader started 10.7 s after reset (FPDT `bootloader_load_ns` 10.73 s), the fastest boot in the journal. Full boots today took 14.3–15.1 s, and 19:51, also without the driver (short-path entry), took 14.3 s.
     - **It matches the boots before the project:** every boot from Oct 24 to Nov 1 afternoon took 12.3–12.6 s in the firmware, then 5.24 s in Limine. Every full boot since the Nov 1 mains power cycle took 14–15 s, then 1.3–2.8 s in Limine. The 22:52 boot took 10.7 s plus 5.29 s in Limine. So in a fast boot the firmware leaves device connection to the boot loader, and the whole boot is barely shorter (about 16.0 s to the kernel, against 16.2–17.5 s).
     - **AMI Fast Boot state:** variables under vendor GUID `b540a530-6978-4da7-91cb-7207d764d262`: `FastBootOption` (Limine's full device path, which a fast boot boots directly), `LastBoot` and `LastBootFailed` (0).
     - **Boot order rewritten:** `BootOrder` is now `0001,0003,0017,000E,0002,0004,0005`, with Limine first and three AMI placeholder entries (`UEFI:CD/DVD Drive`, `UEFI:Removable Device`, `UEFI:Network Device`, `BBS(129–131)`). At 20:34 it was `0017,0003,0001,000E`.
     - **Conclusion:** Fast Boot has been on all along. Today's full boots were the exception, perhaps set off by the many boot-option changes and the failed boot. The 21:22 failure fits: the boot counter shows the driver didn't run then either, and the 22:00 cold start came right after that failed boot. Why AMI chose full or fast for each boot today isn't known.
   - **Change:** `board-log.sh` now explains a boot without a driver log: when the boot loader started, and the Fast Boot hint if the AMI variables exist.
   - **Fast Boot off (Nov 2, 23:12):** the user set it in setup, reached with `systemctl reboot --firmware-setup`. Then `sudo scripts/board-install.sh` installed the boot-record build (23:14), followed by a warm reboot.
   - **Warm reboot with Fast Boot off (Nov 2, 23:15): the driver ran.**
     - **Load and bring-up:** the firmware loaded the driver 9.84 s after reset; the controller was ready 0.22 s later (bring-up 209 ms). That includes the new check for links left from before, which found none (nothing logged), at no measurable cost.
     - **Connection:** the keyboard connected at 12.09 s, after a key press. Encryption Change v2 again, passed on as v1; the host stack confirmed it 1 ms later. First key 215 ms after connecting; one connection until the OS start; 86 key reports, none of them hotkey-like.
     - **Keys went to Limine:** the firmware started Limine at 12.11 s, 0.02 s after the connection, so the key presses reached Limine through the driver. Limine took 9.4 s, against 2.3 s in the boot before, with no keys.
     - **Hand-off and record:** hand-off at the OS start (21.36 s); Linux's setup took 187 ms. The boot record was written (`…; OS started +11.61 s`). "previous boot: no record" is expected for the first boot of this build.
     - **Firmware time:** 12.07 s in both boots after the setup change, against 14.3–15.1 s in today's earlier full boots and 10.7 s in the fast boot. A possible reason: Limine is now first in BootOrder, while before the firmware first had to fail on the two Windows entries (BootCurrent was always Limine). Not verified.
     - **Setup-key window:** 2.05 s between the controller being ready (10.06 s) and the firmware starting the boot loader (12.11 s). At 22:00, Del tapped from power-on arrived 0.7 s after the driver loaded, so it fits, with little to spare. A longer Setup Prompt Timeout would widen it.
     - **AMI's second Ctrl+Alt+Del set:** the key notify lines now show the character: notifies 5–8 are Delete with char `.` (0x2E), the keypad's Del key.
   - **Next:**
     1. A warm reboot without touching the keyboard: the record should say "keyboard never connected".
     2. A warm reboot with Del tapped from power-on: setup; a pause over a minute, then a key (the idle reconnect); leave through Boot Override → Limine; `scripts/board-log.sh`.
     3. A setup session ending in Save & Exit or Reset. The record isn't written in the reset notification, but the next boot's log shows whether the reset hand-off closed the link: a "closed a link left from before" line would mean it didn't.
     4. One Windows boot: Bluetooth in Windows after the hand-off.
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

## Security hardening (Nov 3)

Threat model and goals as in the README's Security section: root can always read the LTK from BlueZ, so hiding it from root is not a goal. The goals:
1. Root can't change what runs before the OS, or which keyboard the firmware trusts, without a key that isn't on the machine.
2. No plaintext LTK at rest outside the encrypted root file system.
3. With a TPM, the stored key is sealed.
4. Nothing received before encryption becomes a keystroke.
5. Radio-range attackers without the LTK can only deny service.

Stages, in order: 0 a QEMU harness with Secure Boot and a TPM; 1 the link; 2 Secure Boot with sbctl and the firmware image; 3 bond authenticity and a no-TPM fallback; 4 TPM sealing. Status Nov 3, evening: all five done and tested offline (swtpm and sbsigntools installed in the afternoon); none of it on the board yet.

### Stage 1: the link (done Nov 3)

- **Found while reviewing the tap: TrouBLE 0.8 pairs on its own.** When encryption with the bonded key fails, its central sends a fresh Pairing Request if the security request was user-initiated (`handle_bonded_encryption_failed` in `security_manager/pairing/central.rs`). `Connection::request_security()`, the only public way to start encryption, is user-initiated.
  - **Attack:** a device that advertises with the keyboard's address gets our accept-list connection, rejects the bonded key, and lets TrouBLE pair Just Works. The Encryption Change that follows has status 0x00, so the old tap would have delivered its reports.
  - **And it lasts:** on PairingComplete TrouBLE may store the new keys as the bond for the rest of the boot. The session also took PairingComplete as success.
- **The guard** (`uefi_bt::tap`): every packet TrouBLE sends passes `InboxTransport::write`, and every packet it receives passes the driver's pump.
  - **Encryption:** LE Enable Encryption goes out only with the bond's LTK, EDIV and Rand, compared in constant time. LE Long Term Key Request Reply never goes out (the driver is never a peripheral). A refused command fails the host stack, and with it the driver.
  - **No SMP:** Security Manager PDUs (L2CAP channel 6) are dropped both ways, continuation fragments included. Starting encryption with a stored key is link-layer only, so the driver needs no SMP at all.
  - **Session:** PairingComplete is an error.
  - **Hand-off:** the guard's copy of the key is wiped, so no encryption can start afterwards.
- **The tap** treats the link as encrypted only after an Encryption Change (v1 or v2) with status 0x00 and encryption on. It must be for the connection to the bonded address and address type, with us as the central, and follow a bonded start on that connection. Starts are forgotten when a connection begins or ends: the controller reuses handle 0x0200.
  - An encryption without a bonded start is a violation: the driver fails closed. It can't happen while the guard is in place.
  - Encryption turning off releases all keys.
- **Pre-encryption reports** are dropped and counted: logged per connection, and in the boot record as "N from before encryption dropped".
  - Reports that arrive on the encrypted link before the layout is known are still kept and replayed.
  - The old behaviour is the `insecure-replay-unencrypted` cargo feature, which logs a warning at every start.
  - **Cost:** HCI events and ACL data come on different USB endpoints, so a report sent right after encryption can overtake its Encryption Change. Usually that's the key that woke the keyboard. In the Nov 2 board logs the first report came 28 ms after the Encryption Change, so this should be rare.
- **Tests:** 11 host tests in `tap.rs` and `bootrec.rs`. The offline QEMU suite passes, but it has no controller, so the new paths only run in the `qemu-hw-*` sessions on the real keyboard.

### Stage 0: the QEMU harness (Nov 3; done)

- **OVMF:** Arch's `edk2-ovmf` 202608 `OVMF_CODE.secboot.4m.fd` has Secure Boot (`SecureBootConfigDxe`), SMM (`PiSmmCore`, `VariableSmm`), TPM 2.0 (`Tcg2Pei`, `Tcg2Dxe`, `Tcg2ConfigPei`) and no built-in shell (checked with `virt-fw-dump`). No source build needed.
- **`SB=1`** (common.sh, in `qemu-driver-test.sh` and the `qemu-hw-*` scripts):
  - **Machine:** q35 with `smm=on` and `-global driver=cfi.pflash01,property=secure,value=on`.
  - **Keys:** throwaway PK/KEK/db plus an "other" key, made with openssl into `qemu/sb/keys/`, and enrolled with `virt-fw-vars` (venv in `tools/venv-fw`) with Secure Boot on.
  - **Images:** every image on an ESP comes from `qemu/sb/signed/`, signed with sbsign. Without sbsigntools, their Authenticode hashes (`hash-to-efi-sig-list`) are enrolled in db instead.
  - **Checked:** SecureBoot=1 and SetupMode=0 as the shell sees them; a tampered app gets Access Denied; the whole offline suite passes under SB=1.
- **`TPM=1`:** swtpm as `tpm-crb`, plus a host provisioning mode (`tpm_host_start`: swtpm on TCP, `TPM2TOOLS_TCTI=swtpm:…`). Tested in the afternoon: tpm2-tools reach swtpm, and offline case 8's replay of the event log matches the PCR 7 the driver read.
- **One TPM boot in ten hangs (Nov 3):** found when case 8 timed out twice in four runs.
  - **What the guest does:** the vCPU sits in a firmware delay loop (RIP fixed, port 0x608, the ACPI PM timer, read over and over).
  - **What QEMU shows:** its `tpm_*` trace events show one TPM command polled ~500K times (~15 s at EDK2's 30 µs step; a normal boot's slowest takes ~19K). After that, all hung runs stop after exactly 128 commands, the last one complete (Start cleared, goIdle written), and no TPM traffic follows.
  - **Not the driver:** hangs happened without the driver (2 of 14, 2 of 19 with swtpm's state on tmpfs), with `tpm-tis` as well (2 of 20), and with the driver (2 of 8). So the cause is in QEMU 11.1.3's TPM emulator path, not fsync and not this project.
  - **Workaround:** `run_qemu` retries a TPM boot that times out, from snapshots of the variable store and TPM state, and prints `(TPM boot hung, retrying …)`. Case 7, which is typed into over QMP, runs without the TPM.
- **Driver:** at entry it logs PCR 7 (TPM2_PCR_Read through SubmitCommand), which of PCRs 0–7 already have an EV_SEPARATOR in the event log, and its own load event. It also replays PCR 7 from the log against the TPM.
  - **Finding the load event:** first written to match the image base. That never matched: EDK2 and AMI both log the buffer the file was read into (AMI: `ImageLengthInMemory` is the file size, 457728). It now matches the file path in the event's device path, as `eventlog.py` does.
  - **Numbering:** events are numbered as `tpm2_eventlog` numbers them (the Spec ID header is event 0), in the driver and in `eventlog.py`.
  - **Code:** `uefi_bt::tcg`, `tpm2`, `eventlog`. The event log fetch reads the last event's header field by field, so nothing past the log is touched.
  - **Boot record:** keeps the separator bitmap, so the AMI ordering survives a reset.
- **`btlog -eventlog FILE`** writes the raw log to the ESP. `scripts/eventlog.py` reads that or Linux's `binary_bios_measurements`; offline case 8 compares its PCR 7 prediction with the driver's reading.
- **Confirmed in EDK2's source (Tcg2Dxe.c, `MeasureSecureBootPolicy`):** PCR 7's separator is measured right after the Secure Boot variables, early in DXE, "because this event must be between SecureBootPolicy (Configure) and ImageVerification (Authority)", explicitly for images from DriverOrder. PCRs 0–6 get theirs at ReadyToBoot, after Driver####.
  - **So in EDK2 a Driver#### runs after PCR 7's separator and before those of 0–6.**
- **The board, with Secure Boot off (the user's `tpm2_eventlog` of Nov 3):** AMI is different. bt-kb-dxe's EV_EFI_BOOT_SERVICES_DRIVER (PCR 2, `\EFI\btkb\bt-kb-dxe.efi`, event 11) comes before every separator, PCR 7's included. All eight separators come at ReadyToBoot (events 19–26), after the boot variables (PCR 1) and "Calling EFI Application from Boot Option" (PCR 4).
  - **PCR 7 at the driver:** the replay of SecureBoot (0), PK, KEK and db (all empty: Setup Mode) and dbx, `2ac5d2f4…`. The OS sees `01895e74…`, with the separator.
  - **PCR 2 at the driver:** two option ROMs and the driver, `1c2ab0c2…`; the OS sees `26e06776…`.
  - **Checked:** the replay of all events reproduces both final values the TPM reported.
  - **Still to check:** with Secure Boot on, AMI has to log authority events, and may move PCR 7's separator.

### Stage 2: Secure Boot and the firmware image (Nov 3; tested offline, signed and in hash mode)

- **Firmware image pinned:** `build.rs` hashes `BT_KB_FIRMWARE` (`build-rust.sh` passes the linux-firmware copy), and the driver refuses any other image before parsing it. Offline case 9 changes one byte, and the driver refuses with Security Violation.
  - **Pinned, not embedded:** embedding would add 517 KB for the same guarantee.
  - **After a linux-firmware update:** rebuild and reinstall. `board-install.sh` checks the system image against the pin before installing.
- **Secure Boot test** (offline case 10, SB=1): a tampered driver behind Driver#### is refused, and the boot goes on to the shell. In sign mode it also tries the unsigned driver and one signed with the "other" key.
- **`board-install.sh`:**
  - **Signing:** with sbctl's key via `sbctl sign -o` into a staging directory, then `sbctl sign -s` on the installed files, so sbctl keeps re-signing them. Or with an off-machine key: `DB_KEY` (a file, or a `pkcs11:` URI through sbsign's engine) and `DB_CERT`.
  - **With Secure Boot on:** it refuses if a file doesn't verify (sbverify), or if the signing certificate isn't in the firmware's db (its DER in the db variable).
  - **With Secure Boot off:** it installs, with a warning.
- **`scripts/secureboot-setup.sh`:** the CachyOS flow as a checklist; it never enrolls keys.
- **Keys off the machine:** sbctl's keys are unencrypted in `/var/lib/sbctl/keys`, so against root (goal 1) they must not stay there. The price: sbctl's hook can't re-sign kernel updates.
- **`--microsoft`:** anything Microsoft signs also runs, so goal 1 also rests on dbx.

### Stage 3: bonds (Nov 3; tested offline)

- **Recommendation implemented:** bond digests baked into the build, not Ed25519-signed bonds. One root of trust (the db key), and no asymmetric crypto in firmware. The price is a rebuild and re-sign per re-pairing.
  - **The digest:** SHA-256("bt-kb-dxe bond v1\0" ‖ 42-byte record). Rust (`ExportedBond::digest`) and Python (`scripts/bond-digest.py`) agree, checked by a host test with a shared vector.
  - **Builds:** `build-rust.sh` pins `qemu/keys/*.bond`. The offline tests build a separate driver that trusts only a public test bond, since a production build that trusted it would let anyone type.
- **No-TPM storage:** a trusted bond file is imported into `BtKbBond` (NV+BS, no RT), checked by reading it back, then deleted from the ESP. Later boots check the stored bond against the build again. Untrusted files are ignored.
  - **Removal:** the marker `bt-kb-dxe.forget` makes the driver delete the variable, and `board-install.sh --remove` uses it in two steps.
- **Variables with RUNTIME_ACCESS:** BtKbLog, BtKbLastBoot, BtKbBoots, BtKbGatt, BtKbPanic. None holds key material. Offline case 11 checks that with the test key, in both byte orders, in the variable store and the log.
- **Memory:** the Config copy of the key is wiped at BeforeExitBootServices, and the guard's at the hand-off.

### Stage 4: TPM sealing (Nov 3; tested offline)

- **Policy (decided after the board's event log):** one TPM2_PolicyPCR over PCR 2, PCR 7 and a spare PCR (8; `BT_KB_SPARE_PCR` at build time), with the values they have while the driver runs.
  - **The spec's default, "PCR 7 before its separator", holds on the board** (the separator comes at ReadyToBoot) but not in EDK2, which measures it before any image.
  - **And PCR 7 alone has a gap:** if the Driver#### entry is removed (root can), an image signed with the same db key, say Limine as a Driver####, sees the same PCR 7. Driver#### images run before ReadyToBoot, so it could even start an OS before any separator.
  - **PCR 2 closes that:** it holds the driver's own load measurement, and its separator comes after the driver both in EDK2 and on the board.
  - **The spare PCR closes the rest:** code started later in the same window, such as an app from setup with an already-measured authority (with `--microsoft`, the GPU option ROM's MS CA is measured before the driver), would see PCR 2 and 7 unchanged. The driver extends PCR 8 right after its unseal attempt, on every boot with a TPM, whether a seal exists or not; otherwise removing the file would skip the extend. It does so even when the boot-loop guard stops it, and logs an EV_EFI_ACTION. The number is compiled in, so the ESP can't change it.
  - **PCR 8 is free on this machine:** GRUB uses it, Limine doesn't, Windows uses 11–14.
- **Driver side** (`uefi-bt/src/tpm2.rs`, `seal.rs`, `rng.rs`; `bt-kb-dxe/src/sealed.rs`):
  - **The sequence:** ReadPublic(0x81000001) and a check against the `srk_name` recorded at sealing; Load; StartAuthSession (policy, salted with ECDH P-256 to the SRK, XOR parameter encryption, SHA-256); PolicyPCR with the expected PCR digest, so a change shows as TPM_RC_VALUE; Unseal with the response encrypted; FlushContext on every error path.
  - **Hand-encoded** for SubmitCommand. A `Tpm` trait lets the same code run over swtpm's TCP port in host tests.
  - **Found against libtpms:** a salted policy session needs the command HMAC even without PolicyAuthValue. An empty one gets TPM_RC_BAD_AUTH (0x9A2).
  - **The answer:** XOR-decrypted (KDFa "XOR", nonceTPM, nonceCaller), and its HMAC checked against libtpms.
  - **KDFa/KDFe:** known answers from Python; policy digest from `tpm2_policypcr`.
  - **Randomness:** RDSEED/RDRAND, EFI_RNG_PROTOCOL and TPM2_GetRandom through SHA-256 (not the TPM alone: a bus interposer would choose it).
  - **Zeroizing:** `Zeroizing` buffers for TPM responses; `ExportedBond` now wipes itself on drop (every early return).
  - **TrouBLE never holds the key:** it gets a stand-in (`b"bt-kb-dxe:no-ltk"`), and the link guard writes the real LTK into LE Enable Encryption on its way out; the transport wipes command packets after sending. This matters because the driver runs at every boot: an OS booted from USB gets boot-services memory as it is. Untested on the real controller yet.
- **OS side** (`scripts/tpm-seal.sh`):
  - **SRK:** 0x81000001, created from systemd's template if missing (ECC P-256, AES-128-CFB, noda).
  - **Prediction:** `eventlog.py predict` replays up to the driver's load event, substituting the Authenticode hash of the driver the next boot runs (`eventlog.py pehash`, checked against efitools and against EDK2's measurement).
  - **Checks:** the policy digest against `tpm2_policypcr`'s trial session; it refuses values the TPM has right now.
  - **Sealing:** `tpm2_create -i -` from `bond-digest.py --record`, which refuses a terminal.
  - **Output:** `bt-kb-dxe.sealed`: text, public and private parts in hex, expected values, policy, bond digest.
  - **Options:** `--if-needed` reseals when the policy, the bond or the fallback setting changed, or the last boot record says "unseal failed". `scripts/systemd/bt-kb-reseal.service` runs it at boot. `board-install.sh` reseals right away for a new driver.
- **Fallback:**
  - **As specified, the stage 3 copy stays** for boots where unsealing fails. It is plaintext in SPI flash, readable from a flash dump.
  - **`--no-fallback`** writes `fallback=no`: the driver deletes `BtKbBond`, deletes trusted `.bond` files without importing them, and refuses to fall back. `board-install.sh` then stops copying the bond file.
- **Tests:**
  - **`scripts/tpm-host-test.sh` (6 of 6):** it unseals with the HMAC checked; PCR 8 extended gives TPM_RC_VALUE at PolicyPCR, and the same without expected values gives POLICY_FAIL at Unseal; after a restart it unseals again; a corrupted private part is refused at Load; another SRK name is refused. Nothing stays loaded in the TPM.
  - **Offline case 12 (14 of 14 checks, 8 boots):** seal from boot 1's log; the driver unseals; `btlog -unseal-test` (a test-only feature) is refused from the shell both ways; a dbx entry makes the driver report "PCRs that changed since sealing: 7" and use the copy; `--if-needed` reseals once, then reports up to date; a corrupted seal fails cleanly; without a TPM the copy is used; `fallback=no` deletes the copy, and a failed unseal then leaves no key.
- **Bugs found on the way:**
  - `pehash` read Characteristics instead of SizeOfOptionalHeader (a struct format off by two bytes); caught by case 12's check against the logged digest.
  - `tpm2_createprimary` leaves its transient copy loaded without a resource manager, so swtpm ran out of object slots; `tpm2_flushcontext -t` fixes it, and through `/dev/tpmrm0` it's a no-op.

## Open questions

- Does the keyboard advertise with its static address or with resolvable private addresses? If `[IdentityResolvingKey]` is present and it uses RPAs, load the IRK into the controller's resolving list.
- Does AMI setup accept a tagged Simple Text Input device that appears late? AMI's console splitter does: in the UEFI shell it bound the device as soon as the driver loaded, and typing worked (Nov 2). Setup itself is still to be seen.
- ~~Does AMI's USB stack handle a timed-out bulk read the way EDK2's does?~~ Well enough: the ACL pipe carried a full connection, discovery and typing (Nov 2). The new timing lines will show how long its 1 ms reads really take.
- ~~Does AMI's USB stack copy back only the received bytes of a short control transfer? The WMT event poll relies on it.~~ Bring-up, including the WMT firmware status query, worked in 215 ms (Nov 2).
- ~~Does this firmware load drivers from Driver####?~~ Yes, from a full device path (Nov 2). Not from efibootmgr's short, partition-only form, which the same firmware accepts for Boot####.
- Why did the keyboard's first connection on the board take long? Unknown; that log was lost. The second time it was instant, with the layout remembered. Candidates for the first time:
  - the driver loaded only after the shell's 5 s countdown and its information commands;
  - the keyboard's reconnect behavior after Linux's session ended at the reboot;
  - the first GATT discovery (no layout was remembered on the board yet);
  - AMI's USB timing.
- ~~Does the MT7922 subsystem reset clear the loaded firmware?~~ Yes: Linux's MediaTek reset (subsystem reset plus USB reset) dropped it on Nov 1, followed by a 20.4 s re-upload. So the upload path can be tested without cutting power. Still open: does the reset revive a controller that has stopped answering HCI?
- ~~How fast is the board firmware's timer tick?~~ 10 ms on AMI (Nov 2): a 5 ms relative timer fired every 10 ms. That is the 100 packets/s the event pipe was planned for.
- Does the setup hotkey work with the Bluetooth keyboard?
  - **Timing:** the window is short. The driver loads late (Driver#### in BDS), bring-up takes about 0.2 s, and the keyboard must be woken by a key press. The wake key itself is delivered (Nov 1), so pressing the hotkey repeatedly from power-on can work. With the remembered layout it should arrive about 0.5 s after the keyboard wakes.
  - **OVMF: yes** (Nov 2, real controller and keyboard). F2 pressed during the countdown woke the keyboard and was delivered as the hotkey 0.18 s after the connection; the boot menu opened. The first try had failed only because the countdown was invisible in the terminal, so the keyboard first connected after it.
  - **F-key mode:** answered: F2 arrives as the keyboard page's F2.
  - **Workarounds:** a longer "Setup Prompt Timeout" in AMI setup; reboot-to-firmware (`systemctl reboot --firmware-setup`); `efibootmgr --bootnext` for a one-time boot override.
  - **Board:** AMI loads the driver about 11.3 s after reset, and starts the boot loader about 3.9 s later (Nov 2, default 1 s prompt). Whether its setup-key check falls in those 3.9 s is the next test.
  - **AMI's key notifies:** AMI registered Ctrl+Alt+Del (all four Ctrl/Alt combinations, twice), F9, Pause and a null key on the device; Del and F2 are not among them. So AMI probably polls the console for its setup key, and our key FIFO keeps keys until it does.
- ~~Does the keyboard advertise with its identity address?~~ Yes: on a key press it sends directed advertising to this PC from `C0:00:00:00:00:01`, and undirected advertising with the HID UUID and appearance `0x03C1` (Nov 1 scan).
- Was the Nov 1 wedge really unread ACL data holding back events? A run with a live, busy link would tell, but it risks another mains power cycle.
- Why does each upload chunk take about 10 ms? If it's the chip's write time, the cold start can't get much faster than 20 s.
- Why did the controller report encryption with v1 in QEMU but v2 on the board? The board's cold boot logged "Encryption Change v2" (Nov 2); a QEMU run with this build would show what it sends there.
- ~~What happened in the warm reboot right after installing the stall fix (Nov 2, 21:22), which never reached Linux?~~ Most likely an AMI fast boot, as at 22:52: the boot counter shows the driver didn't run. How that boot ended is unknown.
- ~~When does this AMI firmware choose a full boot over a fast one?~~ Moot: Fast Boot is off since Nov 2, 23:12. (Full boots from the Nov 1 mains power cycle until 22:00, fast at 21:22 and 22:52.)
- ~~Does AMI 4.43 signal `BeforeExitBootServices`?~~ Yes (Nov 2): the driver's hand-off ran from it when Linux started, and the log flushed there was readable in Linux.

Possible next steps:

- [x] Sketch the EDK2 module layout
- [x] Identify the machine's BT chip and whether it needs a firmware upload
- [x] Milestone 1: MT7922 bring-up probe, in `~/Projects/bt-uefi-keyboard`. It is tested against a simulated MT7922 and has run on the real controller through QEMU/OVMF (EDK2's USB stack), first in C, then in Rust (`bt-hci-probe.efi`).
- [x] Switch to Rust (uefi-rs + TrouBLE)
- [x] Milestone 2: `bt-le-scan.efi` saw the bonded keyboard (third scan, Nov 1).
  - The first attempt wedged the controller (see [Controller wedge](#controller-wedge-nov-1)).
  - The second ended in a TrouBLE panic after about 30 s (see [Scan panic](#scan-panic-nov-1-second-attempt)).
  - Events now use an async interrupt transfer, with validation and a safe panic handler.
- [x] Milestone 3: `bt-kb-probe.efi` connected, encrypted with the exported key and decoded typing in report protocol (Nov 1). Boot protocol doesn't work on this keyboard.
- [x] Larger TrouBLE queues confirmed on hardware: no lost key reports with fast, overlapping typing
- [x] Milestone 4: the driver (`bt-kb-dxe.efi`) in OVMF on the real controller and keyboard: the shell (Nov 1), then loaded at boot with the F2 boot-menu hotkey, setup, and the reset hand-off (Nov 2).
- [ ] Milestone 5: the real board (AMI Aptio, its own USB stack). Done: typing in a UEFI shell, loading at every boot from a full-path Driver#### entry, the hand-off when Linux starts, Del into AMI setup and typing there (Nov 2). The stall fix is confirmed after a cold boot (Nov 2, 22:00). The two failed warm reboots were AMI fast boots, which skip driver entries. With Fast Boot off, a warm reboot ran the driver (Nov 2, 23:15). Next: Del after a warm reboot, the idle reconnect, a reset from setup, and one Windows boot.
- [x] Persistent cache of the keyboard's handles and report layout (`BtKbGatt`), so connections after the first skip the GATT discovery. On hardware (Nov 2): first key 180 ms after the connection instead of 2.4 s.
- [ ] Firmware upload in the driver (cold start after a power cut, about 20 s)
- [ ] Run `BtHciProbe.efi` from a UEFI shell on the board itself, to test AMI's USB stack
- [ ] OS-side bond exporter for the bond variable (bt-sync)
