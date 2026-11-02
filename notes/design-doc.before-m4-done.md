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

An earlier manual check (Nov 2) loaded the self-test driver from the shell, typed `exit`, and pressed Enter in the boot menu. OVMF's setup front page (UiApp) appeared, driven by keys from our driver.

Tally: 14 runs of the four-case suite (56 boots) plus 21 runs of the panic case alone.
- **Confirmed failure:** one panic run hung after the message was stored and the notice shown; the reset never happened.
- **Unexplained timeout:** one early suite run timed out with its output lost, so it may be the same thing.
- **Everything else** passed.

The panic hang's cause is unknown; it may be the same OVMF behavior as with variable writes during a reset. The boot-loop counter covers this on real hardware: a machine that hangs here gets power-cycled, and after 3 such boots the driver stays off. The six-case suite (Nov 2) passed on its first run.

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
   - **Next:** `scripts/qemu-hw-boot.sh` again, now with the guest's screen in a QEMU window and the driver's log live in the terminal (see [Test-environment findings](#test-environment-findings)). The countdown is now 20 s.
     - **Hotkey:** press F2 on the Bluetooth keyboard while the progress bar runs, until the boot menu appears. The log shows each F2 the driver delivers, and how many key notify functions ran for it.
     - **Setup:** pick "EFI Firmware Setup" and move around.
     - **Reset hand-off from setup:** end with "Reset" on the front page.
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
- ~~Does the MT7922 subsystem reset clear the loaded firmware?~~ Yes: Linux's MediaTek reset (subsystem reset plus USB reset) dropped it on Nov 1, followed by a 20.4 s re-upload. So the upload path can be tested without cutting power. Still open: does the reset revive a controller that has stopped answering HCI?
- How fast is the board firmware's timer tick? It caps the async event pipe's throughput (one packet per tick).
- Does the setup hotkey work with the Bluetooth keyboard?
  - **Timing:** the window is short. The driver loads late (Driver#### in BDS), bring-up takes about 0.2 s, and the keyboard must be woken by a key press. The wake key itself is delivered (Nov 1), so pressing the hotkey repeatedly from power-on can work. With the remembered layout it should arrive about 0.5 s after the keyboard wakes.
  - **OVMF:** the mechanism works offline (test 5: an F2 from our driver opens the boot menu during the countdown). The first hardware run (Nov 2) didn't test it: the keyboard first connected 24 s after the driver started, after the countdown. Was F2 pressed in that time? With nothing on screen, there was no cue. Rerun with the window.
  - **F-key mode:** does F2 on this keyboard send the keyboard page's F2, or a media function in another report (the Report Map has report IDs 16, 39 and 44–47 besides the keyboard's 1)? The driver logs reports on other handles to find out.
  - **Workarounds:** a longer "Setup Prompt Timeout" in AMI setup; reboot-to-firmware (`systemctl reboot --firmware-setup`); `efibootmgr --bootnext` for a one-time boot override.
  - **Board-only question:** whether AMI checks hotkeys before or after it processes Driver####.
- ~~Does the keyboard advertise with its identity address?~~ Yes: on a key press it sends directed advertising to this PC from `C0:00:00:00:00:01`, and undirected advertising with the HID UUID and appearance `0x03C1` (Nov 1 scan).
- Was the Nov 1 wedge really unread ACL data holding back events? A run with a live, busy link would tell, but it risks another mains power cycle.
- Why does each upload chunk take about 10 ms? If it's the chip's write time, the cold start can't get much faster than 20 s.
- Does AMI 4.43 signal `BeforeExitBootServices`? A 2026 build probably implements UEFI 2.8 or later, but I haven't verified it.

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
- [ ] Milestone 4: the driver (`bt-kb-dxe.efi`) in OVMF, with keys working in the shell and in OVMF's setup UI. Shell done on hardware (Nov 1); loading at boot, the hotkey and the setup UI pass offline; their hardware run is next.
- [x] Persistent cache of the keyboard's handles and report layout (`BtKbGatt`), so connections after the first skip the GATT discovery. Built Nov 2; its effect on hardware is still to be measured.
- [ ] Firmware upload in the driver (cold start after a power cut, about 20 s)
- [ ] Run `BtHciProbe.efi` from a UEFI shell on the board itself, to test AMI's USB stack
- [ ] OS-side bond exporter for the bond variable (bt-sync)
