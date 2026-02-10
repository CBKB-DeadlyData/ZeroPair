# ZeroPair

**Zero Authentication Bluetooth Exploit**

*"Steal The Print, Own The System"*

```
███████╗███████╗██████╗  ██████╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
  ███╔╝ █████╗  ██████╔╝██║   ██║
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████╗███████╗██║  ██║╚██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝
    ██████╗  █████╗ ██╗██████╗
    ██╔══██╗██╔══██╗██║██╔══██╗
    ██████╔╝███████║██║██████╔╝
    ██╔═══╝ ██╔══██║██║██╔══██╗
    ██║     ██║  ██║██║██║  ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```

**Author:** [CBKB] DeadlyData | 2026

ZeroPair is a proof-of-concept tool that demonstrates a zero-authentication vulnerability in Bluetooth-enabled thermal printers using Jieli and Barrot chipsets. The affected devices accept unauthenticated RFCOMM connections without requiring pairing or user interaction, allowing an attacker within Bluetooth range to access the printer command interface.

**CVE:** Submitted to MITRE (pending assignment)

---

## Proof of Concept

<p align="center">
  <img src="assets/PoC.jpg" alt="ZeroPair Proof of Concept" width="600">
</p>

<p align="center">
  <video src="assets/PoC.mov" controls width="600"></video>
</p>

> **Note:** If the video doesn't render on GitHub, [click here to download it](assets/PoC.mov).

---

## Vulnerability Summary

Bluetooth-enabled thermal printers using Jieli and Barrot Bluetooth chipsets contain an authentication bypass vulnerability in their RFCOMM (SPP) service. Due to improper access control implemented in firmware, the affected devices accept unauthenticated RFCOMM connections without requiring pairing or user interaction. The vulnerability exists in a hidden firmware trust state that cannot be inspected or removed using standard Bluetooth management tools.

### Impact

- **Information Disclosure** - Read printer buffer/status without authorization
- **Arbitrary Command Execution** - Inject ESC/POS or TSPL commands to print arbitrary content
- **Denial of Service** - Consume paper, lock the command interface, or disrupt normal operation
- **Persistent Backdoor** - Device remains exploitable across reboots; pairing cache cannot be cleared through standard tools

### Vulnerability Classifications Detected

| Classification | Severity |
|---|---|
| Zero Authentication | Critical |
| Persistent Pairing Trust | High |
| Hidden Pairing State | High |
| Unknown Authentication Bypass | High |

---

## Affected Devices

| Model | Manufacturer | Chipset | Default PIN | Command Set |
|---|---|---|---|---|
| X6h-A725 | Zhuhai Jieli | Jieli | 1234 | ESC/POS |
| M58-L | Zhuhai Jieli | Jieli | 1234 | ESC/POS |
| D450 | Omezizy | Barrot | 0000 | TSPL |

Other Bluetooth thermal printers using these chipsets may also be affected.

---

## Requirements

### Platform
- Linux (requires BlueZ stack)

### System Dependencies
- `bluez` - Bluetooth protocol stack (`hcitool`, `bluetoothctl`, `rfcomm`, `sdptool`)

Install on Debian/Ubuntu:
```bash
sudo apt install bluez
```

### Python Dependencies
- Python 3
- `colorama`

```bash
pip install colorama
```

### Hardware
- Bluetooth adapter (built-in or USB dongle)
- Must be within Bluetooth range (~10m) of the target device

---

## Usage

ZeroPair requires root privileges for RFCOMM operations.

### Single Target (with validation)
Performs a full 4-step vulnerability validation before exploitation:
```bash
sudo python3 ZeroPair.py <MAC_ADDRESS>
```
```bash
sudo python3 ZeroPair.py 66:32:9E:2E:FD:94
```

### Single Target (skip validation)
Skips validation and attempts direct exploitation:
```bash
sudo python3 ZeroPair.py <MAC_ADDRESS> --skip
```

### Auto-Scan Mode (with validation)
Scans for all Bluetooth devices, identifies printers, validates, and exploits:
```bash
sudo python3 ZeroPair.py --scan
```

### Auto-Scan Mode (skip validation)
Fastest mode - scans and exploits without validation:
```bash
sudo python3 ZeroPair.py --scan --skip
```

### Arguments

| Argument | Short | Description |
|---|---|---|
| `target` | | Target MAC address (e.g., `66:32:9E:2E:FD:94`) |
| `--scan` | `-a` | Auto-scan mode: find and exploit all printers |
| `--skip` | `-s` | Skip vulnerability validation (faster) |

---

## How It Works

### Exploitation Chain

1. **Discovery** - Bluetooth scan identifies thermal printers by device name
2. **Validation** (optional) - 4-stage vulnerability check:
   - User-space pairing visibility via `bluetoothctl`
   - Local Bluetooth adapter identification
   - Filesystem pairing cache inspection (`/var/lib/bluetooth/`)
   - RFCOMM unauthenticated access test (critical)
3. **Channel Discovery** - SDP browse to find the RFCOMM SPP channel
4. **Connection** - RFCOMM bind to the target without pairing or PIN
5. **Command Injection** - ESC/POS or TSPL payload sent to the printer
6. **Physical Output** - Printer produces a receipt/label as proof of exploitation

### Why This Works

The affected printers implement a permissive RFCOMM accept policy at the firmware level. The Bluetooth controller does not enforce authentication or encryption for incoming SPP connections. Because the trust state is managed in firmware rather than by the host Bluetooth stack (BlueZ), standard tools like `bluetoothctl` cannot detect, inspect, or revoke the implicit trust. The device silently accepts connections from any Bluetooth host without user interaction.

---

## Example Output

```
[*] single target mode (validation enabled)

[*] ==========================================================
[*] target: 66:32:9E:2E:FD:94 (X6h-A725)
[*] model: X6h-A725
[*] ==========================================================

[*] starting vulnerability validation...
[*] testing user-space pairing visibility [DONE]
[*] identifying local bluetooth adapter [DONE]
[*] checking filesystem pairing cache [DONE]
[*] testing RFCOMM unauthenticated access [DONE]

[!] VULNERABILITY CONFIRMED
    Type: ZERO AUTHENTICATION
    Severity: CRITICAL

[*] vulnerability details:
    [+] RFCOMM accessible: YES
    [+] BlueZ visible: NO
    [+] BlueZ paired: NO
    [+] Cache exists: NO

[+] target is exploitable - proceeding with attack

[*] discovering RFCOMM channels [channel 1]
[*] establishing RFCOMM connection [CONNECTED]
[*] injecting ESC/POS payload [SUCCESS]

[*] exploitation successful - check printer output!

[+] exploitation completed successfully
```

---

## Disclaimer

This tool is for **authorized security testing** and **educational purposes** only. Unauthorized access to computer systems is **illegal**. The author assumes **no liability** and is **not responsible** for any misuse or damage caused by this tool. Use responsibly and **only on systems you own** or have **explicit permission** to test.

---

## License

MIT
