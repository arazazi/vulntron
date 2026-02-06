#!/usr/bin/env python3
"""
╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦  ╔═╗
╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝  ║ ║
 ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝   ╚╝  o╚═╝

Vultron v2.1 - Windows Security Auditor
Multi-Module: E-Inventory | Digital Forensics | NVD Intelligence | Port Scanning
Author: Cybersecurity Engineering Team
Target: Windows 10/11 & Server 2008/2012/2016/2019/2022 | Python 3.12+
"""

import os
import sys
import json
import platform
import subprocess
import ctypes
import winreg
import time
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Any
import re

# Third-party imports with fallback handling
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    print("[!] Warning: colorama not installed. Install with: pip install colorama")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] Warning: requests not installed. Install with: pip install requests")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ==================== COLOR UTILITIES ====================
class Colors:
    """Color management with fallback for missing colorama"""
    
    @staticmethod
    def critical(text: str) -> str:
        return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}" if HAS_COLORAMA else f"[CRITICAL] {text}"
    
    @staticmethod
    def warning(text: str) -> str:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if HAS_COLORAMA else f"[WARNING] {text}"
    
    @staticmethod
    def success(text: str) -> str:
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else f"[SUCCESS] {text}"
    
    @staticmethod
    def info(text: str) -> str:
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if HAS_COLORAMA else f"[INFO] {text}"
    
    @staticmethod
    def forensic(text: str) -> str:
        return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}" if HAS_COLORAMA else f"[FORENSIC] {text}"
    
    @staticmethod
    def header(text: str) -> str:
        return f"{Fore.BLUE}{Style.BRIGHT}{text}{Style.RESET_ALL}" if HAS_COLORAMA else f"\n{'='*60}\n{text}\n{'='*60}"


# ==================== PRIVILEGE CHECK ====================
def is_admin() -> bool:
    """Check if script is running with administrative privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def require_admin():
    """Ensure script runs with admin privileges"""
    if not is_admin():
        print(Colors.critical("[!] CRITICAL: This script requires Administrator privileges!"))
        print(Colors.warning("[?] Right-click and select 'Run as Administrator'"))
        sys.exit(1)


# ==================== POWERSHELL EXECUTOR ====================
class PowerShellExecutor:
    """Safe PowerShell command execution with error handling"""
    
    @staticmethod
    def execute(command: str, timeout: int = 30) -> Tuple[bool, str]:
        """
        Execute PowerShell command and return results
        Returns: (success: bool, output: str)
        """
        try:
            # Build PowerShell command with execution policy bypass
            ps_cmd = [
                'powershell.exe',
                '-NoProfile',
                '-NonInteractive',
                '-ExecutionPolicy', 'Bypass',
                '-Command', command
            ]
            
            result = subprocess.run(
                ps_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, result.stderr.strip()
                
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, f"Execution error: {str(e)}"


# ==================== MODULE 1: E-INVENTORY ====================
class EInventory:
    """Asset Discovery and System Inventory"""
    
    def __init__(self):
        self.data = {
            'os_specs': {},
            'software': [],
            'services': [],
            'patches': []
        }
    
    def collect_os_specs(self) -> Dict[str, str]:
        """Collect OS specifications and MAC address"""
        print(Colors.info("[+] Collecting OS Specifications..."))
        
        try:
            os_info = {
                'hostname': platform.node(),
                'os_name': platform.system(),
                'os_version': platform.version(),
                'os_release': platform.release(),
                'architecture': platform.machine(),
                'build': '',
                'mac_address': ''
            }
            
            # Get detailed Windows build
            ps_cmd = "(Get-WmiObject -Class Win32_OperatingSystem).BuildNumber"
            success, output = PowerShellExecutor.execute(ps_cmd)
            if success:
                os_info['build'] = output
            
            # Get MAC address
            ps_cmd = "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).MacAddress"
            success, output = PowerShellExecutor.execute(ps_cmd)
            if success:
                os_info['mac_address'] = output
            
            self.data['os_specs'] = os_info
            print(Colors.success(f"    OS: {os_info['os_name']} {os_info['os_release']} Build {os_info['build']}"))
            print(Colors.success(f"    MAC: {os_info['mac_address']}"))
            
            return os_info
            
        except Exception as e:
            print(Colors.warning(f"[!] Error collecting OS specs: {str(e)}"))
            return {}
    
    def generate_sbom(self) -> List[Dict[str, str]]:
        """Generate Software Bill of Materials from Registry"""
        print(Colors.info("[+] Generating SBOM (Software Inventory)..."))
        
        software_list = []
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for reg_path in registry_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    version = ""
                                    publisher = ""
                                    
                                    try:
                                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    except:
                                        pass
                                    
                                    try:
                                        publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                                    except:
                                        pass
                                    
                                    if name:
                                        software_list.append({
                                            'name': name,
                                            'version': version,
                                            'publisher': publisher
                                        })
                                except:
                                    pass
                        except:
                            continue
            except Exception as e:
                print(Colors.warning(f"[!] Error reading registry path {reg_path}: {str(e)}"))
        
        # Remove duplicates
        unique_software = []
        seen = set()
        for sw in software_list:
            identifier = (sw['name'], sw['version'])
            if identifier not in seen:
                seen.add(identifier)
                unique_software.append(sw)
        
        self.data['software'] = unique_software
        print(Colors.success(f"    Found {len(unique_software)} installed applications"))
        
        return unique_software
    
    def map_services(self) -> List[Dict[str, str]]:
        """Map running services and their executable paths"""
        print(Colors.info("[+] Mapping Running Services..."))
        
        ps_cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status | ConvertTo-Json"
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=45)
        
        if not success:
            print(Colors.warning(f"[!] Error mapping services: {output}"))
            return []
        
        try:
            services_data = json.loads(output)
            if isinstance(services_data, dict):
                services_data = [services_data]
            
            services = []
            for svc in services_data:
                # Get executable path
                ps_path_cmd = f"(Get-WmiObject -Class Win32_Service -Filter \"Name='{svc['Name']}'\").PathName"
                success_path, path_output = PowerShellExecutor.execute(ps_path_cmd)
                
                services.append({
                    'name': svc.get('Name', ''),
                    'display_name': svc.get('DisplayName', ''),
                    'status': svc.get('Status', ''),
                    'path': path_output if success_path else 'N/A'
                })
            
            self.data['services'] = services
            print(Colors.success(f"    Mapped {len(services)} running services"))
            
            return services
            
        except json.JSONDecodeError:
            print(Colors.warning("[!] Error parsing service data"))
            return []
    
    def list_patches(self) -> List[Dict[str, str]]:
        """List installed Windows patches (KBs)"""
        print(Colors.info("[+] Listing Installed Patches (KBs)..."))
        
        ps_cmd = "Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json"
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=45)
        
        if not success:
            print(Colors.warning(f"[!] Error listing patches: {output}"))
            return []
        
        try:
            patches_data = json.loads(output)
            if isinstance(patches_data, dict):
                patches_data = [patches_data]
            
            patches = []
            for patch in patches_data:
                patches.append({
                    'kb_id': patch.get('HotFixID', ''),
                    'description': patch.get('Description', ''),
                    'installed_on': patch.get('InstalledOn', '')
                })
            
            self.data['patches'] = patches
            print(Colors.success(f"    Found {len(patches)} installed patches"))
            
            return patches
            
        except json.JSONDecodeError:
            print(Colors.warning("[!] Error parsing patch data"))
            return []
    
    def run(self) -> Dict[str, Any]:
        """Execute complete inventory collection"""
        print(Colors.header("\n[MODULE 1] E-INVENTORY - Asset Discovery"))
        
        self.collect_os_specs()
        self.generate_sbom()
        self.map_services()
        self.list_patches()
        
        return self.data


# ==================== MODULE 2: DIGITAL FORENSICS ====================
class DigitalForensics:
    """Enhanced Digital Forensics and Triage Module"""
    
    def __init__(self):
        self.data = {
            'persistence': [],
            'execution_timeline': [],
            'event_logs': [],
            'scheduled_tasks': [],
            'startup_folders': [],
            'services_detailed': [],
            'network_connections': [],
            'browser_extensions': [],
            'wmi_persistence': [],
            'dll_hijacking': [],
            'powershell_history': [],
            'recent_files': [],
            'usb_history': [],
            'user_accounts': [],
            'firewall_rules': [],
            'open_ports': [],
            'listening_services': []
        }
    
    def check_persistence(self) -> List[Dict[str, str]]:
        """Check registry run keys for persistence mechanisms"""
        print(Colors.info("[+] Checking Registry Persistence Mechanisms..."))
        
        persistence_keys = []
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        
        for hive, path in run_keys:
            try:
                with winreg.OpenKey(hive, path) as key:
                    hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            persistence_keys.append({
                                'location': f"{hive_name}\\{path}",
                                'name': name,
                                'value': value,
                                'type': 'Registry Run Key'
                            })
                            print(Colors.forensic(f"    [?] FORENSIC: {hive_name}\\...\\{name} -> {value[:80]}"))
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                pass
            except Exception as e:
                pass
        
        self.data['persistence'] = persistence_keys
        print(Colors.success(f"    Found {len(persistence_keys)} registry persistence entries"))
        
        return persistence_keys
    
    def check_scheduled_tasks(self) -> List[Dict[str, str]]:
        """Check scheduled tasks for persistence"""
        print(Colors.info("[+] Analyzing Scheduled Tasks..."))
        
        ps_cmd = """
        Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | 
        Select-Object TaskName, State, TaskPath, 
        @{Name='Action';Expression={$_.Actions.Execute}},
        @{Name='Arguments';Expression={$_.Actions.Arguments}} | 
        ConvertTo-Json -Depth 3
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=60)
        
        if not success:
            print(Colors.warning(f"[!] Error reading scheduled tasks: {output}"))
            return []
        
        try:
            tasks_data = json.loads(output)
            if isinstance(tasks_data, dict):
                tasks_data = [tasks_data]
            
            tasks = []
            suspicious_count = 0
            
            for task in tasks_data:
                task_name = task.get('TaskName', '')
                action = task.get('Action', '')
                arguments = task.get('Arguments', '')
                
                # Flag suspicious tasks
                is_suspicious = False
                if any(keyword in str(action).lower() for keyword in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32']):
                    is_suspicious = True
                    suspicious_count += 1
                
                task_entry = {
                    'name': task_name,
                    'state': task.get('State', ''),
                    'path': task.get('TaskPath', ''),
                    'action': action,
                    'arguments': arguments,
                    'suspicious': is_suspicious
                }
                tasks.append(task_entry)
                
                if is_suspicious:
                    print(Colors.forensic(f"    [?] SUSPICIOUS TASK: {task_name} -> {action}"))
            
            self.data['scheduled_tasks'] = tasks
            print(Colors.success(f"    Analyzed {len(tasks)} scheduled tasks ({suspicious_count} suspicious)"))
            
            return tasks
            
        except json.JSONDecodeError:
            print(Colors.warning("[!] Error parsing scheduled tasks"))
            return []
    
    def check_startup_folders(self) -> List[Dict[str, str]]:
        """Check startup folders for persistence"""
        print(Colors.info("[+] Scanning Startup Folders..."))
        
        startup_paths = [
            Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
            Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"))
        ]
        
        startup_items = []
        
        for startup_path in startup_paths:
            try:
                if startup_path.exists():
                    for item in startup_path.iterdir():
                        if item.is_file():
                            startup_items.append({
                                'location': str(startup_path),
                                'filename': item.name,
                                'full_path': str(item),
                                'size': item.stat().st_size,
                                'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                            })
                            print(Colors.forensic(f"    [?] STARTUP: {item.name}"))
            except Exception as e:
                pass
        
        self.data['startup_folders'] = startup_items
        print(Colors.success(f"    Found {len(startup_items)} startup items"))
        
        return startup_items
    
    def check_network_connections(self) -> List[Dict[str, Any]]:
        """Check active network connections"""
        print(Colors.info("[+] Analyzing Network Connections..."))
        
        ps_cmd = """
        Get-NetTCPConnection -State Established,Listen | 
        Where-Object {$_.RemoteAddress -ne '::' -and $_.RemoteAddress -ne '0.0.0.0'} | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
        ConvertTo-Json -Depth 2
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=45)
        
        if not success:
            print(Colors.warning(f"[!] Error reading network connections"))
            return []
        
        try:
            conn_data = json.loads(output)
            if isinstance(conn_data, dict):
                conn_data = [conn_data]
            
            connections = []
            suspicious_count = 0
            
            for conn in conn_data[:100]:  # Limit to 100 most relevant
                remote_addr = conn.get('RemoteAddress', '')
                remote_port = conn.get('RemotePort', 0)
                
                # Flag suspicious connections
                is_suspicious = False
                if remote_port in [4444, 5555, 6666, 7777, 8888, 31337]:  # Common backdoor ports
                    is_suspicious = True
                    suspicious_count += 1
                
                connections.append({
                    'local_address': conn.get('LocalAddress', ''),
                    'local_port': conn.get('LocalPort', 0),
                    'remote_address': remote_addr,
                    'remote_port': remote_port,
                    'state': conn.get('State', ''),
                    'process_id': conn.get('OwningProcess', 0),
                    'suspicious': is_suspicious
                })
                
                if is_suspicious:
                    print(Colors.forensic(f"    [?] SUSPICIOUS CONNECTION: {remote_addr}:{remote_port}"))
            
            self.data['network_connections'] = connections
            print(Colors.success(f"    Analyzed {len(connections)} connections ({suspicious_count} suspicious)"))
            
            return connections
            
        except json.JSONDecodeError:
            print(Colors.warning("[!] Error parsing network connections"))
            return []
    
    def check_wmi_persistence(self) -> List[Dict[str, str]]:
        """Check for WMI-based persistence"""
        print(Colors.info("[+] Checking WMI Event Subscriptions..."))
        
        ps_cmd = """
        $filters = Get-WmiObject -Namespace root\\subscription -Class __EventFilter
        $consumers = Get-WmiObject -Namespace root\\subscription -Class __EventConsumer
        $bindings = Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding
        
        $result = @{
            Filters = $filters | Select-Object Name, Query
            Consumers = $consumers | Select-Object Name
            Bindings = $bindings | Select-Object Filter, Consumer
        }
        $result | ConvertTo-Json -Depth 3
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=60)
        
        if not success:
            print(Colors.warning(f"[!] WMI persistence check failed"))
            return []
        
        try:
            wmi_data = json.loads(output)
            
            filters = wmi_data.get('Filters', []) or []
            consumers = wmi_data.get('Consumers', []) or []
            bindings = wmi_data.get('Bindings', []) or []
            
            wmi_items = []
            
            for f in filters:
                if f:
                    wmi_items.append({
                        'type': 'Event Filter',
                        'name': f.get('Name', 'Unknown'),
                        'query': f.get('Query', 'N/A')
                    })
                    print(Colors.forensic(f"    [?] WMI Filter: {f.get('Name', 'Unknown')}"))
            
            self.data['wmi_persistence'] = wmi_items
            print(Colors.success(f"    Found {len(wmi_items)} WMI persistence items"))
            
            return wmi_items
            
        except Exception as e:
            print(Colors.warning(f"[!] Error parsing WMI data"))
            return []
    
    def check_powershell_history(self) -> List[Dict[str, str]]:
        """Extract PowerShell command history"""
        print(Colors.info("[+] Analyzing PowerShell History..."))
        
        history_items = []
        
        # Check PowerShell history file
        ps_history_path = Path(os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        ))
        
        try:
            if ps_history_path.exists():
                with open(ps_history_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-50:]  # Last 50 commands
                    
                    suspicious_keywords = [
                        'invoke-expression', 'iex', 'downloadstring', 'downloadfile',
                        'bypass', 'hidden', 'encodedcommand', 'noprofile',
                        'mimikatz', 'invoke-mimikatz', 'invoke-shellcode'
                    ]
                    
                    for idx, line in enumerate(lines, 1):
                        line = line.strip()
                        if line:
                            is_suspicious = any(keyword in line.lower() for keyword in suspicious_keywords)
                            
                            history_items.append({
                                'command_number': idx,
                                'command': line[:200],
                                'suspicious': is_suspicious
                            })
                            
                            if is_suspicious:
                                print(Colors.forensic(f"    [?] SUSPICIOUS CMD: {line[:80]}"))
                
                self.data['powershell_history'] = history_items
                print(Colors.success(f"    Analyzed {len(history_items)} PowerShell commands"))
            else:
                print(Colors.info("    PowerShell history file not found"))
                
        except Exception as e:
            print(Colors.warning(f"[!] Error reading PowerShell history: {str(e)}"))
        
        return history_items
    
    def check_usb_history(self) -> List[Dict[str, str]]:
        """Check USB device history"""
        print(Colors.info("[+] Checking USB Device History..."))
        
        usb_devices = []
        
        try:
            usb_key_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_key_path) as key:
                i = 0
                while True:
                    try:
                        device_key = winreg.EnumKey(key, i)
                        usb_devices.append({
                            'device': device_key,
                            'type': 'USB Storage Device'
                        })
                        print(Colors.forensic(f"    [?] USB DEVICE: {device_key[:60]}"))
                        i += 1
                    except OSError:
                        break
            
            self.data['usb_history'] = usb_devices
            print(Colors.success(f"    Found {len(usb_devices)} USB devices in history"))
            
        except FileNotFoundError:
            print(Colors.info("    No USB history found"))
        except Exception as e:
            print(Colors.warning(f"[!] Error reading USB history: {str(e)}"))
        
        return usb_devices
    
    def check_user_accounts(self) -> List[Dict[str, Any]]:
        """Analyze user accounts for anomalies"""
        print(Colors.info("[+] Analyzing User Accounts..."))
        
        ps_cmd = """
        Get-LocalUser | Select-Object Name, Enabled, 
        PasswordLastSet, PasswordExpires, LastLogon, 
        PasswordRequired, UserMayChangePassword | 
        ConvertTo-Json -Depth 2
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=45)
        
        if not success:
            print(Colors.warning(f"[!] Error reading user accounts"))
            return []
        
        try:
            users_data = json.loads(output)
            if isinstance(users_data, dict):
                users_data = [users_data]
            
            users = []
            suspicious_count = 0
            
            for user in users_data:
                username = user.get('Name', '')
                
                # Flag suspicious accounts
                is_suspicious = False
                if user.get('Enabled') and not user.get('PasswordRequired'):
                    is_suspicious = True
                    suspicious_count += 1
                
                # Check for hidden accounts ($ at end)
                if username.endswith('$') and username.lower() not in ['guest$', 'defaultaccount$']:
                    is_suspicious = True
                
                users.append({
                    'name': username,
                    'enabled': user.get('Enabled', False),
                    'password_last_set': user.get('PasswordLastSet', ''),
                    'last_logon': user.get('LastLogon', ''),
                    'password_required': user.get('PasswordRequired', True),
                    'suspicious': is_suspicious
                })
                
                if is_suspicious:
                    print(Colors.forensic(f"    [?] SUSPICIOUS ACCOUNT: {username}"))
            
            self.data['user_accounts'] = users
            print(Colors.success(f"    Analyzed {len(users)} user accounts ({suspicious_count} suspicious)"))
            
            return users
            
        except json.JSONDecodeError:
            print(Colors.warning("[!] Error parsing user accounts"))
            return []
    
    def check_firewall_rules(self) -> List[Dict[str, str]]:
        """Check firewall rules for suspicious configurations"""
        print(Colors.info("[+] Analyzing Firewall Rules..."))
        
        ps_cmd = """
        Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 'Inbound'} | 
        Select-Object DisplayName, Direction, Action, Enabled | 
        ConvertTo-Json -Depth 2
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=45)
        
        if not success:
            print(Colors.warning(f"[!] Error reading firewall rules"))
            return []
        
        try:
            rules_data = json.loads(output)
            if isinstance(rules_data, dict):
                rules_data = [rules_data]
            
            rules = []
            allow_count = 0
            
            for rule in rules_data[:100]:  # Limit to 100
                if rule.get('Action') == 'Allow':
                    allow_count += 1
                    rules.append({
                        'name': rule.get('DisplayName', ''),
                        'direction': rule.get('Direction', ''),
                        'action': rule.get('Action', ''),
                        'enabled': rule.get('Enabled', False)
                    })
            
            self.data['firewall_rules'] = rules
            print(Colors.success(f"    Analyzed {len(rules)} inbound Allow rules"))
            
            return rules
            
        except json.JSONDecodeError:
            print(Colors.warning("[!] Error parsing firewall rules"))
            return []
    
    def scan_open_ports(self) -> List[Dict[str, Any]]:
        """Scan for open/listening ports and identify services"""
        print(Colors.info("[+] Scanning Open Ports and Services..."))
        
        # Get listening TCP and UDP ports with process information
        ps_cmd = """
        $tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
               Select-Object LocalAddress, LocalPort, State, OwningProcess
        
        $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | 
               Select-Object LocalAddress, LocalPort, OwningProcess
        
        $result = @{
            TCP = $tcp
            UDP = $udp
        }
        $result | ConvertTo-Json -Depth 3
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=60)
        
        if not success:
            print(Colors.warning(f"[!] Error scanning ports"))
            return []
        
        open_ports = []
        listening_services = []
        
        try:
            ports_data = json.loads(output)
            
            # Process TCP listening ports
            tcp_ports = ports_data.get('TCP', [])
            if isinstance(tcp_ports, dict):
                tcp_ports = [tcp_ports]
            
            # Process UDP listening ports
            udp_ports = ports_data.get('UDP', [])
            if isinstance(udp_ports, dict):
                udp_ports = [udp_ports]
            
            # Common service port mappings with known vulnerabilities
            port_services = {
                21: {'name': 'FTP', 'risk': 'HIGH', 'vulns': ['Anonymous access', 'Clear text credentials']},
                22: {'name': 'SSH', 'risk': 'MEDIUM', 'vulns': ['Brute force', 'Weak keys']},
                23: {'name': 'Telnet', 'risk': 'CRITICAL', 'vulns': ['Clear text credentials', 'No encryption']},
                25: {'name': 'SMTP', 'risk': 'MEDIUM', 'vulns': ['Open relay', 'Spam']},
                53: {'name': 'DNS', 'risk': 'MEDIUM', 'vulns': ['DNS amplification', 'Cache poisoning']},
                80: {'name': 'HTTP', 'risk': 'LOW', 'vulns': ['Unencrypted web traffic']},
                110: {'name': 'POP3', 'risk': 'HIGH', 'vulns': ['Clear text credentials']},
                135: {'name': 'MS-RPC', 'risk': 'HIGH', 'vulns': ['Remote code execution', 'MS08-067']},
                139: {'name': 'NetBIOS', 'risk': 'HIGH', 'vulns': ['SMB relay', 'Information disclosure']},
                143: {'name': 'IMAP', 'risk': 'MEDIUM', 'vulns': ['Clear text credentials']},
                389: {'name': 'LDAP', 'risk': 'MEDIUM', 'vulns': ['Anonymous bind', 'LDAP injection']},
                443: {'name': 'HTTPS', 'risk': 'LOW', 'vulns': ['SSL/TLS misconfig']},
                445: {'name': 'SMB', 'risk': 'CRITICAL', 'vulns': ['EternalBlue', 'SMBGhost', 'WannaCry']},
                1433: {'name': 'MS-SQL', 'risk': 'HIGH', 'vulns': ['SQL injection', 'Weak passwords']},
                1521: {'name': 'Oracle DB', 'risk': 'HIGH', 'vulns': ['TNS poisoning']},
                3306: {'name': 'MySQL', 'risk': 'HIGH', 'vulns': ['SQL injection', 'Weak passwords']},
                3389: {'name': 'RDP', 'risk': 'CRITICAL', 'vulns': ['BlueKeep', 'Brute force', 'Pass-the-hash']},
                5432: {'name': 'PostgreSQL', 'risk': 'MEDIUM', 'vulns': ['SQL injection']},
                5900: {'name': 'VNC', 'risk': 'HIGH', 'vulns': ['Weak passwords', 'No encryption']},
                8080: {'name': 'HTTP-Alt', 'risk': 'LOW', 'vulns': ['Unencrypted web traffic']},
                8443: {'name': 'HTTPS-Alt', 'risk': 'LOW', 'vulns': ['SSL/TLS misconfig']},
            }
            
            # Process TCP ports
            seen_ports = set()
            for port_info in tcp_ports:
                if not port_info:
                    continue
                    
                port = port_info.get('LocalPort', 0)
                address = port_info.get('LocalAddress', '0.0.0.0')
                pid = port_info.get('OwningProcess', 0)
                
                if port and (port, 'TCP') not in seen_ports:
                    seen_ports.add((port, 'TCP'))
                    
                    # Get process information
                    process_name = self._get_process_name(pid)
                    service_info = port_services.get(port, {'name': 'Unknown', 'risk': 'LOW', 'vulns': []})
                    
                    # Determine if externally accessible
                    is_external = address in ['0.0.0.0', '::']
                    
                    port_entry = {
                        'port': port,
                        'protocol': 'TCP',
                        'address': address,
                        'service': service_info['name'],
                        'process': process_name,
                        'pid': pid,
                        'risk_level': service_info['risk'],
                        'known_vulns': service_info['vulns'],
                        'external_access': is_external,
                        'state': 'LISTENING'
                    }
                    
                    open_ports.append(port_entry)
                    
                    # Flag high-risk or critical ports
                    if service_info['risk'] in ['HIGH', 'CRITICAL']:
                        print(Colors.critical(f"    [!] {service_info['risk']}: Port {port}/TCP ({service_info['name']}) - {process_name}"))
                        if service_info['vulns']:
                            print(Colors.warning(f"        Known vulns: {', '.join(service_info['vulns'][:3])}"))
                    elif port in port_services:
                        print(Colors.forensic(f"    [?] Port {port}/TCP ({service_info['name']}) - {process_name}"))
            
            # Process UDP ports
            for port_info in udp_ports:
                if not port_info:
                    continue
                    
                port = port_info.get('LocalPort', 0)
                address = port_info.get('LocalAddress', '0.0.0.0')
                pid = port_info.get('OwningProcess', 0)
                
                if port and (port, 'UDP') not in seen_ports:
                    seen_ports.add((port, 'UDP'))
                    
                    process_name = self._get_process_name(pid)
                    service_info = port_services.get(port, {'name': 'Unknown', 'risk': 'LOW', 'vulns': []})
                    
                    is_external = address in ['0.0.0.0', '::']
                    
                    port_entry = {
                        'port': port,
                        'protocol': 'UDP',
                        'address': address,
                        'service': service_info['name'],
                        'process': process_name,
                        'pid': pid,
                        'risk_level': service_info['risk'],
                        'known_vulns': service_info['vulns'],
                        'external_access': is_external,
                        'state': 'LISTENING'
                    }
                    
                    open_ports.append(port_entry)
                    
                    if service_info['risk'] in ['HIGH', 'CRITICAL']:
                        print(Colors.critical(f"    [!] {service_info['risk']}: Port {port}/UDP ({service_info['name']}) - {process_name}"))
            
            # Sort by risk level and port number
            risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            open_ports.sort(key=lambda x: (risk_order.get(x['risk_level'], 4), x['port']))
            
            # Get detailed service information for listening services
            listening_services = self._get_listening_services_details(open_ports)
            
            self.data['open_ports'] = open_ports
            self.data['listening_services'] = listening_services
            
            critical_count = len([p for p in open_ports if p['risk_level'] == 'CRITICAL'])
            high_count = len([p for p in open_ports if p['risk_level'] == 'HIGH'])
            
            print(Colors.success(f"    Found {len(open_ports)} open ports ({critical_count} critical, {high_count} high risk)"))
            
            return open_ports
            
        except json.JSONDecodeError as e:
            print(Colors.warning(f"[!] Error parsing port data: {str(e)}"))
            return []
        except Exception as e:
            print(Colors.warning(f"[!] Error in port scan: {str(e)}"))
            return []
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        if not pid:
            return "Unknown"
        
        try:
            ps_cmd = f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).Name"
            success, output = PowerShellExecutor.execute(ps_cmd, timeout=5)
            if success and output:
                return output.strip()
        except:
            pass
        
        return f"PID:{pid}"
    
    def _get_listening_services_details(self, open_ports: List[Dict]) -> List[Dict[str, Any]]:
        """Get detailed information about services running on open ports"""
        print(Colors.info("[+] Identifying Service Versions..."))
        
        services = []
        
        # Get detailed service information
        ps_cmd = """
        Get-WmiObject Win32_Service | 
        Where-Object {$_.State -eq 'Running'} | 
        Select-Object Name, DisplayName, PathName, StartMode, ProcessId | 
        ConvertTo-Json -Depth 2
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=60)
        
        if not success:
            return services
        
        try:
            services_data = json.loads(output)
            if isinstance(services_data, dict):
                services_data = [services_data]
            
            # Map PIDs to ports
            pid_to_ports = {}
            for port in open_ports:
                pid = port.get('pid')
                if pid:
                    if pid not in pid_to_ports:
                        pid_to_ports[pid] = []
                    pid_to_ports[pid].append(port)
            
            # Match services to ports
            for svc in services_data:
                pid = svc.get('ProcessId')
                if pid in pid_to_ports:
                    ports = pid_to_ports[pid]
                    
                    # Extract version from executable path if possible
                    path = svc.get('PathName', '')
                    version = self._extract_version_from_path(path)
                    
                    service_entry = {
                        'name': svc.get('Name', ''),
                        'display_name': svc.get('DisplayName', ''),
                        'path': path,
                        'version': version,
                        'start_mode': svc.get('StartMode', ''),
                        'pid': pid,
                        'ports': [{'port': p['port'], 'protocol': p['protocol'], 'service': p['service']} for p in ports]
                    }
                    
                    services.append(service_entry)
                    
                    # Display service with version
                    port_list = ', '.join([f"{p['port']}/{p['protocol']}" for p in ports])
                    if version:
                        print(Colors.forensic(f"    [?] {svc.get('DisplayName', '')} v{version} on ports: {port_list}"))
                    else:
                        print(Colors.forensic(f"    [?] {svc.get('DisplayName', '')} on ports: {port_list}"))
            
            print(Colors.success(f"    Identified {len(services)} services with open ports"))
            
            return services
            
        except Exception as e:
            print(Colors.warning(f"[!] Error identifying service versions: {str(e)}"))
            return services
    
    def _extract_version_from_path(self, path: str) -> str:
        """Try to extract version number from executable path or use file version"""
        if not path:
            return "Unknown"
        
        try:
            # Clean up the path
            path = path.strip('"').split()[0]
            
            if not os.path.exists(path):
                return "Unknown"
            
            # Try to get file version using PowerShell
            ps_cmd = f"(Get-Item '{path}').VersionInfo.FileVersion"
            success, output = PowerShellExecutor.execute(ps_cmd, timeout=5)
            
            if success and output and output.strip():
                return output.strip()
            
            # Fallback: try to extract version from path string
            version_pattern = r'v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)'
            match = re.search(version_pattern, path)
            if match:
                return match.group(1)
            
        except Exception as e:
            pass
        
        return "Unknown"
    
    def execution_timeline(self) -> List[Dict[str, str]]:
        """Parse Prefetch directory for recently executed programs"""
        print(Colors.info("[+] Building Execution Timeline from Prefetch..."))
        
        prefetch_path = Path(r"C:\Windows\Prefetch")
        timeline = []
        
        try:
            if prefetch_path.exists():
                prefetch_files = sorted(
                    prefetch_path.glob("*.pf"),
                    key=lambda x: x.stat().st_mtime,
                    reverse=True
                )[:50]  # Increased to 50
                
                for pf_file in prefetch_files:
                    stat = pf_file.stat()
                    timeline.append({
                        'program': pf_file.stem.replace('.pf', ''),
                        'last_executed': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'file': pf_file.name
                    })
                    print(Colors.forensic(f"    [?] {pf_file.stem} - {datetime.fromtimestamp(stat.st_mtime)}"))
                
                self.data['execution_timeline'] = timeline
                print(Colors.success(f"    Parsed {len(timeline)} recent executions"))
            else:
                print(Colors.warning("[!] Prefetch directory not accessible"))
                
        except Exception as e:
            print(Colors.warning(f"[!] Error parsing Prefetch: {str(e)}"))
        
        return timeline
    
    def watch_event_logs(self) -> List[Dict[str, Any]]:
        """Extract critical/error events from Windows Event Log"""
        print(Colors.info("[+] Watching Event Logs (Critical/Error)..."))
        
        ps_cmd = """
        Get-WinEvent -FilterHashtable @{LogName='System','Security'; Level=1,2} -MaxEvents 20 -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message, LogName | 
        ConvertTo-Json -Depth 2
        """
        
        success, output = PowerShellExecutor.execute(ps_cmd, timeout=60)
        
        if not success:
            print(Colors.warning(f"[!] Error reading event logs: {output}"))
            return []
        
        try:
            events_data = json.loads(output)
            if isinstance(events_data, dict):
                events_data = [events_data]
            
            events = []
            for event in events_data:
                msg = event.get('Message', '')[:300]
                events.append({
                    'time': event.get('TimeCreated', ''),
                    'event_id': event.get('Id', ''),
                    'level': event.get('LevelDisplayName', ''),
                    'log_name': event.get('LogName', ''),
                    'message': msg
                })
                print(Colors.forensic(f"    [?] {event.get('LogName')} Event {event.get('Id')} - {msg[:60]}..."))
            
            self.data['event_logs'] = events
            print(Colors.success(f"    Extracted {len(events)} critical/error events"))
            
            return events
            
        except json.JSONDecodeError:
            print(Colors.warning("[!] Error parsing event log data"))
            return []
    
    def run(self) -> Dict[str, Any]:
        """Execute complete enhanced forensic analysis"""
        print(Colors.header("\n[MODULE 2] DIGITAL FORENSICS - Advanced Triage Analysis"))
        
        # Core forensics
        self.check_persistence()
        self.check_scheduled_tasks()
        self.check_startup_folders()
        self.execution_timeline()
        self.watch_event_logs()
        
        # Network and port analysis
        self.scan_open_ports()  # NEW: Comprehensive port scanning
        self.check_network_connections()
        
        # Advanced forensics
        self.check_wmi_persistence()
        self.check_powershell_history()
        self.check_usb_history()
        self.check_user_accounts()
        self.check_firewall_rules()
        
        return self.data


# ==================== MODULE 3: NVD INTELLIGENCE ====================
class NVDIntelligence:
    """NVD API 2.0 Vulnerability Intelligence"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.data = {
            'cpe': '',
            'vulnerabilities': [],
            'kev_vulns': []
        }
    
    def build_cpe(self, os_info: Dict[str, str]) -> str:
        """Generate CPE 2.3 string for the operating system"""
        print(Colors.info("[+] Building CPE String..."))
        
        os_name = os_info.get('os_name', 'windows').lower()
        os_release = os_info.get('os_release', '10').lower()
        build = os_info.get('build', '')
        os_version = os_info.get('os_version', '').lower()
        
        # Detect Windows Server versions
        if 'server' in os_version or 'server' in os_name:
            # Map server versions to CPE
            if '2022' in os_version or '20348' in build:
                cpe = f"cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"
            elif '2019' in os_version or '17763' in build:
                cpe = f"cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"
            elif '2016' in os_version or '14393' in build:
                cpe = f"cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*"
            elif '2012' in os_version:
                if 'r2' in os_version:
                    cpe = f"cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*"
                else:
                    cpe = f"cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*"
            elif '2008' in os_version:
                if 'r2' in os_version:
                    cpe = f"cpe:2.3:o:microsoft:windows_server_2008:r2:*:*:*:*:*:*:*"
                else:
                    cpe = f"cpe:2.3:o:microsoft:windows_server_2008:-:*:*:*:*:*:*:*"
            else:
                cpe = f"cpe:2.3:o:microsoft:windows_server:-:*:*:*:*:*:*:*"
            
            print(Colors.success(f"    Detected: Windows Server"))
        else:
            # Map Windows desktop releases to CPE format
            if 'windows' in os_name:
                if os_release == '10':
                    cpe = f"cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"
                elif os_release == '11':
                    cpe = f"cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*"
                else:
                    cpe = f"cpe:2.3:o:microsoft:windows_{os_release}:-:*:*:*:*:*:*:*"
            else:
                cpe = f"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
        
        self.data['cpe'] = cpe
        print(Colors.success(f"    CPE: {cpe}"))
        
        return cpe
    
    def query_nvd(self, days: int = None, include_historical: bool = True) -> List[Dict[str, Any]]:
        """
        Query NVD API 2.0 for vulnerabilities
        
        Args:
            days: Number of days to look back (None for all time)
            include_historical: If True, queries from 2015 onwards for comprehensive coverage
        """
        if not HAS_REQUESTS:
            print(Colors.warning("[!] requests library not available. Skipping NVD query."))
            return []
        
        all_vulnerabilities = []
        kev_vulns = []
        
        # For comprehensive coverage, query in chunks
        if include_historical:
            print(Colors.info(f"[+] Querying NVD API (Comprehensive Historical Scan)..."))
            print(Colors.info("    This may take 2-3 minutes for complete coverage..."))
            
            # Query in yearly chunks from 2015 to present for better coverage
            current_year = datetime.now().year
            start_year = 2015  # Windows 10 released in 2015
            
            try:
                for year in range(start_year, current_year + 1):
                    year_start = f"{year}-01-01T00:00:00.000"
                    year_end = f"{year}-12-31T23:59:59.999"
                    
                    print(Colors.info(f"    Scanning {year}..."))
                    
                    params = {
                        'pubStartDate': year_start,
                        'pubEndDate': year_end,
                        'keywordSearch': 'Microsoft Windows',
                        'resultsPerPage': 2000  # Max results per page
                    }
                    
                    headers = {}
                    if self.api_key:
                        headers['apiKey'] = self.api_key
                    
                    # Make API request with retry logic
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            response = requests.get(
                                self.base_url,
                                params=params,
                                headers=headers,
                                timeout=45
                            )
                            
                            if response.status_code == 200:
                                data = response.json()
                                year_vulns = data.get('vulnerabilities', [])
                                
                                for vuln in year_vulns:
                                    processed_vuln = self._process_vulnerability(vuln)
                                    if processed_vuln:
                                        all_vulnerabilities.append(processed_vuln)
                                        
                                        if processed_vuln['is_kev']:
                                            kev_vulns.append(processed_vuln)
                                            print(Colors.critical(f"    [!] CISA KEV: {processed_vuln['cve_id']} ({year})"))
                                
                                print(Colors.success(f"    {year}: Found {len(year_vulns)} CVEs"))
                                break  # Success, exit retry loop
                                
                            elif response.status_code == 429:
                                wait_time = 6 * (attempt + 1)
                                print(Colors.warning(f"    Rate limited, waiting {wait_time}s..."))
                                import time
                                time.sleep(wait_time)
                            else:
                                print(Colors.warning(f"    {year}: API returned {response.status_code}"))
                                break
                                
                        except requests.exceptions.Timeout:
                            if attempt < max_retries - 1:
                                print(Colors.warning(f"    Timeout, retrying ({attempt + 1}/{max_retries})..."))
                                import time
                                time.sleep(3)
                            else:
                                print(Colors.warning(f"    {year}: Timeout after {max_retries} attempts"))
                                break
                        except Exception as e:
                            print(Colors.warning(f"    {year}: Error - {str(e)}"))
                            break
                    
                    # Rate limiting: wait between years if no API key
                    if not self.api_key and year < current_year:
                        import time
                        time.sleep(6)  # NVD rate limit: 5 requests per 30 seconds
                
            except Exception as e:
                print(Colors.warning(f"[!] Error in historical scan: {str(e)}"))
        
        else:
            # Quick scan - last N days only
            print(Colors.info(f"[+] Querying NVD API (Last {days} days)..."))
            
            try:
                end_date = datetime.now()
                start_date = end_date - timedelta(days=days)
                
                pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000")
                pub_end = end_date.strftime("%Y-%m-%dT23:59:59.999")
                
                params = {
                    'pubStartDate': pub_start,
                    'pubEndDate': pub_end,
                    'keywordSearch': 'Microsoft Windows',
                    'resultsPerPage': 2000
                }
                
                headers = {}
                if self.api_key:
                    headers['apiKey'] = self.api_key
                
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        processed_vuln = self._process_vulnerability(vuln)
                        if processed_vuln:
                            all_vulnerabilities.append(processed_vuln)
                            
                            if processed_vuln['is_kev']:
                                kev_vulns.append(processed_vuln)
                                print(Colors.critical(f"    [!] CISA KEV: {processed_vuln['cve_id']}"))
                
            except Exception as e:
                print(Colors.warning(f"[!] Error querying NVD: {str(e)}"))
        
        self.data['vulnerabilities'] = all_vulnerabilities
        self.data['kev_vulns'] = kev_vulns
        
        print(Colors.success(f"\n    Total CVEs Retrieved: {len(all_vulnerabilities)}"))
        print(Colors.critical(f"    Total CISA KEV Entries: {len(kev_vulns)}"))
        
        return all_vulnerabilities
    
    def _process_vulnerability(self, vuln: Dict) -> Optional[Dict[str, Any]]:
        """Process a single vulnerability from NVD API response"""
        try:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            # Extract description
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract CVSS score
            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            cvss_severity = 'UNKNOWN'
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                # Convert CVSS v2 to severity
                if cvss_score >= 7.0:
                    cvss_severity = 'HIGH'
                elif cvss_score >= 4.0:
                    cvss_severity = 'MEDIUM'
                else:
                    cvss_severity = 'LOW'
            
            # Check for CISA KEV flag
            is_kev = cve_data.get('cisaVulnerabilityName') is not None or \
                     cve_data.get('cisaExploitAdd') is not None
            
            # Extract CPE configurations for better matching
            configurations = cve_data.get('configurations', [])
            affected_products = []
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable'):
                            cpe = cpe_match.get('criteria', '')
                            if 'microsoft:windows' in cpe.lower():
                                affected_products.append(cpe)
            
            return {
                'cve_id': cve_id,
                'description': description[:400],
                'cvss_score': cvss_score,
                'severity': cvss_severity,
                'published': cve_data.get('published', ''),
                'is_kev': is_kev,
                'affected_products': affected_products[:10]  # Limit for size
            }
            
        except Exception as e:
            return None
    
    def run(self, os_info: Dict[str, str], quick_scan: bool = False) -> Dict[str, Any]:
        """
        Execute NVD intelligence gathering
        
        Args:
            os_info: Operating system information
            quick_scan: If True, only scan last 120 days. If False, comprehensive historical scan.
        """
        print(Colors.header("\n[MODULE 3] NVD INTELLIGENCE - Vulnerability Discovery"))
        
        self.build_cpe(os_info)
        
        if quick_scan:
            self.query_nvd(days=120, include_historical=False)
        else:
            # Default: Comprehensive scan for ALL historical CVEs
            self.query_nvd(include_historical=True)
        
        return self.data


# ==================== MODULE 4: AUDIT & LOGIC GATES ====================
class AuditEngine:
    """Vulnerability matching and risk assessment engine"""
    
    def __init__(self, inventory_data: Dict, forensics_data: Dict, nvd_data: Dict):
        self.inventory = inventory_data
        self.forensics = forensics_data
        self.nvd = nvd_data
        self.findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'active_risks': [],
            'port_vulnerabilities': []
        }
    
    def match_vulnerabilities(self):
        """Match NVD vulnerabilities against installed patches, services, and open ports"""
        print(Colors.header("\n[MODULE 4] AUDIT ENGINE - Logic Gates & Matching"))
        print(Colors.info("[+] Analyzing Vulnerability Matches..."))
        
        installed_kbs = {patch['kb_id'] for patch in self.inventory.get('patches', [])}
        vulnerabilities = self.nvd.get('vulnerabilities', [])
        services = {svc['name'].lower(): svc for svc in self.inventory.get('services', [])}
        open_ports = self.forensics.get('open_ports', [])
        
        for vuln in vulnerabilities:
            cve_id = vuln['cve_id']
            cvss_score = vuln['cvss_score']
            severity = vuln['severity']
            is_kev = vuln['is_kev']
            
            # Extract KB references from description (basic pattern matching)
            kb_pattern = r'KB\d{7}'
            required_kbs = re.findall(kb_pattern, vuln['description'])
            
            # Logic Gate 1: Missing Patch Check
            if required_kbs:
                missing_kbs = [kb for kb in required_kbs if kb not in installed_kbs]
                
                if missing_kbs:
                    finding = {
                        'cve_id': cve_id,
                        'type': 'MISSING_PATCH',
                        'severity': severity,
                        'cvss': cvss_score,
                        'is_kev': is_kev,
                        'missing_kb': missing_kbs,
                        'description': vuln['description']
                    }
                    
                    if is_kev or cvss_score >= 9.0:
                        self.findings['critical'].append(finding)
                        print(Colors.critical(f"    [!] CRITICAL: {cve_id} - Missing KB: {', '.join(missing_kbs)}"))
                        if is_kev:
                            print(Colors.critical(f"        ⚠️  CISA KEV - IMMEDIATE ACTION REQUIRED!"))
                    elif cvss_score >= 7.0:
                        self.findings['high'].append(finding)
                        print(Colors.warning(f"    [!] HIGH: {cve_id} - Missing KB: {', '.join(missing_kbs)}"))
                    else:
                        self.findings['medium'].append(finding)
            
            # Logic Gate 2: Active Service Risk
            desc_lower = vuln['description'].lower()
            for svc_name, svc_info in services.items():
                if svc_name in desc_lower or svc_info['display_name'].lower() in desc_lower:
                    finding = {
                        'cve_id': cve_id,
                        'type': 'ACTIVE_SERVICE_RISK',
                        'service': svc_info['display_name'],
                        'severity': severity,
                        'cvss': cvss_score,
                        'is_kev': is_kev,
                        'description': vuln['description']
                    }
                    self.findings['active_risks'].append(finding)
                    print(Colors.warning(f"    [!] ACTIVE RISK: Service '{svc_info['display_name']}' - {cve_id}"))
            
            # Logic Gate 3: Open Port Vulnerability Correlation (NEW)
            self._match_port_vulnerabilities(vuln, open_ports)
        
        # Summary
        print(Colors.success(f"\n[+] Audit Complete:"))
        print(Colors.critical(f"    Critical Findings: {len(self.findings['critical'])}"))
        print(Colors.warning(f"    High Findings: {len(self.findings['high'])}"))
        print(Colors.info(f"    Medium Findings: {len(self.findings['medium'])}"))
        print(Colors.warning(f"    Active Risks: {len(self.findings['active_risks'])}"))
        print(Colors.critical(f"    Port Vulnerabilities: {len(self.findings['port_vulnerabilities'])}"))
        
        return self.findings
    
    def _match_port_vulnerabilities(self, vuln: Dict, open_ports: List[Dict]):
        """Match CVEs to open ports based on service names and known vulnerabilities"""
        cve_id = vuln['cve_id']
        desc_lower = vuln['description'].lower()
        
        # Port/service to CVE keywords mapping
        port_vuln_keywords = {
            21: ['ftp', 'file transfer protocol'],
            22: ['ssh', 'openssh', 'secure shell'],
            23: ['telnet'],
            25: ['smtp', 'sendmail', 'postfix', 'mail server'],
            53: ['dns', 'bind', 'domain name'],
            80: ['http', 'apache', 'nginx', 'iis', 'web server'],
            110: ['pop3', 'pop', 'post office protocol'],
            135: ['rpc', 'remote procedure call', 'msrpc'],
            139: ['netbios', 'smb session'],
            143: ['imap', 'mail'],
            389: ['ldap', 'active directory'],
            443: ['https', 'ssl', 'tls', 'apache', 'nginx', 'iis'],
            445: ['smb', 'server message block', 'cifs', 'samba', 'eternalblue', 'wannacry', 'smbghost'],
            1433: ['sql server', 'mssql', 't-sql'],
            1521: ['oracle', 'tns'],
            3306: ['mysql', 'mariadb'],
            3389: ['rdp', 'remote desktop', 'terminal services', 'bluekeep'],
            5432: ['postgresql', 'postgres'],
            5900: ['vnc', 'virtual network computing'],
            8080: ['tomcat', 'jetty', 'http'],
            8443: ['https', 'ssl', 'tls']
        }
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Check if this port's keywords appear in the CVE
            keywords = port_vuln_keywords.get(port, [service.lower()])
            
            if any(keyword in desc_lower for keyword in keywords):
                # This CVE likely affects this open port/service
                finding = {
                    'cve_id': cve_id,
                    'type': 'PORT_VULNERABILITY',
                    'port': port,
                    'protocol': port_info['protocol'],
                    'service': service,
                    'process': port_info['process'],
                    'severity': vuln['severity'],
                    'cvss': vuln['cvss_score'],
                    'is_kev': vuln['is_kev'],
                    'risk_level': port_info['risk_level'],
                    'external_access': port_info['external_access'],
                    'description': vuln['description'][:300]
                }
                
                self.findings['port_vulnerabilities'].append(finding)
                
                if vuln['is_kev'] or vuln['cvss_score'] >= 9.0:
                    print(Colors.critical(
                        f"    [!] PORT VULN: {cve_id} affects {service} on port {port}/{port_info['protocol']} "
                        f"(CVSS: {vuln['cvss_score']})"
                    ))
                elif vuln['cvss_score'] >= 7.0:
                    print(Colors.warning(
                        f"    [!] PORT VULN: {cve_id} affects {service} on port {port}/{port_info['protocol']}"
                    ))


# ==================== REPORT GENERATOR ====================
class ReportGenerator:
    """Generate JSON and HTML reports"""
    
    @staticmethod
    def generate_json(inventory: Dict, forensics: Dict, nvd: Dict, audit: Dict, filename: str = "vultron_report.json"):
        """Generate comprehensive JSON report"""
        print(Colors.info(f"\n[+] Generating JSON Report: {filename}"))
        
        report = {
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'scanner': 'Vultron v2.0',
                'target_os': inventory.get('os_specs', {}).get('os_name', 'Unknown')
            },
            'inventory': inventory,
            'forensics': forensics,
            'nvd_intelligence': nvd,
            'audit_findings': audit
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(Colors.success(f"    JSON report saved: {filename}"))
        except Exception as e:
            print(Colors.warning(f"[!] Error saving JSON report: {str(e)}"))
    
    @staticmethod
    def generate_html(inventory: Dict, forensics: Dict, nvd: Dict, audit: Dict, filename: str = "vultron_report.html"):
        """Generate professional HTML report"""
        print(Colors.info(f"[+] Generating HTML Report: {filename}"))
        
        os_specs = inventory.get('os_specs', {})
        
        # Count findings
        critical_count = len(audit.get('critical', []))
        high_count = len(audit.get('high', []))
        medium_count = len(audit.get('medium', []))
        active_risk_count = len(audit.get('active_risks', []))
        kev_count = len(nvd.get('kev_vulns', []))
        port_vuln_count = len(audit.get('port_vulnerabilities', []))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vultron v2.0 - Security Audit Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .scan-info {{
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 3px solid #e9ecef;
        }}
        
        .scan-info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .info-item {{
            padding: 10px;
        }}
        
        .info-item label {{
            font-weight: bold;
            color: #495057;
            display: block;
            margin-bottom: 5px;
        }}
        
        .info-item value {{
            color: #212529;
        }}
        
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .metric-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        
        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }}
        
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .metric-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .info {{ color: #17a2b8; }}
        .success {{ color: #28a745; }}
        
        .section {{
            padding: 40px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #2a5298;
            border-bottom: 3px solid #2a5298;
            padding-bottom: 10px;
        }}
        
        .finding {{
            background: #fff;
            border-left: 4px solid #dee2e6;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .finding.critical {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        
        .finding.high {{
            border-left-color: #fd7e14;
            background: #fff8f0;
        }}
        
        .finding.medium {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .cve-id {{
            font-weight: bold;
            font-size: 1.1em;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }}
        
        .badge.critical {{ background: #dc3545; }}
        .badge.high {{ background: #fd7e14; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .badge.kev {{ background: #e83e8c; animation: pulse 2s infinite; }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: #2a5298;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .footer {{
            background: #212529;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VULTRON v2.0</h1>
            <div class="subtitle">Windows Security Audit Report</div>
            <div class="subtitle">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
        </div>
        
        <div class="scan-info">
            <div class="scan-info-grid">
                <div class="info-item">
                    <label>Hostname:</label>
                    <value>{os_specs.get('hostname', 'N/A')}</value>
                </div>
                <div class="info-item">
                    <label>Operating System:</label>
                    <value>{os_specs.get('os_name', 'N/A')} {os_specs.get('os_release', 'N/A')}</value>
                </div>
                <div class="info-item">
                    <label>Build:</label>
                    <value>{os_specs.get('build', 'N/A')}</value>
                </div>
                <div class="info-item">
                    <label>Architecture:</label>
                    <value>{os_specs.get('architecture', 'N/A')}</value>
                </div>
                <div class="info-item">
                    <label>MAC Address:</label>
                    <value>{os_specs.get('mac_address', 'N/A')}</value>
                </div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="metric-card">
                <div class="metric-value critical">{critical_count}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric-card">
                <div class="metric-value high">{high_count}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric-card">
                <div class="metric-value medium">{medium_count}</div>
                <div class="metric-label">Medium</div>
            </div>
            <div class="metric-card">
                <div class="metric-value info">{active_risk_count}</div>
                <div class="metric-label">Active Risks</div>
            </div>
            <div class="metric-card">
                <div class="metric-value critical">{kev_count}</div>
                <div class="metric-label">CISA KEV</div>
            </div>
            <div class="metric-card">
                <div class="metric-value high">{port_vuln_count}</div>
                <div class="metric-label">Port Vulns</div>
            </div>
        </div>
"""
        
        # Critical Findings Section
        html_content += """
        <div class="section">
            <h2>🔴 Critical Findings</h2>
"""
        
        if audit.get('critical'):
            for finding in audit['critical']:
                kev_badge = '<span class="badge kev">CISA KEV</span>' if finding.get('is_kev') else ''
                html_content += f"""
            <div class="finding critical">
                <div class="finding-header">
                    <span class="cve-id">{finding['cve_id']}</span>
                    <div>
                        <span class="badge critical">CVSS {finding['cvss']}</span>
                        {kev_badge}
                    </div>
                </div>
                <div><strong>Missing KB:</strong> {', '.join(finding.get('missing_kb', []))}</div>
                <div><strong>Description:</strong> {finding['description'][:200]}...</div>
            </div>
"""
        else:
            html_content += '<div class="no-data">✅ No critical findings detected</div>'
        
        html_content += "</div>"
        
        # High Findings Section
        html_content += """
        <div class="section">
            <h2>🟠 High Severity Findings</h2>
"""
        
        if audit.get('high'):
            for finding in audit['high']:
                html_content += f"""
            <div class="finding high">
                <div class="finding-header">
                    <span class="cve-id">{finding['cve_id']}</span>
                    <span class="badge high">CVSS {finding['cvss']}</span>
                </div>
                <div><strong>Missing KB:</strong> {', '.join(finding.get('missing_kb', []))}</div>
                <div><strong>Description:</strong> {finding['description'][:200]}...</div>
            </div>
"""
        else:
            html_content += '<div class="no-data">✅ No high severity findings detected</div>'
        
        html_content += "</div>"
        
        # Active Service Risks
        html_content += """
        <div class="section">
            <h2>⚠️ Active Service Risks</h2>
"""
        
        if audit.get('active_risks'):
            for risk in audit['active_risks']:
                html_content += f"""
            <div class="finding medium">
                <div class="finding-header">
                    <span class="cve-id">{risk['cve_id']}</span>
                    <span class="badge medium">Active</span>
                </div>
                <div><strong>Affected Service:</strong> {risk['service']}</div>
                <div><strong>CVSS:</strong> {risk['cvss']} ({risk['severity']})</div>
                <div><strong>Description:</strong> {risk['description'][:200]}...</div>
            </div>
"""
        else:
            html_content += '<div class="no-data">✅ No active service risks detected</div>'
        
        html_content += "</div>"
        
        # Forensic Findings - Enhanced Section
        html_content += """
        <div class="section">
            <h2>🔍 Digital Forensics - Comprehensive Analysis</h2>
"""
        
        # Persistence Mechanisms
        html_content += """
            <h3>🔴 Persistence Mechanisms</h3>
"""
        
        if forensics.get('persistence'):
            html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Location</th>
                        <th>Name</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
"""
            for entry in forensics['persistence'][:30]:
                html_content += f"""
                    <tr>
                        <td>{entry.get('type', 'Registry')}</td>
                        <td style="font-size: 0.85em;">{entry['location']}</td>
                        <td><strong>{entry['name']}</strong></td>
                        <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; font-family: monospace; font-size: 0.8em;">{entry['value'][:100]}</td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
"""
        else:
            html_content += '<div class="no-data">No persistence mechanisms detected</div>'
        
        # Scheduled Tasks
        html_content += """
            <h3>⏰ Scheduled Tasks (Suspicious)</h3>
"""
        
        suspicious_tasks = [t for t in forensics.get('scheduled_tasks', []) if t.get('suspicious')]
        if suspicious_tasks:
            html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Task Name</th>
                        <th>State</th>
                        <th>Action</th>
                        <th>Arguments</th>
                    </tr>
                </thead>
                <tbody>
"""
            for task in suspicious_tasks[:20]:
                html_content += f"""
                    <tr style="background: #fff8f0;">
                        <td><strong>{task['name']}</strong></td>
                        <td>{task['state']}</td>
                        <td style="font-family: monospace; font-size: 0.85em;">{task['action']}</td>
                        <td style="font-family: monospace; font-size: 0.85em;">{task.get('arguments', 'N/A')[:80]}</td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
"""
        else:
            html_content += '<div class="no-data">✅ No suspicious scheduled tasks detected</div>'
        
        # Network Connections
        html_content += """
            <h3>🌐 Network Connections (Suspicious)</h3>
"""
        
        suspicious_conns = [c for c in forensics.get('network_connections', []) if c.get('suspicious')]
        if suspicious_conns:
            html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Local</th>
                        <th>Remote Address</th>
                        <th>Remote Port</th>
                        <th>State</th>
                        <th>Process ID</th>
                    </tr>
                </thead>
                <tbody>
"""
            for conn in suspicious_conns:
                html_content += f"""
                    <tr style="background: #fff5f5;">
                        <td>{conn['local_address']}:{conn['local_port']}</td>
                        <td><strong>{conn['remote_address']}</strong></td>
                        <td><span class="badge critical">{conn['remote_port']}</span></td>
                        <td>{conn['state']}</td>
                        <td>{conn['process_id']}</td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
"""
        else:
            html_content += '<div class="no-data">✅ No suspicious network connections detected</div>'
        
        # PowerShell History
        html_content += """
            <h3>💻 PowerShell Command History (Suspicious)</h3>
"""
        
        suspicious_ps = [p for p in forensics.get('powershell_history', []) if p.get('suspicious')]
        if suspicious_ps:
            html_content += """
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Command</th>
                    </tr>
                </thead>
                <tbody>
"""
            for ps in suspicious_ps[:15]:
                html_content += f"""
                    <tr style="background: #fff5f5;">
                        <td>{ps['command_number']}</td>
                        <td style="font-family: monospace; font-size: 0.85em; color: #d63384;"><strong>{ps['command'][:150]}</strong></td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
"""
        else:
            html_content += '<div class="no-data">✅ No suspicious PowerShell commands detected</div>'
        
        # WMI Persistence
        if forensics.get('wmi_persistence'):
            html_content += """
            <h3>⚙️ WMI Event Subscriptions</h3>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Name</th>
                        <th>Query</th>
                    </tr>
                </thead>
                <tbody>
"""
            for wmi in forensics['wmi_persistence'][:10]:
                html_content += f"""
                    <tr>
                        <td>{wmi['type']}</td>
                        <td><strong>{wmi['name']}</strong></td>
                        <td style="font-family: monospace; font-size: 0.85em;">{wmi.get('query', 'N/A')[:100]}</td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
"""
        
        # User Accounts
        suspicious_users = [u for u in forensics.get('user_accounts', []) if u.get('suspicious')]
        if suspicious_users:
            html_content += """
            <h3>👤 User Accounts (Suspicious)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Enabled</th>
                        <th>Password Required</th>
                        <th>Last Logon</th>
                    </tr>
                </thead>
                <tbody>
"""
            for user in suspicious_users:
                html_content += f"""
                    <tr style="background: #fff8f0;">
                        <td><strong>{user['name']}</strong></td>
                        <td>{'✅ Yes' if user['enabled'] else '❌ No'}</td>
                        <td>{'✅ Yes' if user.get('password_required') else '⚠️ No'}</td>
                        <td>{user.get('last_logon', 'Never')}</td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
"""
        
        # USB History
        if forensics.get('usb_history'):
            usb_count = len(forensics['usb_history'])
            html_content += f"""
            <h3>🔌 USB Device History</h3>
            <p style="padding: 15px; background: #f8f9fa; border-radius: 5px;">
                <strong>{usb_count}</strong> USB storage devices have been connected to this system. 
                Review full JSON report for detailed device information.
            </p>
"""
        
        html_content += "</div>"
        
        # Open Ports and Vulnerabilities Section (NEW)
        html_content += """
        <div class="section">
            <h2>🔓 Open Ports & Network Attack Surface</h2>
"""
        
        open_ports = forensics.get('open_ports', [])
        if open_ports:
            critical_ports = [p for p in open_ports if p['risk_level'] == 'CRITICAL']
            high_ports = [p for p in open_ports if p['risk_level'] == 'HIGH']
            
            html_content += f"""
            <div style="padding: 15px; background: #f8f9fa; border-radius: 5px; margin-bottom: 20px;">
                <strong>Total Open Ports:</strong> {len(open_ports)} 
                (<span style="color: #dc3545;"><strong>{len(critical_ports)} CRITICAL</strong></span>, 
                <span style="color: #fd7e14;"><strong>{len(high_ports)} HIGH</strong></span>)
            </div>
            
            <h3>🔴 Critical & High Risk Ports</h3>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Process</th>
                        <th>Risk</th>
                        <th>External</th>
                        <th>Known Vulnerabilities</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for port in critical_ports + high_ports:
                risk_color = '#dc3545' if port['risk_level'] == 'CRITICAL' else '#fd7e14'
                external_icon = '🌐 Yes' if port['external_access'] else '🔒 No'
                vulns = '<br>'.join(port.get('known_vulns', [])[:3])
                
                html_content += f"""
                    <tr style="background: {'#fff5f5' if port['risk_level'] == 'CRITICAL' else '#fff8f0'};">
                        <td><strong style="font-size: 1.2em;">{port['port']}</strong></td>
                        <td>{port['protocol']}</td>
                        <td><strong>{port['service']}</strong></td>
                        <td style="font-family: monospace; font-size: 0.85em;">{port['process']}</td>
                        <td><span class="badge" style="background: {risk_color};">{port['risk_level']}</span></td>
                        <td>{external_icon}</td>
                        <td style="font-size: 0.85em;">{vulns if vulns else 'None listed'}</td>
                    </tr>
"""
            
            html_content += """
                </tbody>
            </table>
"""
        else:
            html_content += '<div class="no-data">No open ports detected (scan may have been blocked)</div>'
        
        # Port-Specific CVE Vulnerabilities
        port_vulns = audit.get('port_vulnerabilities', [])
        if port_vulns:
            html_content += f"""
            <h3>⚠️ CVEs Affecting Open Ports ({len(port_vulns)} found)</h3>
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>CVSS</th>
                        <th>Severity</th>
                        <th>External</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
            
            for pv in port_vulns[:30]:  # Limit to 30 most critical
                kev_badge = '<span class="badge kev">KEV</span>' if pv.get('is_kev') else ''
                external_badge = '<span class="badge critical">EXTERNAL</span>' if pv.get('external_access') else ''
                
                html_content += f"""
                    <tr style="background: {'#fff5f5' if pv.get('cvss', 0) >= 9.0 else '#fff8f0'};">
                        <td><strong>{pv['cve_id']}</strong> {kev_badge}</td>
                        <td><strong>{pv['port']}/{pv['protocol']}</strong></td>
                        <td>{pv['service']}</td>
                        <td><span class="badge {'critical' if pv.get('cvss', 0) >= 9.0 else 'high'}">{pv.get('cvss', 0)}</span></td>
                        <td>{pv.get('severity', 'UNKNOWN')}</td>
                        <td>{external_badge}</td>
                        <td style="font-size: 0.85em;">{pv['description'][:150]}...</td>
                    </tr>
"""
            
            html_content += """
                </tbody>
            </table>
"""
        
        html_content += "</div>"
        
        # Inventory Summary
        software_count = len(inventory.get('software', []))
        service_count = len(inventory.get('services', []))
        patch_count = len(inventory.get('patches', []))
        
        html_content += f"""
        <div class="section">
            <h2>📊 System Inventory</h2>
            <div class="dashboard" style="padding: 20px 0;">
                <div class="metric-card">
                    <div class="metric-value info">{software_count}</div>
                    <div class="metric-label">Installed Software</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value success">{service_count}</div>
                    <div class="metric-label">Running Services</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value success">{patch_count}</div>
                    <div class="metric-label">Installed Patches</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>🛡️ Vultron v2.0 - Windows Security Auditor</p>
            <p>Cybersecurity Engineering Team | {datetime.now().year}</p>
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(Colors.success(f"    HTML report saved: {filename}"))
        except Exception as e:
            print(Colors.warning(f"[!] Error saving HTML report: {str(e)}"))


# ==================== MAIN ORCHESTRATOR ====================
def show_help():
    """Display help and usage information"""
    help_text = """
╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦ ╔═╗
╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝ ║ ║
 ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝   ╚╝ o╚═╝

Vultron v2.1 - Windows Security Auditor
═══════════════════════════════════════════════════════════

DESCRIPTION:
  Comprehensive Windows security scanner combining vulnerability 
  assessment, digital forensics, and network analysis.

SUPPORTED SYSTEMS:
  ✓ Windows 10 (All builds from 1507 to current)
  ✓ Windows 11 (All builds)
  ✓ Windows Server 2008 (Standard, R2, Enterprise, Datacenter)
  ✓ Windows Server 2012 (Standard, R2, Datacenter)
  ✓ Windows Server 2016 (Standard, Datacenter)
  ✓ Windows Server 2019 (Standard, Datacenter)
  ✓ Windows Server 2022 (Standard, Datacenter)

FEATURES:
  ✓ CVE Scanning (2015-present or last 120 days)
  ✓ 15+ Digital Forensic Artifacts
  ✓ Open Port Detection with Vulnerability Correlation
  ✓ Service Version Detection
  ✓ CISA KEV Flagging
  ✓ Professional HTML + JSON Reports

USAGE:
  python vultron_v2.py [OPTIONS]

OPTIONS:
  --help, -h          Show this help message and exit
  --version, -v       Show version information
  --quick             Run quick scan (120 days, faster)
  --comprehensive     Run comprehensive scan (2015-present, thorough)

SCAN MODES:

  1. COMPREHENSIVE (Recommended for legacy systems)
     - Scans ALL CVEs from 2015 to present
     - Complete historical vulnerability coverage
     - Perfect for Windows Server 2008/2012 and older Win10 builds
     - Time: 3-5 minutes
  
  2. QUICK (Recommended for updated systems)
     - Scans last 120 days of CVEs only
     - Fast security check for current systems
     - Perfect for Windows 11 and Server 2022
     - Time: 1-2 minutes

MODULES:

  Module 1: E-Inventory
    - OS specifications and build info
    - Software Bill of Materials (SBOM)
    - Service mapping
    - Installed patches (KBs)
  
  Module 2: Digital Forensics
    - Registry persistence (9 locations)
    - Scheduled tasks analysis
    - Network connections
    - Open ports with service detection
    - PowerShell command history
    - Execution timeline (Prefetch)
    - Event log monitoring
    - USB device history
    - User account anomalies
    - WMI event subscriptions
    - Firewall rules
  
  Module 3: NVD Intelligence
    - NVD API 2.0 integration
    - CPE string generation (Desktop & Server)
    - CISA KEV detection
    - CVSS scoring
  
  Module 4: Audit Engine
    - Missing patch detection
    - Active service vulnerabilities
    - Port-specific CVE correlation
    - Risk prioritization

OUTPUT:
  vultron_report.html - Interactive dashboard
  vultron_report.json - Machine-readable data

REQUIREMENTS:
  - Windows 10/11 or Server 2008/2012/2016/2019/2022
  - Python 3.12+
  - Administrator privileges
  - colorama, requests, psutil

EXAMPLES:

  Basic scan (interactive mode):
    python vultron_v2.py
  
  Quick scan (command line):
    python vultron_v2.py --quick
  
  Comprehensive scan (command line):
    python vultron_v2.py --comprehensive

NOTES:
  - Always run as Administrator
  - Internet required for NVD API
  - First scan takes longer (downloads CVE data)
  - Reports saved in current directory
  - Server 2008/2012 systems should use COMPREHENSIVE mode

DOCUMENTATION:
  README.md - Full documentation
  QUICK_START.md - 5-minute setup guide
  ENHANCED_FEATURES.md - Feature details

For more information: https://github.com/your-repo/vultron
"""
    print(help_text)


def main():
    """Main execution orchestrator"""
    
    # Check for help flag
    if len(sys.argv) > 1:
        if sys.argv[1] in ['--help', '-h', 'help', '/?']:
            show_help()
            sys.exit(0)
        elif sys.argv[1] in ['--version', '-v']:
            print("Vultron v2.1 - Windows Security Auditor")
            print("Copyright (c) 2025 Cybersecurity Engineering Team")
            sys.exit(0)
    
    # ASCII Banner
    banner = """
    ╦  ╦╦ ╦╦  ╔╦╗╦═╗╔═╗╔╗╔  ╦  ╦  ╔═╗
    ╚╗╔╝║ ║║   ║ ╠╦╝║ ║║║║  ╚╗╔╝  ║ ║
     ╚╝ ╚═╝╩═╝ ╩ ╩╚═╚═╝╝╚╝   ╚╝  o╚═╝
    
    Windows Security Auditor v2.1 - ENHANCED EDITION
    E-Inventory | Advanced Forensics | Full CVE History | Port Scanning
    
    Supported: Windows 10/11 & Server 2008/2012/2016/2019/2022
    ═══════════════════════════════════════════════════════════
    """
    
    print(Colors.header(banner))
    
    # Check admin privileges
    require_admin()
    print(Colors.success("[+] Running with Administrator privileges\n"))
    
    # Check dependencies
    missing_deps = []
    if not HAS_COLORAMA:
        missing_deps.append("colorama")
    if not HAS_REQUESTS:
        missing_deps.append("requests")
    
    if missing_deps:
        print(Colors.warning(f"[!] Missing optional dependencies: {', '.join(missing_deps)}"))
        print(Colors.info(f"[+] Install with: pip install {' '.join(missing_deps)}\n"))
    
    # Scan mode selection
    quick_scan = False
    
    # Check for command-line arguments
    if len(sys.argv) > 1:
        if '--quick' in sys.argv:
            quick_scan = True
            print(Colors.info("[+] Quick scan mode selected via command line\n"))
        elif '--comprehensive' in sys.argv:
            quick_scan = False
            print(Colors.info("[+] Comprehensive scan mode selected via command line\n"))
    else:
        # Interactive mode
        print(Colors.info("[?] Scan Mode Selection:"))
        print(Colors.info("    1. COMPREHENSIVE (Recommended) - All CVEs from 2015-present + Full Forensics"))
        print(Colors.info("    2. QUICK - Last 120 days only + Full Forensics"))
        print(Colors.info("    [Press Enter for Comprehensive, or type '2' for Quick]"))
        
        try:
            mode_input = input(Colors.info("\n[>] Select mode: ")).strip()
            quick_scan = (mode_input == '2')
            
            if quick_scan:
                print(Colors.info("\n[+] Starting QUICK scan mode...\n"))
            else:
                print(Colors.info("\n[+] Starting COMPREHENSIVE scan mode (this may take 3-5 minutes)...\n"))
        except:
            quick_scan = False
            print(Colors.info("\n[+] Starting COMPREHENSIVE scan mode...\n"))
    
    # Initialize results storage
    all_results = {
        'inventory': {},
        'forensics': {},
        'nvd': {},
        'audit': {}
    }
    
    # Module 1: E-Inventory
    inventory = EInventory()
    inventory_data = inventory.run()
    all_results['inventory'] = inventory_data
    
    # Module 2: Digital Forensics (Enhanced)
    forensics = DigitalForensics()
    forensics_data = forensics.run()
    all_results['forensics'] = forensics_data
    
    # Module 3: NVD Intelligence (run in parallel)
    print(Colors.info("\n[*] Starting NVD vulnerability scan in background..."))
    
    with ThreadPoolExecutor(max_workers=1) as executor:
        nvd_future = executor.submit(
            lambda: NVDIntelligence().run(inventory_data.get('os_specs', {}), quick_scan=quick_scan)
        )
        
        # Wait for NVD results
        nvd_data = nvd_future.result()
        all_results['nvd'] = nvd_data
    
    # Module 4: Audit Engine
    audit_engine = AuditEngine(inventory_data, forensics_data, nvd_data)
    audit_results = audit_engine.match_vulnerabilities()
    all_results['audit'] = audit_results
    
    # Generate Reports
    print(Colors.header("\n[REPORT GENERATION]"))
    ReportGenerator.generate_json(
        inventory_data,
        forensics_data,
        nvd_data,
        audit_results
    )
    ReportGenerator.generate_html(
        inventory_data,
        forensics_data,
        nvd_data,
        audit_results
    )
    
    # Final Summary
    print(Colors.header("\n[SCAN COMPLETE]"))
    print(Colors.success("✅ All modules executed successfully"))
    print(Colors.info(f"📁 Reports generated: vultron_report.json, vultron_report.html"))
    print(Colors.info(f"📊 Total CVEs Analyzed: {len(nvd_data.get('vulnerabilities', []))}"))
    print(Colors.critical(f"🔴 Critical Findings: {len(audit_results.get('critical', []))}"))
    print(Colors.warning(f"🟠 High Findings: {len(audit_results.get('high', []))}"))
    print(Colors.warning(f"⚠️  Active Risks: {len(audit_results.get('active_risks', []))}"))
    print(Colors.critical(f"🔓 Port Vulnerabilities: {len(audit_results.get('port_vulnerabilities', []))}"))
    
    if nvd_data.get('kev_vulns'):
        print(Colors.critical(f"\n⚠️  CISA KEV DETECTED: {len(nvd_data['kev_vulns'])} vulnerabilities require IMMEDIATE ACTION!"))
    
    # Forensic Summary
    total_forensic_items = (
        len(forensics_data.get('persistence', [])) +
        len([t for t in forensics_data.get('scheduled_tasks', []) if t.get('suspicious')]) +
        len([c for c in forensics_data.get('network_connections', []) if c.get('suspicious')]) +
        len([p for p in forensics_data.get('powershell_history', []) if p.get('suspicious')])
    )
    
    # Port Summary
    open_ports = forensics_data.get('open_ports', [])
    critical_ports = len([p for p in open_ports if p['risk_level'] == 'CRITICAL'])
    high_ports = len([p for p in open_ports if p['risk_level'] == 'HIGH'])
    
    if open_ports:
        print(Colors.forensic(f"\n🔓 Network Exposure: {len(open_ports)} open ports detected"))
        if critical_ports > 0:
            print(Colors.critical(f"    - {critical_ports} CRITICAL risk ports (RDP, SMB, Telnet, etc.)"))
        if high_ports > 0:
            print(Colors.warning(f"    - {high_ports} HIGH risk ports (SQL, FTP, VNC, etc.)"))
    
    if total_forensic_items > 0:
        print(Colors.forensic(f"\n🔍 Forensic Alerts: {total_forensic_items} suspicious items detected"))
        print(Colors.forensic("    - Registry persistence entries"))
        print(Colors.forensic("    - Suspicious scheduled tasks"))
        print(Colors.forensic("    - Unusual network connections"))
        print(Colors.forensic("    - PowerShell command history"))
    
    print(Colors.header("\n" + "="*60))
    print(Colors.info("💡 TIP: Open vultron_report.html in your browser for interactive analysis"))
    print(Colors.header("="*60 + "\n"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Colors.warning("\n\n[!] Scan interrupted by user"))
        sys.exit(0)
    except Exception as e:
        print(Colors.critical(f"\n[!] Fatal error: {str(e)}"))
        import traceback
        traceback.print_exc()
        sys.exit(1)
