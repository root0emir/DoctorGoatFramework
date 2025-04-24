#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
System information collection module
"""

import os
import sys
import platform
import socket
import logging
import subprocess
import json
import re
import psutil
import requests
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("doctorgoat.system_info")

class SystemInfo:
    """System information collection class"""
    
    def __init__(self, detailed=True):
        """
        Initialize the system information collector
        
        Args:
            detailed (bool): Whether to collect detailed information
        """
        self.system_data = {}
        self.detailed = detailed
    
    def collect(self):
        """
        Collect system information
        
        Returns:
            dict: Collected system information
        """
        logger.info("Collecting system information...")
        
        try:
            self._collect_os_info()
            self._collect_cpu_info()
            self._collect_memory_info()
            self._collect_disk_info()
            self._collect_network_info()
            self._collect_user_info()
            self._collect_service_info()
            self._collect_kernel_info()
            self._collect_security_info()
            
            if self.detailed:
                self._collect_installed_packages()
                self._collect_running_containers()
                self._collect_virtualization_info()
                self._collect_hardware_info()
            
            logger.info("System information successfully collected")
            return self.system_data
        
        except Exception as e:
            logger.error(f"Error collecting system information: {str(e)}")
            raise
    
    def _collect_os_info(self):
        """Collect operating system information"""
        logger.debug("Collecting operating system information...")
        
        self.system_data["os"] = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_seconds": int(datetime.now().timestamp() - psutil.boot_time()),
            "platform": platform.platform(aliased=True, terse=False),
            "python_version": platform.python_version()
        }
        
        # Linux distribution information
        if platform.system() == "Linux":
            try:
                # Read /etc/os-release file
                os_release = {}
                if os.path.exists("/etc/os-release"):
                    with open("/etc/os-release", "r") as f:
                        for line in f:
                            if "=" in line:
                                key, value = line.strip().split("=", 1)
                                os_release[key] = value.strip('"')
                
                self.system_data["os"]["distribution"] = os_release.get("NAME", "Unknown")
                self.system_data["os"]["distribution_version"] = os_release.get("VERSION_ID", "Unknown")
                self.system_data["os"]["distribution_codename"] = os_release.get("VERSION_CODENAME", "Unknown")
                self.system_data["os"]["distribution_id"] = os_release.get("ID", "Unknown")
                self.system_data["os"]["distribution_id_like"] = os_release.get("ID_LIKE", "Unknown")
                
                # Check for EOL/support status
                try:
                    if self.system_data["os"]["distribution_id"] in ["ubuntu", "debian", "centos", "rhel", "fedora"]:
                        self._check_distribution_support_status()
                except Exception as e:
                    logger.warning(f"Could not determine distribution support status: {str(e)}")
                
                # Check for required security updates
                try:
                    self._check_security_updates()
                except Exception as e:
                    logger.warning(f"Could not check for security updates: {str(e)}")
                
            except Exception as e:
                logger.warning(f"Could not get distribution information: {str(e)}")
                self.system_data["os"]["distribution"] = "Unknown"
                self.system_data["os"]["distribution_version"] = "Unknown"
                self.system_data["os"]["distribution_codename"] = "Unknown"
        
        # Get timezone information
        try:
            self.system_data["os"]["timezone"] = datetime.now().astimezone().tzname()
            
            # Check if NTP is configured and active
            self._check_ntp_status()
        except Exception as e:
            logger.warning(f"Could not determine timezone information: {str(e)}")
    
    def _check_distribution_support_status(self):
        """Check if the distribution is still supported"""
        dist_id = self.system_data["os"]["distribution_id"]
        version = self.system_data["os"]["distribution_version"]
        
        # This is a simplified check - in a real implementation, you would
        # have a more comprehensive database of EOL dates for distributions
        eol_dates = {
            "ubuntu": {
                "16.04": "2021-04-30",  # ESM until 2024
                "18.04": "2023-04-30",  # ESM until 2028
                "20.04": "2025-04-30",  # ESM until 2030
                "22.04": "2027-04-30",  # ESM until 2032
            },
            "debian": {
                "9": "2022-06-30",
                "10": "2024-06-30",
                "11": "2026-06-30",
            },
            "centos": {
                "7": "2024-06-30",
                "8": "2021-12-31",  # Early EOL
            },
            "rhel": {
                "7": "2024-06-30",
                "8": "2029-05-31",
                "9": "2032-05-31",
            },
            "fedora": {
                "34": "2022-06-07",
                "35": "2022-12-13",
                "36": "2023-05-16",
                "37": "2023-12-05",
                "38": "2024-05-21",
            }
        }
        
        if dist_id in eol_dates and version in eol_dates[dist_id]:
            eol_date = eol_dates[dist_id][version]
            today = datetime.now().strftime("%Y-%m-%d")
            
            self.system_data["os"]["eol_date"] = eol_date
            self.system_data["os"]["is_eol"] = today > eol_date
            
            # Calculate days until EOL
            eol_datetime = datetime.strptime(eol_date, "%Y-%m-%d")
            days_until_eol = (eol_datetime - datetime.now()).days
            self.system_data["os"]["days_until_eol"] = days_until_eol
        else:
            self.system_data["os"]["eol_date"] = "Unknown"
            self.system_data["os"]["is_eol"] = None
            self.system_data["os"]["days_until_eol"] = None
    
    def _check_security_updates(self):
        """Check for available security updates"""
        dist_id = self.system_data["os"]["distribution_id"]
        
        security_updates = {
            "available": False,
            "count": 0,
            "details": []
        }
        
        if platform.system() != "Linux":
            self.system_data["os"]["security_updates"] = security_updates
            return
        
        try:
            if dist_id in ["ubuntu", "debian"]:
                # Use apt to check for security updates
                result = subprocess.run(
                    ["apt-get", "--simulate", "--quiet", "upgrade"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if "security" in result.stdout.lower():
                    security_updates["available"] = True
                    # Count security updates (simplified)
                    security_count = result.stdout.lower().count("security")
                    security_updates["count"] = security_count
            
            elif dist_id in ["centos", "rhel", "fedora"]:
                # Use yum to check for security updates
                result = subprocess.run(
                    ["yum", "check-update", "--security"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Return code 100 means updates available
                if result.returncode == 100:
                    security_updates["available"] = True
                    # Count lines with updates (simplified)
                    lines = [line for line in result.stdout.split('\n') if line.strip() and not line.startswith(' ')]
                    security_updates["count"] = len(lines) - 2  # Subtract header lines
        
        except Exception as e:
            logger.warning(f"Error checking for security updates: {str(e)}")
        
        self.system_data["os"]["security_updates"] = security_updates
    
    def _check_ntp_status(self):
        """Check if NTP is configured and active"""
        ntp_status = {
            "configured": False,
            "synchronized": False,
            "service": "unknown"
        }
        
        if platform.system() != "Linux":
            self.system_data["os"]["ntp"] = ntp_status
            return
        
        try:
            # Check for systemd-timesyncd
            result = subprocess.run(
                ["timedatectl", "status"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                if "NTP service: active" in result.stdout:
                    ntp_status["configured"] = True
                    ntp_status["service"] = "systemd-timesyncd"
                
                if "System clock synchronized: yes" in result.stdout:
                    ntp_status["synchronized"] = True
            
            # Check for ntpd
            result = subprocess.run(
                ["systemctl", "is-active", "ntpd"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip() == "active":
                ntp_status["configured"] = True
                ntp_status["service"] = "ntpd"
                ntp_status["synchronized"] = True  # Assume synchronized if active
            
            # Check for chronyd
            result = subprocess.run(
                ["systemctl", "is-active", "chronyd"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip() == "active":
                ntp_status["configured"] = True
                ntp_status["service"] = "chronyd"
                ntp_status["synchronized"] = True  # Assume synchronized if active
        
        except Exception as e:
            logger.warning(f"Error checking NTP status: {str(e)}")
        
        self.system_data["os"]["ntp"] = ntp_status
    
    def _collect_cpu_info(self):
        """CPU bilgilerini toplar"""
        logger.debug("CPU bilgileri toplanıyor...")
        
        self.system_data["cpu"] = {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "usage_percent": psutil.cpu_percent(interval=1),
            "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else None
        }
        
        # CPU modeli (Linux)
        if platform.system() == "Linux":
            try:
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "model name" in line:
                            self.system_data["cpu"]["model"] = line.split(":")[1].strip()
                            break
            except Exception as e:
                logger.warning(f"CPU model bilgisi alınamadı: {str(e)}")
                self.system_data["cpu"]["model"] = "Unknown"
    
    def _collect_memory_info(self):
        """Bellek bilgilerini toplar"""
        logger.debug("Bellek bilgileri toplanıyor...")
        
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        self.system_data["memory"] = {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent,
            "swap_total": swap.total,
            "swap_used": swap.used,
            "swap_percent": swap.percent
        }
    
    def _collect_disk_info(self):
        """Disk bilgilerini toplar"""
        logger.debug("Disk bilgileri toplanıyor...")
        
        self.system_data["disks"] = []
        
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                
                disk_info = {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "opts": partition.opts,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                }
                
                self.system_data["disks"].append(disk_info)
            except PermissionError:
                # Bazı disk bölümlerine erişim izni olmayabilir
                logger.warning(f"Disk bölümüne erişim izni yok: {partition.mountpoint}")
            except Exception as e:
                logger.warning(f"Disk bilgisi alınamadı: {str(e)}")
    
    def _collect_network_info(self):
        """Ağ bilgilerini toplar"""
        logger.debug("Ağ bilgileri toplanıyor...")
        
        self.system_data["network"] = {
            "interfaces": [],
            "connections": []
        }
        
        # Ağ arayüzleri
        for interface_name, interface_addresses in psutil.net_if_addrs().items():
            interface_info = {
                "name": interface_name,
                "addresses": []
            }
            
            for addr in interface_addresses:
                address_info = {
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                }
                interface_info["addresses"].append(address_info)
            
            self.system_data["network"]["interfaces"].append(interface_info)
        
        # Ağ bağlantıları
        try:
            for conn in psutil.net_connections(kind='inet'):
                connection_info = {
                    "fd": conn.fd,
                    "family": conn.family,
                    "type": conn.type,
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                }
                self.system_data["network"]["connections"].append(connection_info)
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Ağ bağlantıları alınamadı: Yetki hatası")
        except Exception as e:
            logger.warning(f"Ağ bağlantıları alınamadı: {str(e)}")
    
    def _collect_user_info(self):
        """Kullanıcı bilgilerini toplar"""
        logger.debug("Kullanıcı bilgileri toplanıyor...")
        
        self.system_data["users"] = {
            "current_user": os.getlogin() if hasattr(os, "getlogin") else None,
            "effective_user_id": os.geteuid() if hasattr(os, "geteuid") else None,
            "users": []
        }
        
        # Sistemdeki kullanıcılar (Linux)
        if platform.system() == "Linux":
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        if line.strip():
                            parts = line.strip().split(":")
                            if len(parts) >= 7:
                                user_info = {
                                    "username": parts[0],
                                    "uid": parts[2],
                                    "gid": parts[3],
                                    "home": parts[5],
                                    "shell": parts[6]
                                }
                                self.system_data["users"]["users"].append(user_info)
            except Exception as e:
                logger.warning(f"Kullanıcı bilgileri alınamadı: {str(e)}")
    
    def _collect_service_info(self):
        """Servis bilgilerini toplar"""
        logger.debug("Servis bilgileri toplanıyor...")
        
        self.system_data["services"] = {
            "running_processes": []
        }
        
        # Çalışan işlemler
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
            try:
                process_info = proc.info
                process_info['create_time'] = datetime.fromtimestamp(process_info['create_time']).strftime("%Y-%m-%d %H:%M:%S")
                self.system_data["services"]["running_processes"].append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sistemd servisleri (Linux)
        if platform.system() == "Linux":
            try:
                result = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    services = []
                    for line in result.stdout.splitlines()[1:]:  # İlk satırı atla (başlık)
                        parts = line.split()
                        if len(parts) >= 5:
                            service_name = parts[0]
                            service_status = parts[3]
                            services.append({
                                "name": service_name,
                                "status": service_status
                            })
                    
                    self.system_data["services"]["systemd_services"] = services
            except Exception as e:
                logger.warning(f"Systemd servisleri alınamadı: {str(e)}")
    
    def _collect_kernel_info(self):
        """Collect kernel information and security parameters"""
        logger.debug("Collecting kernel information and security parameters...")
        
        self.system_data["kernel"] = {
            "name": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "security": {
                "parameters": {},
                "assessment": {},
                "recommendations": []
            }
        }
        
        # Only proceed with detailed kernel checks on Linux
        if platform.system() != "Linux":
            return
        
        # Get kernel compile options
        try:
            if os.path.exists("/proc/config.gz"):
                # Extract kernel config
                result = subprocess.run(
                    ["zcat", "/proc/config.gz"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    kernel_config = {}
                    for line in result.stdout.splitlines():
                        if line.startswith("CONFIG_"):
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                kernel_config[parts[0]] = parts[1]
                    
                    self.system_data["kernel"]["config"] = kernel_config
                    
                    # Check for security-relevant kernel options
                    self._assess_kernel_security_options(kernel_config)
            
            # Get kernel command line parameters
            if os.path.exists("/proc/cmdline"):
                with open("/proc/cmdline", "r") as f:
                    cmdline = f.read().strip()
                    self.system_data["kernel"]["cmdline"] = cmdline
                    
                    # Check for security-relevant cmdline options
                    self._assess_kernel_cmdline_security(cmdline)
        
        except Exception as e:
            logger.warning(f"Error collecting kernel configuration: {str(e)}")
        
        # Collect sysctl parameters
        try:
            result = subprocess.run(
                ["sysctl", "-a"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                kernel_params = {}
                for line in result.stdout.splitlines():
                    if "=" in line:
                        key, value = line.split("=", 1)
                        kernel_params[key.strip()] = value.strip()
                
                self.system_data["kernel"]["parameters"] = kernel_params
                
                # Assess security-relevant sysctl parameters
                self._assess_sysctl_security(kernel_params)
        
        except Exception as e:
            logger.warning(f"Error collecting kernel parameters: {str(e)}")
    
    def _assess_kernel_security_options(self, kernel_config):
        """Assess security-relevant kernel configuration options"""
        security_options = {
            "CONFIG_SECURITY": {"expected": "y", "description": "Security subsystem"},
            "CONFIG_SECURITY_SELINUX": {"expected": "y", "description": "SELinux support"},
            "CONFIG_SECURITY_SMACK": {"expected": "y", "description": "Smack support"},
            "CONFIG_SECURITY_APPARMOR": {"expected": "y", "description": "AppArmor support"},
            "CONFIG_SECURITY_YAMA": {"expected": "y", "description": "Yama support"},
            "CONFIG_STRICT_KERNEL_RWX": {"expected": "y", "description": "Strict kernel R/W/X mappings"},
            "CONFIG_STRICT_MODULE_RWX": {"expected": "y", "description": "Strict module R/W/X mappings"},
            "CONFIG_STACKPROTECTOR": {"expected": "y", "description": "Stack Protector buffer overflow detection"},
            "CONFIG_STACKPROTECTOR_STRONG": {"expected": "y", "description": "Stack Protector Strong"},
            "CONFIG_RANDOMIZE_BASE": {"expected": "y", "description": "KASLR - Kernel Address Space Layout Randomization"},
            "CONFIG_RANDOMIZE_MEMORY": {"expected": "y", "description": "KASLR for physical memory"},
            "CONFIG_SECURITY_DMESG_RESTRICT": {"expected": "y", "description": "Restrict unprivileged access to kernel logs"},
            "CONFIG_DEBUG_CREDENTIALS": {"expected": "y", "description": "Debug credential management"},
            "CONFIG_DEBUG_NOTIFIERS": {"expected": "y", "description": "Debug notifier call chains"},
            "CONFIG_DEBUG_LIST": {"expected": "y", "description": "Debug linked list manipulation"},
            "CONFIG_SECCOMP": {"expected": "y", "description": "Seccomp support"},
            "CONFIG_SECCOMP_FILTER": {"expected": "y", "description": "Seccomp filter support"},
            "CONFIG_HARDENED_USERCOPY": {"expected": "y", "description": "Hardened user copy"},
            "CONFIG_FORTIFY_SOURCE": {"expected": "y", "description": "Fortify source"},
            "CONFIG_INIT_ON_ALLOC_DEFAULT_ON": {"expected": "y", "description": "Initialize memory on allocation"},
            "CONFIG_INIT_ON_FREE_DEFAULT_ON": {"expected": "y", "description": "Initialize memory on free"},
        }
        
        assessment = {}
        recommendations = []
        
        for option, details in security_options.items():
            if option in kernel_config:
                value = kernel_config[option]
                expected = details["expected"]
                
                assessment[option] = {
                    "value": value,
                    "expected": expected,
                    "status": value == expected,
                    "description": details["description"]
                }
                
                if value != expected:
                    recommendations.append(f"Enable kernel option {option} for {details['description']}")
            else:
                assessment[option] = {
                    "value": "not found",
                    "expected": details["expected"],
                    "status": False,
                    "description": details["description"]
                }
                
                recommendations.append(f"Enable kernel option {option} for {details['description']}")
        
        self.system_data["kernel"]["security"]["kernel_options"] = assessment
        self.system_data["kernel"]["security"]["recommendations"].extend(recommendations)
    
    def _assess_kernel_cmdline_security(self, cmdline):
        """Assess security-relevant kernel command line parameters"""
        security_cmdline = {
            "slab_nomerge": {"expected": True, "description": "Disable slab merging"},
            "slub_debug=F": {"expected": True, "description": "Enable sanity checks"},
            "page_poison=1": {"expected": True, "description": "Poison free pages"},
            "pti=on": {"expected": True, "description": "Page Table Isolation (Meltdown mitigation)"},
            "spectre_v2=on": {"expected": True, "description": "Spectre v2 mitigation"},
            "spec_store_bypass_disable=on": {"expected": True, "description": "Spectre v4 mitigation"},
            "mds=full,nosmt": {"expected": True, "description": "MDS vulnerability mitigation"},
            "tsx=off": {"expected": True, "description": "Disable TSX (Intel Transactional Synchronization Extensions)"},
            "tsx_async_abort=full,nosmt": {"expected": True, "description": "TAA vulnerability mitigation"},
            "kvm.nx_huge_pages=force": {"expected": True, "description": "KVM NX huge pages protection"},
            "nosmt": {"expected": True, "description": "Disable SMT (Simultaneous Multi-Threading)"},
            "init_on_alloc=1": {"expected": True, "description": "Initialize memory on allocation"},
            "init_on_free=1": {"expected": True, "description": "Initialize memory on free"},
            "vsyscall=none": {"expected": True, "description": "Disable vsyscall"},
            "debugfs=off": {"expected": True, "description": "Disable debugfs"},
            "oops=panic": {"expected": True, "description": "Panic on oops"},
        }
        
        assessment = {}
        recommendations = []
        
        for option, details in security_cmdline.items():
            found = option in cmdline
            
            assessment[option] = {
                "found": found,
                "expected": details["expected"],
                "status": found == details["expected"],
                "description": details["description"]
            }
            
            if found != details["expected"]:
                if details["expected"]:
                    recommendations.append(f"Add '{option}' to kernel command line for {details['description']}")
                else:
                    recommendations.append(f"Remove '{option}' from kernel command line")
        
        self.system_data["kernel"]["security"]["cmdline_options"] = assessment
        self.system_data["kernel"]["security"]["recommendations"].extend(recommendations)
    
    def _assess_sysctl_security(self, kernel_params):
        """Assess security-relevant sysctl parameters"""
        # Define security-relevant sysctl parameters and their recommended values
        security_params = {
            # Network security
            "net.ipv4.conf.all.accept_redirects": {"expected": "0", "description": "Disable ICMP redirects (all)"},
            "net.ipv4.conf.default.accept_redirects": {"expected": "0", "description": "Disable ICMP redirects (default)"},
            "net.ipv4.conf.all.accept_source_route": {"expected": "0", "description": "Disable source routing (all)"},
            "net.ipv4.conf.default.accept_source_route": {"expected": "0", "description": "Disable source routing (default)"},
            "net.ipv4.conf.all.rp_filter": {"expected": "1", "description": "Enable reverse path filtering (all)"},
            "net.ipv4.conf.default.rp_filter": {"expected": "1", "description": "Enable reverse path filtering (default)"},
            "net.ipv4.icmp_echo_ignore_broadcasts": {"expected": "1", "description": "Ignore ICMP broadcast requests"},
            "net.ipv4.icmp_ignore_bogus_error_responses": {"expected": "1", "description": "Ignore bogus ICMP error responses"},
            "net.ipv4.tcp_syncookies": {"expected": "1", "description": "Enable TCP SYN cookies"},
            "net.ipv4.tcp_max_syn_backlog": {"expected": "2048", "description": "Increase TCP SYN backlog", "min": "2048"},
            "net.ipv4.tcp_synack_retries": {"expected": "2", "description": "Reduce TCP SYN-ACK retries", "max": "3"},
            "net.ipv4.tcp_syn_retries": {"expected": "5", "description": "Reduce TCP SYN retries", "max": "5"},
            "net.ipv6.conf.all.accept_redirects": {"expected": "0", "description": "Disable IPv6 ICMP redirects (all)"},
            "net.ipv6.conf.default.accept_redirects": {"expected": "0", "description": "Disable IPv6 ICMP redirects (default)"},
            "net.ipv6.conf.all.accept_source_route": {"expected": "0", "description": "Disable IPv6 source routing (all)"},
            "net.ipv6.conf.default.accept_source_route": {"expected": "0", "description": "Disable IPv6 source routing (default)"},
            
            # Kernel hardening
            "kernel.randomize_va_space": {"expected": "2", "description": "Enable ASLR"},
            "kernel.kptr_restrict": {"expected": "2", "description": "Restrict kernel pointer exposure"},
            "kernel.dmesg_restrict": {"expected": "1", "description": "Restrict access to kernel logs"},
            "kernel.perf_event_paranoid": {"expected": "3", "description": "Restrict access to performance events", "min": "2"},
            "kernel.yama.ptrace_scope": {"expected": "2", "description": "Restrict ptrace capabilities", "min": "1"},
            "kernel.unprivileged_bpf_disabled": {"expected": "1", "description": "Disable unprivileged BPF"},
            "kernel.sysrq": {"expected": "0", "description": "Disable SysRq key", "max": "4"},
            "kernel.core_uses_pid": {"expected": "1", "description": "Add PID to core dumps"},
            "kernel.pid_max": {"expected": "65536", "description": "Increase maximum PID value", "min": "32768"},
            
            # File system security
            "fs.protected_hardlinks": {"expected": "1", "description": "Protect hardlinks"},
            "fs.protected_symlinks": {"expected": "1", "description": "Protect symlinks"},
            "fs.suid_dumpable": {"expected": "0", "description": "Disable core dumps of SUID programs"},
            
            # User space security
            "vm.mmap_min_addr": {"expected": "65536", "description": "Increase minimum mmap address", "min": "65536"},
            "vm.unprivileged_userfaultfd": {"expected": "0", "description": "Disable unprivileged userfaultfd"},
        }
        
        assessment = {}
        recommendations = []
        
        for param, details in security_params.items():
            if param in kernel_params:
                value = kernel_params[param]
                expected = details["expected"]
                
                # Check if the parameter meets the security requirement
                status = False
                
                if "min" in details:
                    # Parameter should be at least the minimum value
                    try:
                        status = int(value) >= int(details["min"])
                    except ValueError:
                        status = False
                elif "max" in details:
                    # Parameter should be at most the maximum value
                    try:
                        status = int(value) <= int(details["max"])
                    except ValueError:
                        status = False
                else:
                    # Parameter should match exactly
                    status = value == expected
                
                assessment[param] = {
                    "value": value,
                    "expected": expected,
                    "status": status,
                    "description": details["description"]
                }
                
                if not status:
                    recommendations.append(f"Set {param}={expected} in /etc/sysctl.conf for {details['description']}")
            else:
                assessment[param] = {
                    "value": "not found",
                    "expected": details["expected"],
                    "status": False,
                    "description": details["description"]
                }
                
                recommendations.append(f"Set {param}={details['expected']} in /etc/sysctl.conf for {details['description']}")
        
        self.system_data["kernel"]["security"]["sysctl_parameters"] = assessment
        self.system_data["kernel"]["security"]["recommendations"].extend(recommendations)
        
        # Calculate overall security score
        total_params = len(security_params)
        secure_params = sum(1 for param in assessment.values() if param["status"])
        security_score = (secure_params / total_params) * 100 if total_params > 0 else 0
        
        self.system_data["kernel"]["security"]["sysctl_score"] = {
            "score": round(security_score, 2),
            "secure_params": secure_params,
            "total_params": total_params
        }
