#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper utilities for the DoctorGoatFramework
"""

import os
import sys
import platform
import logging
import subprocess
import shutil
import tempfile
import datetime
import tarfile
from pathlib import Path

logger = logging.getLogger("doctorgoat.utils.helpers")

def is_linux():
    """
    Check if the system is Linux
    
    Returns:
        bool: True if the system is Linux, False otherwise
    """
    return platform.system() == "Linux"

def check_root():
    """
    Check if the script is running with root privileges
    
    Returns:
        bool: True if running as root, False otherwise
    """
    if not is_linux():
        return False
    
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Not on a POSIX system
        return False

def backup_system():
    """
    Create a backup of important system configuration files
    
    Returns:
        str: Path to the backup archive
    
    Raises:
        Exception: If backup creation fails
    """
    if not is_linux():
        raise Exception("System backup is only supported on Linux")
    
    logger.info("Creating system configuration backup")
    
    # Create a timestamp for the backup filename
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = tempfile.mkdtemp(prefix="doctorgoat_backup_")
    backup_archive = os.path.join(os.path.expanduser("~"), f"doctorgoat_backup_{timestamp}.tar.gz")
    
    # List of important configuration files and directories to backup
    backup_paths = [
        "/etc/sysctl.conf",
        "/etc/sysctl.d/",
        "/etc/ssh/sshd_config",
        "/etc/pam.d/",
        "/etc/security/",
        "/etc/login.defs",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d/",
        "/etc/hosts.allow",
        "/etc/hosts.deny",
        "/etc/firewalld/",
        "/etc/iptables/",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.monthly/",
        "/etc/cron.weekly/",
        "/etc/crontab",
        "/etc/fstab",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/profile",
        "/etc/bashrc",
        "/etc/issue",
        "/etc/issue.net",
        "/etc/motd",
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg"
    ]
    
    try:
        # Create directory structure in the temporary backup directory
        for path in backup_paths:
            if os.path.exists(path):
                # Create the parent directory structure
                target_path = os.path.join(backup_dir, path.lstrip('/'))
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                
                # Copy the file or directory
                if os.path.isdir(path):
                    shutil.copytree(path, target_path, symlinks=True, dirs_exist_ok=True)
                else:
                    shutil.copy2(path, target_path)
                
                logger.debug(f"Backed up: {path}")
        
        # Create the tar archive
        with tarfile.open(backup_archive, "w:gz") as tar:
            tar.add(backup_dir, arcname=os.path.basename(backup_dir))
        
        logger.info(f"Backup created: {backup_archive}")
        
        # Clean up the temporary directory
        shutil.rmtree(backup_dir)
        
        return backup_archive
    
    except Exception as e:
        logger.error(f"Backup creation failed: {str(e)}")
        # Clean up the temporary directory if it exists
        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir)
        raise

def get_linux_distribution():
    """
    Get detailed information about the Linux distribution
    
    Returns:
        dict: Distribution information
    """
    if not is_linux():
        return {"name": "Not Linux", "version": "N/A"}
    
    distribution = {
        "name": "Unknown",
        "version": "Unknown",
        "id": "unknown",
        "id_like": "",
        "codename": ""
    }
    
    try:
        # Read /etc/os-release file
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        value = value.strip('"')
                        
                        if key == "NAME":
                            distribution["name"] = value
                        elif key == "VERSION_ID":
                            distribution["version"] = value
                        elif key == "ID":
                            distribution["id"] = value
                        elif key == "ID_LIKE":
                            distribution["id_like"] = value
                        elif key == "VERSION_CODENAME":
                            distribution["codename"] = value
        
        # Try to get more specific version information
        if os.path.exists("/etc/lsb-release"):
            with open("/etc/lsb-release", "r") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        value = value.strip('"')
                        
                        if key == "DISTRIB_DESCRIPTION":
                            distribution["name"] = value
                        elif key == "DISTRIB_RELEASE":
                            distribution["version"] = value
                        elif key == "DISTRIB_CODENAME":
                            distribution["codename"] = value
    
    except Exception as e:
        logger.warning(f"Error getting Linux distribution: {str(e)}")
    
    return distribution

def run_command(command, timeout=60, shell=False):
    """
    Run a command and return the result
    
    Args:
        command (list or str): Command to run
        timeout (int): Timeout in seconds
        shell (bool): Whether to run the command in a shell
    
    Returns:
        dict: Command result with stdout, stderr, and return code
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell
        )
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0
        }
    
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds",
            "returncode": -1,
            "success": False
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "success": False
        }

def get_kernel_security_features():
    """
    Get information about enabled kernel security features
    
    Returns:
        dict: Kernel security features
    """
    if not is_linux():
        return {"error": "Not a Linux system"}
    
    security_features = {
        "selinux": {"enabled": False, "mode": "unknown"},
        "apparmor": {"enabled": False, "mode": "unknown"},
        "seccomp": {"enabled": False},
        "yama": {"enabled": False, "ptrace_scope": "unknown"},
        "nx": {"enabled": False},
        "aslr": {"enabled": False, "level": "unknown"},
        "kaslr": {"enabled": False},
        "smep": {"enabled": False},
        "smap": {"enabled": False},
        "meltdown_mitigation": {"enabled": False},
        "spectre_mitigation": {"enabled": False}
    }
    
    try:
        # Check SELinux
        if os.path.exists("/sys/fs/selinux"):
            security_features["selinux"]["enabled"] = True
            
            # Check SELinux mode
            result = run_command(["getenforce"])
            if result["success"]:
                security_features["selinux"]["mode"] = result["stdout"].strip()
        
        # Check AppArmor
        if os.path.exists("/sys/kernel/security/apparmor"):
            security_features["apparmor"]["enabled"] = True
            
            # Check AppArmor mode
            result = run_command(["aa-status"])
            if result["success"]:
                if "enforce mode" in result["stdout"]:
                    security_features["apparmor"]["mode"] = "enforcing"
                elif "complain mode" in result["stdout"]:
                    security_features["apparmor"]["mode"] = "complaining"
        
        # Check Seccomp
        result = run_command(["grep", "CONFIG_SECCOMP=y", "/boot/config-$(uname -r)"])
        security_features["seccomp"]["enabled"] = result["success"]
        
        # Check YAMA
        if os.path.exists("/proc/sys/kernel/yama/ptrace_scope"):
            security_features["yama"]["enabled"] = True
            with open("/proc/sys/kernel/yama/ptrace_scope", "r") as f:
                security_features["yama"]["ptrace_scope"] = f.read().strip()
        
        # Check NX (No Execute)
        result = run_command(["grep", "nx", "/proc/cpuinfo"])
        security_features["nx"]["enabled"] = "nx" in result["stdout"].lower()
        
        # Check ASLR (Address Space Layout Randomization)
        if os.path.exists("/proc/sys/kernel/randomize_va_space"):
            with open("/proc/sys/kernel/randomize_va_space", "r") as f:
                level = f.read().strip()
                security_features["aslr"]["enabled"] = level != "0"
                security_features["aslr"]["level"] = level
        
        # Check KASLR (Kernel Address Space Layout Randomization)
        result = run_command(["grep", "CONFIG_RANDOMIZE_BASE=y", "/boot/config-$(uname -r)"])
        security_features["kaslr"]["enabled"] = result["success"]
        
        # Check SMEP (Supervisor Mode Execution Prevention)
        result = run_command(["grep", "smep", "/proc/cpuinfo"])
        security_features["smep"]["enabled"] = "smep" in result["stdout"].lower()
        
        # Check SMAP (Supervisor Mode Access Prevention)
        result = run_command(["grep", "smap", "/proc/cpuinfo"])
        security_features["smap"]["enabled"] = "smap" in result["stdout"].lower()
        
        # Check Meltdown mitigation
        result = run_command(["grep", "PTI", "/proc/cpuinfo"])
        security_features["meltdown_mitigation"]["enabled"] = "pti" in result["stdout"].lower()
        
        # Check Spectre mitigation
        result = run_command(["grep", "spectre_v2", "/sys/devices/system/cpu/vulnerabilities/spectre_v2"])
        if result["success"]:
            security_features["spectre_mitigation"]["enabled"] = "vulnerable" not in result["stdout"].lower()
            security_features["spectre_mitigation"]["status"] = result["stdout"].strip()
    
    except Exception as e:
        logger.warning(f"Error checking kernel security features: {str(e)}")
    
    return security_features

def is_service_running(service_name):
    """
    Check if a systemd service is running
    
    Args:
        service_name (str): Name of the service
    
    Returns:
        bool: True if the service is running, False otherwise
    """
    if not is_linux():
        return False
    
    result = run_command(["systemctl", "is-active", service_name])
    return result["stdout"].strip() == "active"

def is_package_installed(package_name):
    """
    Check if a package is installed
    
    Args:
        package_name (str): Name of the package
    
    Returns:
        bool: True if the package is installed, False otherwise
    """
    if not is_linux():
        return False
    
    # Try apt (Debian/Ubuntu)
    result = run_command(["dpkg", "-l", package_name])
    if result["success"] and f"ii  {package_name}" in result["stdout"]:
        return True
    
    # Try rpm (RHEL/CentOS/Fedora)
    result = run_command(["rpm", "-q", package_name])
    if result["success"]:
        return True
    
    return False
