#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Security audit module for DoctorGoatFramework
"""

import os
import sys
import logging
import platform
import subprocess
import re
import socket
import json
import time
from datetime import datetime
from pathlib import Path

from lib.core.exceptions import AuditError
from lib.utils.helpers import is_linux, run_command, is_service_running, is_package_installed

logger = logging.getLogger("doctorgoat.security_audit")

class SecurityAudit:
    """Security audit implementation class"""
    
    def __init__(self, config_data):
        """
        Initialize the security audit module
        
        Args:
            config_data (dict): Configuration data
        """
        self.config_data = config_data
        self.security_level = config_data.get("security.default_security_level", "medium")
        self.results = {}
    
    def run_user_audit(self):
        """
        Run user account security audit
        
        Returns:
            dict: Audit results
        """
        logger.info("Running user account security audit")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        if not is_linux():
            logger.warning("User audit is only supported on Linux")
            results["status"] = "skipped"
            results["issues"].append({
                "severity": "error",
                "message": "User audit is only supported on Linux"
            })
            return results
        
        try:
            # Check for users with UID 0 (root)
            if self.config_data.get("security.user_audit.check_root_access", True):
                self._check_root_users(results)
            
            # Check sudo configuration
            if self.config_data.get("security.user_audit.check_sudo_config", True):
                self._check_sudo_config(results)
            
            # Check password policy
            if self.config_data.get("security.user_audit.check_password_policy", True):
                self._check_password_policy(results)
            
            # Check for inactive users
            if self.config_data.get("security.user_audit.check_inactive_users", True):
                self._check_inactive_users(results)
            
            # Check user permissions
            if self.config_data.get("security.user_audit.check_user_permissions", True):
                self._check_user_permissions(results)
            
            # Check SSH keys
            if self.config_data.get("security.user_audit.check_ssh_keys", True):
                self._check_ssh_keys(results)
            
            logger.info(f"User audit completed with {len(results['issues'])} issues found")
            return results
        
        except Exception as e:
            logger.error(f"Error in user audit: {str(e)}")
            results["status"] = "error"
            results["issues"].append({
                "severity": "error",
                "message": f"User audit error: {str(e)}"
            })
            return results
    
    def _check_root_users(self, results):
        """Check for users with root privileges"""
        logger.debug("Checking for users with root privileges")
        
        try:
            # Get users with UID 0
            root_users = []
            
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[2] == "0":
                        root_users.append(parts[0])
            
            # Only root should have UID 0
            if len(root_users) > 1:
                non_root_users = [user for user in root_users if user != "root"]
                results["issues"].append({
                    "severity": "critical",
                    "message": f"Multiple users with UID 0 (root privileges): {', '.join(root_users)}",
                    "recommendation": "Remove root privileges (UID 0) from all users except the root user"
                })
            
            results["findings"]["root_users"] = root_users
            
        except Exception as e:
            logger.warning(f"Error checking root users: {str(e)}")
            results["issues"].append({
                "severity": "warning",
                "message": f"Could not check for root users: {str(e)}"
            })
    
    def _check_sudo_config(self, results):
        """Check sudo configuration"""
        logger.debug("Checking sudo configuration")
        
        try:
            # Check if sudo is installed
            if not is_package_installed("sudo"):
                results["issues"].append({
                    "severity": "info",
                    "message": "Sudo is not installed",
                    "recommendation": "Install sudo for better access control"
                })
                return
            
            # Check for empty sudo passwords
            cmd_result = run_command(["grep", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d/*"])
            
            if cmd_result["success"] and cmd_result["stdout"]:
                results["issues"].append({
                    "severity": "high",
                    "message": "NOPASSWD directive found in sudo configuration",
                    "recommendation": "Remove NOPASSWD directives from /etc/sudoers and /etc/sudoers.d/*"
                })
            
            # Check sudo log file
            cmd_result = run_command(["grep", "logfile", "/etc/sudoers"])
            
            if not (cmd_result["success"] and "logfile" in cmd_result["stdout"]):
                results["issues"].append({
                    "severity": "medium",
                    "message": "Sudo logging not enabled",
                    "recommendation": "Enable sudo logging by adding 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers"
                })
            
            # Check sudo timeout
            cmd_result = run_command(["grep", "timestamp_timeout", "/etc/sudoers"])
            
            if not (cmd_result["success"] and "timestamp_timeout" in cmd_result["stdout"]):
                results["issues"].append({
                    "severity": "low",
                    "message": "Sudo timeout not configured",
                    "recommendation": "Set sudo timeout by adding 'Defaults timestamp_timeout=15' to /etc/sudoers"
                })
            
        except Exception as e:
            logger.warning(f"Error checking sudo configuration: {str(e)}")
            results["issues"].append({
                "severity": "warning",
                "message": f"Could not check sudo configuration: {str(e)}"
            })
    
    def _check_password_policy(self, results):
        """Check password policy"""
        logger.debug("Checking password policy")
        
        try:
            # Check PAM password configuration
            if os.path.exists("/etc/pam.d/common-password"):
                pam_file = "/etc/pam.d/common-password"
            elif os.path.exists("/etc/pam.d/system-auth"):
                pam_file = "/etc/pam.d/system-auth"
            else:
                results["issues"].append({
                    "severity": "info",
                    "message": "Password policy PAM file not found",
                    "recommendation": "Check that PAM is properly configured"
                })
                return
            
            # Read password policy
            with open(pam_file, "r") as f:
                pam_content = f.read()
            
            # Check complexity requirements
            if "pam_pwquality.so" in pam_content or "pam_cracklib.so" in pam_content:
                # Check for minimum length
                if not re.search(r"minlen=(\d+)", pam_content) or re.search(r"minlen=([0-7])\b", pam_content):
                    results["issues"].append({
                        "severity": "medium",
                        "message": "Password minimum length not properly configured",
                        "recommendation": "Set minimum password length to at least 8 characters"
                    })
                
                # Check for complexity requirements
                if not (re.search(r"ucredit=-1", pam_content) and 
                        re.search(r"lcredit=-1", pam_content) and 
                        re.search(r"dcredit=-1", pam_content) and 
                        re.search(r"ocredit=-1", pam_content)):
                    results["issues"].append({
                        "severity": "medium",
                        "message": "Password complexity requirements not properly configured",
                        "recommendation": "Configure password complexity to require uppercase, lowercase, digits, and special characters"
                    })
            else:
                results["issues"].append({
                    "severity": "high",
                    "message": "Password quality checking not enabled",
                    "recommendation": "Install and configure pam_pwquality.so or pam_cracklib.so"
                })
            
            # Check /etc/login.defs
            if os.path.exists("/etc/login.defs"):
                with open("/etc/login.defs", "r") as f:
                    login_defs = f.read()
                
                # Check password expiration
                if not re.search(r"PASS_MAX_DAYS\s+[0-9]+", login_defs) or re.search(r"PASS_MAX_DAYS\s+9[0-9]|[1-9][0-9]{2,}", login_defs):
                    results["issues"].append({
                        "severity": "medium",
                        "message": "Password expiration policy not properly configured",
                        "recommendation": "Set PASS_MAX_DAYS to 90 days or less in /etc/login.defs"
                    })
        
        except Exception as e:
            logger.warning(f"Error checking password policy: {str(e)}")
            results["issues"].append({
                "severity": "warning",
                "message": f"Could not check password policy: {str(e)}"
            })
    
    def _check_inactive_users(self, results):
        """Check for inactive user accounts"""
        logger.debug("Checking for inactive user accounts")
        
        # Implementation would go here
        pass
    
    def _check_user_permissions(self, results):
        """Check user permissions"""
        logger.debug("Checking user permissions")
        
        # Implementation would go here
        pass
    
    def _check_ssh_keys(self, results):
        """Check SSH keys security"""
        logger.debug("Checking SSH keys security")
        
        # Implementation would go here
        pass
    
    def run_network_audit(self):
        """
        Run network security audit
        
        Returns:
            dict: Audit results
        """
        logger.info("Running network security audit")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        # Implementation would scan open ports, check firewall rules, etc.
        # Placeholder implementation
        
        return results
    
    def run_software_audit(self):
        """
        Run software security audit
        
        Returns:
            dict: Audit results
        """
        logger.info("Running software security audit")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        # Implementation would check for updates, vulnerable packages, etc.
        # Placeholder implementation
        
        return results
    
    def run_filesystem_audit(self):
        """
        Run filesystem security audit
        
        Returns:
            dict: Audit results
        """
        logger.info("Running filesystem security audit")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        # Implementation would check file permissions, SUID/SGID files, etc.
        # Placeholder implementation
        
        return results
    
    def run_kernel_audit(self):
        """
        Run kernel security audit
        
        Returns:
            dict: Audit results
        """
        logger.info("Running kernel security audit")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        # Implementation would check kernel parameters, hardening, etc.
        # Placeholder implementation
        
        return results
    
    def run_service_audit(self):
        """
        Run service configuration security audit
        
        Returns:
            dict: Audit results
        """
        logger.info("Running service configuration security audit")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        # Implementation would check service configurations, permissions, etc.
        # Placeholder implementation
        
        return results
    
    def run_port_scan(self):
        """
        Run port scan to identify open ports
        
        Returns:
            dict: Scan results
        """
        logger.info("Scanning for open ports")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        # Implementation would scan for open ports
        # Placeholder implementation
        
        return results
    
    def run_vulnerability_scan(self):
        """
        Run vulnerability scan to identify known vulnerabilities
        
        Returns:
            dict: Scan results
        """
        logger.info("Scanning for known vulnerabilities")
        
        results = {
            "status": "completed",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {}
        }
        
        # Implementation would scan for known vulnerabilities
        # Placeholder implementation
        
        return results
