#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compliance checking module for DoctorGoatFramework
"""

import os
import sys
import logging
import json
import yaml
from pathlib import Path
from datetime import datetime

from lib.core.exceptions import ComplianceError
from lib.utils.helpers import is_linux, run_command, is_service_running, is_package_installed

logger = logging.getLogger("doctorgoat.compliance")

class ComplianceChecker:
    """Compliance checking implementation class"""
    
    def __init__(self, config_data):
        """
        Initialize the compliance checker module
        
        Args:
            config_data (dict): Configuration data
        """
        self.config_data = config_data
        self.compliance_enabled = config_data.get("compliance.enabled", False)
        self.compliance_standards = config_data.get("compliance.standards", [])
        self.custom_profiles_dir = config_data.get("compliance.custom_profiles_dir", "profiles")
        self.results = {}
    
    def check_compliance(self, standard, profile=None, level=None):
        """
        Check system compliance against a specific standard
        
        Args:
            standard (str): Compliance standard (e.g., 'cis', 'nist')
            profile (str, optional): Specific profile within the standard
            level (int, optional): Compliance level (1 or 2 for CIS)
            
        Returns:
            dict: Compliance check results
        """
        logger.info(f"Checking compliance against {standard.upper()} standard")
        
        # Validate the standard name
        if standard.lower() not in ['cis', 'nist', 'pci', 'hipaa', 'gdpr', 'custom']:
            raise ComplianceError(f"Unsupported compliance standard: {standard}")
        
        # Initialize results
        results = {
            "standard": standard.upper(),
            "profile": profile,
            "level": level,
            "status": "unchecked",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "issues": [],
            "findings": {},
            "compliance_score": 0.0,
            "total_checks": 0,
            "passed_checks": 0
        }
        
        try:
            # Call appropriate compliance checker based on standard
            if standard.lower() == 'cis':
                self._check_cis_compliance(results, profile, level)
            elif standard.lower() == 'nist':
                self._check_nist_compliance(results, profile)
            elif standard.lower() == 'pci':
                self._check_pci_compliance(results)
            elif standard.lower() == 'hipaa':
                self._check_hipaa_compliance(results)
            elif standard.lower() == 'gdpr':
                self._check_gdpr_compliance(results)
            elif standard.lower() == 'custom':
                self._check_custom_compliance(results, profile)
            
            # Calculate compliance score
            if results["total_checks"] > 0:
                results["compliance_score"] = (results["passed_checks"] / results["total_checks"]) * 100
            
            # Set final status
            if results["compliance_score"] >= 90:
                results["status"] = "compliant"
            elif results["compliance_score"] >= 75:
                results["status"] = "partially compliant"
            else:
                results["status"] = "non-compliant"
            
            logger.info(f"Compliance check completed with score: {results['compliance_score']:.2f}%")
            return results
            
        except Exception as e:
            logger.error(f"Error in compliance check: {str(e)}")
            results["status"] = "error"
            results["issues"].append({
                "severity": "error",
                "message": f"Compliance check error: {str(e)}"
            })
            return results
    
    def _check_cis_compliance(self, results, profile=None, level=None):
        """
        Check compliance against CIS benchmarks
        
        Args:
            results (dict): Results dictionary to update
            profile (str): CIS profile (server, workstation)
            level (int): CIS level (1 or 2)
        """
        logger.info(f"Checking CIS compliance (Profile: {profile}, Level: {level})")
        
        # Set defaults if not provided
        profile = profile or "server"
        level = level or 1
        
        # Validate inputs
        if profile not in ["server", "workstation"]:
            raise ComplianceError(f"Invalid CIS profile: {profile}")
        
        if level not in [1, 2]:
            raise ComplianceError(f"Invalid CIS level: {level}")
        
        # Load appropriate CIS benchmark
        benchmark_file = f"cis_{profile}_l{level}.json"
        benchmark_path = os.path.join(os.path.dirname(__file__), "../data/compliance", benchmark_file)
        
        # Check if benchmark file exists
        if not os.path.exists(benchmark_path):
            # Use placeholder checks for now
            cis_checks = self._get_placeholder_cis_checks(profile, level)
        else:
            with open(benchmark_path, 'r') as f:
                cis_checks = json.load(f)
        
        # Run CIS compliance checks
        for check in cis_checks:
            results["total_checks"] += 1
            
            check_id = check.get("id", "unknown")
            check_title = check.get("title", "Unknown check")
            check_description = check.get("description", "")
            check_remediation = check.get("remediation", "")
            check_severity = check.get("severity", "medium")
            
            logger.debug(f"Running CIS check {check_id}: {check_title}")
            
            check_result = self._run_compliance_check(check)
            
            if check_result["status"] == "passed":
                results["passed_checks"] += 1
            else:
                results["issues"].append({
                    "id": check_id,
                    "title": check_title,
                    "severity": check_severity,
                    "status": check_result["status"],
                    "message": check_result["message"],
                    "description": check_description,
                    "remediation": check_remediation,
                    "details": check_result.get("details", {})
                })
            
            # Add to findings
            results["findings"][check_id] = {
                "title": check_title,
                "status": check_result["status"],
                "severity": check_severity,
                "details": check_result.get("details", {})
            }
    
    def _get_placeholder_cis_checks(self, profile, level):
        """
        Get placeholder CIS checks for demonstration
        
        This is used when actual benchmark files are not available
        """
        return [
            {
                "id": "1.1.1",
                "title": "Ensure mounting of cramfs filesystems is disabled",
                "description": "The cramfs filesystem type is a compressed read-only Linux filesystem.",
                "severity": "medium",
                "check_type": "command",
                "command": "modprobe -n -v cramfs",
                "expected_output": "install /bin/true",
                "remediation": "Add 'install cramfs /bin/true' to /etc/modprobe.d/CIS.conf"
            },
            {
                "id": "1.1.22",
                "title": "Ensure sticky bit is set on all world-writable directories",
                "description": "Setting the sticky bit prevents users from deleting or renaming files in world writable directories that are not owned by them.",
                "severity": "high",
                "check_type": "command",
                "command": "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d -perm -0002 -a ! -perm -1000 2>/dev/null",
                "expected_output": "",
                "remediation": "find <world-writable-directory> -xdev -type d -perm -0002 -a ! -perm -1000 -exec chmod +t {} \\;"
            },
            {
                "id": "2.2.1",
                "title": "Ensure xinetd is not installed",
                "description": "The eXtended InterNET Daemon (xinetd) is an open source super daemon that replaced the original inetd daemon.",
                "severity": "medium",
                "check_type": "package",
                "package": "xinetd",
                "expected_state": "not_installed",
                "remediation": "apt purge xinetd"
            },
            {
                "id": "3.2.1",
                "title": "Ensure IP forwarding is disabled",
                "description": "IP forwarding allows packets to flow through a system from one network interface to another.",
                "severity": "medium",
                "check_type": "sysctl",
                "parameter": "net.ipv4.ip_forward",
                "expected_value": "0",
                "remediation": "Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf"
            },
            {
                "id": "5.2.1",
                "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
                "description": "The /etc/ssh/sshd_config file contains configuration specifications for sshd.",
                "severity": "high",
                "check_type": "file_permission",
                "file": "/etc/ssh/sshd_config",
                "expected_permission": "600",
                "expected_owner": "root",
                "expected_group": "root",
                "remediation": "chmod 600 /etc/ssh/sshd_config"
            }
        ]
    
    def _check_nist_compliance(self, results, profile=None):
        """
        Check compliance against NIST standards
        
        Args:
            results (dict): Results dictionary to update
            profile (str): NIST profile (800-53, 800-171, etc.)
        """
        logger.info(f"Checking NIST compliance (Profile: {profile})")
        
        # Implementation would go here
        # For now, use placeholder implementation
        results["status"] = "unchecked"
        results["issues"].append({
            "severity": "info",
            "message": f"NIST compliance checking not yet implemented for profile: {profile}"
        })
    
    def _check_pci_compliance(self, results):
        """
        Check compliance against PCI DSS
        
        Args:
            results (dict): Results dictionary to update
        """
        logger.info("Checking PCI DSS compliance")
        
        # Implementation would go here
        # For now, use placeholder implementation
        results["status"] = "unchecked"
        results["issues"].append({
            "severity": "info",
            "message": "PCI DSS compliance checking not yet implemented"
        })
    
    def _check_hipaa_compliance(self, results):
        """
        Check compliance against HIPAA
        
        Args:
            results (dict): Results dictionary to update
        """
        logger.info("Checking HIPAA compliance")
        
        # Implementation would go here
        # For now, use placeholder implementation
        results["status"] = "unchecked"
        results["issues"].append({
            "severity": "info",
            "message": "HIPAA compliance checking not yet implemented"
        })
    
    def _check_gdpr_compliance(self, results):
        """
        Check compliance against GDPR
        
        Args:
            results (dict): Results dictionary to update
        """
        logger.info("Checking GDPR compliance")
        
        # Implementation would go here
        # For now, use placeholder implementation
        results["status"] = "unchecked"
        results["issues"].append({
            "severity": "info",
            "message": "GDPR compliance checking not yet implemented"
        })
    
    def _check_custom_compliance(self, results, profile):
        """
        Check compliance against custom profile
        
        Args:
            results (dict): Results dictionary to update
            profile (str): Custom profile name
        """
        logger.info(f"Checking custom compliance (Profile: {profile})")
        
        if not profile:
            raise ComplianceError("Profile name is required for custom compliance checks")
        
        # Check if profile exists
        profile_path = os.path.join(self.custom_profiles_dir, f"{profile}.yaml")
        
        if not os.path.exists(profile_path):
            raise ComplianceError(f"Custom profile not found: {profile}")
        
        # Load custom profile
        try:
            with open(profile_path, 'r') as f:
                profile_data = yaml.safe_load(f)
        except Exception as e:
            raise ComplianceError(f"Error loading custom profile: {str(e)}")
        
        # Run custom compliance checks
        # Implementation would go here
        # For now, use placeholder implementation
        results["status"] = "unchecked"
        results["issues"].append({
            "severity": "info",
            "message": f"Custom compliance checking not yet fully implemented for profile: {profile}"
        })
    
    def _run_compliance_check(self, check):
        """
        Run a specific compliance check
        
        Args:
            check (dict): Check definition
            
        Returns:
            dict: Check result
        """
        check_type = check.get("check_type", "unknown")
        
        if check_type == "command":
            return self._run_command_check(check)
        elif check_type == "file_content":
            return self._run_file_content_check(check)
        elif check_type == "file_permission":
            return self._run_file_permission_check(check)
        elif check_type == "package":
            return self._run_package_check(check)
        elif check_type == "service":
            return self._run_service_check(check)
        elif check_type == "sysctl":
            return self._run_sysctl_check(check)
        else:
            return {
                "status": "unknown",
                "message": f"Unknown check type: {check_type}"
            }
    
    def _run_command_check(self, check):
        """Run a command-based compliance check"""
        command = check.get("command", "")
        expected_output = check.get("expected_output", "")
        expected_result = check.get("expected_result", 0)
        
        if not command:
            return {"status": "error", "message": "No command specified for check"}
        
        try:
            cmd_result = run_command(command.split())
            
            if expected_result is not None and cmd_result["exit_code"] != expected_result:
                return {
                    "status": "failed",
                    "message": f"Command returned exit code {cmd_result['exit_code']}, expected {expected_result}",
                    "details": {"output": cmd_result["stdout"], "error": cmd_result["stderr"]}
                }
            
            if expected_output is not None and expected_output not in cmd_result["stdout"]:
                return {
                    "status": "failed",
                    "message": f"Command output does not match expected output",
                    "details": {"output": cmd_result["stdout"], "expected": expected_output}
                }
            
            return {
                "status": "passed",
                "message": "Command check passed",
                "details": {"output": cmd_result["stdout"]}
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error running command check: {str(e)}"
            }
    
    def _run_file_content_check(self, check):
        """Run a file content compliance check"""
        # Implementation would go here
        # For now, return placeholder
        return {"status": "unknown", "message": "File content check not implemented"}
    
    def _run_file_permission_check(self, check):
        """Run a file permission compliance check"""
        # Implementation would go here
        # For now, return placeholder
        return {"status": "unknown", "message": "File permission check not implemented"}
    
    def _run_package_check(self, check):
        """Run a package compliance check"""
        package = check.get("package", "")
        expected_state = check.get("expected_state", "installed")
        
        if not package:
            return {"status": "error", "message": "No package specified for check"}
        
        try:
            is_installed = is_package_installed(package)
            
            if expected_state == "installed" and is_installed:
                return {
                    "status": "passed",
                    "message": f"Package {package} is installed as expected"
                }
            elif expected_state == "not_installed" and not is_installed:
                return {
                    "status": "passed",
                    "message": f"Package {package} is not installed as expected"
                }
            else:
                return {
                    "status": "failed",
                    "message": f"Package {package} state ({is_installed}) does not match expected state ({expected_state})"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking package: {str(e)}"
            }
    
    def _run_service_check(self, check):
        """Run a service compliance check"""
        service = check.get("service", "")
        expected_state = check.get("expected_state", "running")
        
        if not service:
            return {"status": "error", "message": "No service specified for check"}
        
        try:
            is_running = is_service_running(service)
            
            if expected_state == "running" and is_running:
                return {
                    "status": "passed",
                    "message": f"Service {service} is running as expected"
                }
            elif expected_state == "stopped" and not is_running:
                return {
                    "status": "passed",
                    "message": f"Service {service} is stopped as expected"
                }
            else:
                return {
                    "status": "failed",
                    "message": f"Service {service} state ({is_running}) does not match expected state ({expected_state})"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking service: {str(e)}"
            }
    
    def _run_sysctl_check(self, check):
        """Run a sysctl parameter compliance check"""
        parameter = check.get("parameter", "")
        expected_value = check.get("expected_value", "")
        
        if not parameter:
            return {"status": "error", "message": "No sysctl parameter specified for check"}
        
        try:
            cmd_result = run_command(["sysctl", "-n", parameter])
            
            if not cmd_result["success"]:
                return {
                    "status": "error",
                    "message": f"Error getting sysctl parameter {parameter}: {cmd_result['stderr']}"
                }
            
            current_value = cmd_result["stdout"].strip()
            
            if current_value == expected_value:
                return {
                    "status": "passed",
                    "message": f"Sysctl parameter {parameter} is set to expected value {expected_value}",
                    "details": {"current_value": current_value, "expected_value": expected_value}
                }
            else:
                return {
                    "status": "failed",
                    "message": f"Sysctl parameter {parameter} is set to {current_value}, expected {expected_value}",
                    "details": {"current_value": current_value, "expected_value": expected_value}
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking sysctl parameter: {str(e)}"
            }
    
    def remediate_issues(self, issues):
        """
        Remediate compliance issues
        
        Args:
            issues (list): List of compliance issues to remediate
            
        Returns:
            dict: Remediation results
        """
        logger.info(f"Remediating {len(issues)} compliance issues")
        
        remediation_results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_issues": len(issues),
            "remediated_issues": 0,
            "failed_remediations": 0,
            "skipped_remediations": 0,
            "results": []
        }
        
        for issue in issues:
            issue_id = issue.get("id", "unknown")
            issue_title = issue.get("title", "Unknown issue")
            remediation_command = issue.get("remediation", "")
            
            logger.info(f"Remediating issue {issue_id}: {issue_title}")
            
            if not remediation_command:
                logger.warning(f"No remediation command for issue {issue_id}")
                remediation_results["skipped_remediations"] += 1
                remediation_results["results"].append({
                    "id": issue_id,
                    "title": issue_title,
                    "status": "skipped",
                    "message": "No remediation command provided"
                })
                continue
            
            try:
                # Check if remediation command is a shell command or a function call
                if remediation_command.startswith("def:"):
                    # Function call
                    function_name = remediation_command[4:].strip()
                    # Not implemented yet
                    logger.warning(f"Function-based remediation not implemented: {function_name}")
                    remediation_results["skipped_remediations"] += 1
                    remediation_results["results"].append({
                        "id": issue_id,
                        "title": issue_title,
                        "status": "skipped",
                        "message": "Function-based remediation not implemented"
                    })
                else:
                    # Shell command
                    cmd_result = run_command(remediation_command.split())
                    
                    if cmd_result["success"]:
                        remediation_results["remediated_issues"] += 1
                        remediation_results["results"].append({
                            "id": issue_id,
                            "title": issue_title,
                            "status": "success",
                            "message": "Remediation successful",
                            "details": {"output": cmd_result["stdout"]}
                        })
                    else:
                        remediation_results["failed_remediations"] += 1
                        remediation_results["results"].append({
                            "id": issue_id,
                            "title": issue_title,
                            "status": "failed",
                            "message": f"Remediation failed: {cmd_result['stderr']}",
                            "details": {"error": cmd_result["stderr"]}
                        })
            
            except Exception as e:
                logger.error(f"Error remediating issue {issue_id}: {str(e)}")
                remediation_results["failed_remediations"] += 1
                remediation_results["results"].append({
                    "id": issue_id,
                    "title": issue_title,
                    "status": "error",
                    "message": f"Error during remediation: {str(e)}"
                })
        
        return remediation_results
