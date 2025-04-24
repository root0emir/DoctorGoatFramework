#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration management module for DoctorGoatFramework
"""

import os
import sys
import yaml
import json
import logging
import shutil
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("doctorgoat.config")

class Config:
    """Configuration management class for DoctorGoatFramework"""
    
    # Default configuration file path
    DEFAULT_CONFIG_FILE = "config.yaml"
    
    # Configuration schema version
    SCHEMA_VERSION = "1.0"
    
    def __init__(self, config_file=None):
        """
        Initialize the configuration manager
        
        Args:
            config_file (str, optional): Path to the configuration file. If None, uses default path.
        """
        self.config_file = config_file or self.DEFAULT_CONFIG_FILE
        self.config_data = {}
        self.backup_dir = os.path.join(os.path.dirname(os.path.abspath(self.config_file)), "backups")
        
        # Create backup directory if it doesn't exist
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def load(self):
        """
        Load the configuration file
        
        Returns:
            dict: Configuration data
        
        Raises:
            FileNotFoundError: When configuration file is not found
            yaml.YAMLError: When YAML file cannot be parsed
        """
        logger.debug(f"Loading configuration file: {self.config_file}")
        
        # Create default configuration if file doesn't exist
        if not os.path.exists(self.config_file):
            logger.warning(f"Configuration file not found: {self.config_file}")
            logger.info("Creating default configuration...")
            self._create_default_config()
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config_data = yaml.safe_load(f)
            
            # Validate configuration schema version
            if 'schema_version' not in self.config_data:
                logger.warning("No schema version in configuration file, adding current version")
                self.config_data['schema_version'] = self.SCHEMA_VERSION
                self.save()
            elif self.config_data['schema_version'] != self.SCHEMA_VERSION:
                logger.warning(f"Configuration schema version mismatch: {self.config_data['schema_version']} != {self.SCHEMA_VERSION}")
                self._migrate_config(self.config_data['schema_version'])
            
            # Validate required sections
            self._validate_config()
            
            logger.debug("Configuration successfully loaded")
            return self.config_data
        
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            raise
    
    def _create_default_config(self):
        """Create the default configuration file"""
        default_config = {
            "schema_version": self.SCHEMA_VERSION,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "general": {
                "report_format": "html",
                "max_threads": 4,
                "timeout": 30,
                "log_level": "INFO",
                "backup_enabled": True,
                "backup_retention_days": 7
            },
            "security": {
                "default_security_level": "medium",  # low, medium, high, extreme
                "user_audit": {
                    "enabled": True,
                    "check_root_access": True,
                    "check_sudo_config": True,
                    "check_password_policy": True,
                    "check_inactive_users": True,
                    "check_user_permissions": True,
                    "check_ssh_keys": True
                },
                "network_audit": {
                    "enabled": True,
                    "check_open_ports": True,
                    "check_firewall_rules": True,
                    "check_ssh_config": True,
                    "check_network_services": True,
                    "check_listening_services": True,
                    "check_dns_config": True,
                    "port_scan_timeout": 30
                },
                "software_audit": {
                    "enabled": True,
                    "check_updates": True,
                    "check_installed_packages": True,
                    "check_vulnerable_packages": True,
                    "check_package_integrity": True,
                    "check_service_versions": True,
                    "vulnerability_database": "nvd"  # nvd, oval, etc.
                },
                "filesystem_audit": {
                    "enabled": True,
                    "check_permissions": True,
                    "check_suid_sgid": True,
                    "check_world_writable": True,
                    "check_tmp_dirs": True,
                    "check_sticky_bits": True,
                    "check_file_integrity": True,
                    "excluded_paths": [
                        "/proc",
                        "/sys",
                        "/dev",
                        "/run",
                        "/media",
                        "/mnt"
                    ]
                },
                "kernel_audit": {
                    "enabled": True,
                    "check_sysctl_params": True,
                    "check_kernel_modules": True,
                    "check_kernel_hardening": True,
                    "check_boot_params": True
                },
                "service_audit": {
                    "enabled": True,
                    "check_service_configs": True,
                    "check_service_permissions": True,
                    "check_startup_scripts": True,
                    "services": [
                        "ssh", "apache2", "nginx", "mysql", "postgresql", 
                        "ftp", "nfs", "smb", "cups", "cron", "docker"
                    ]
                }
            },
            "hardening": {
                "kernel": {
                    "enabled": True,
                    "apply_sysctl": True,
                    "backup_before_changes": True
                },
                "ssh": {
                    "enabled": True,
                    "port": 22,
                    "permit_root_login": False,
                    "password_authentication": False,
                    "pubkey_authentication": True
                },
                "firewall": {
                    "enabled": True,
                    "default_policy": "deny",
                    "allowed_services": ["ssh"],
                    "allowed_ports": [22]
                },
                "authentication": {
                    "enabled": True,
                    "password_policy": True,
                    "account_lockout": True,
                    "pam_configuration": True
                },
                "permissions": {
                    "enabled": True,
                    "fix_file_permissions": True,
                    "fix_directory_permissions": True
                },
                "updates": {
                    "enabled": True,
                    "auto_update": True,
                    "security_only": True
                }
            },
            "compliance": {
                "enabled": True,
                "standards": [
                    {
                        "name": "CIS",
                        "enabled": True,
                        "level": 1,  # 1 or 2
                        "profile": "server"  # server or workstation
                    },
                    {
                        "name": "NIST",
                        "enabled": False,
                        "profile": "800-53"
                    }
                ],
                "custom_profiles_dir": "profiles"
            },
            "monitoring": {
                "enabled": False,
                "interval": 300,  # seconds
                "events": ["security", "auth", "network"],
                "alert_threshold": "medium",
                "log_dir": "logs/monitoring"
            },
            "reporting": {
                "include_system_info": True,
                "severity_levels": ["critical", "high", "medium", "low", "info"],
                "include_recommendations": True,
                "include_remediation": True,
                "output_formats": ["html", "json", "pdf", "txt"],
                "report_dir": "reports",
                "company_name": "",
                "logo_path": "",
                "email_report": {
                    "enabled": False,
                    "smtp_server": "",
                    "smtp_port": 587,
                    "smtp_user": "",
                    "smtp_password": "",
                    "recipients": []
                }
            }
        }
        
        try:
            # Create a backup directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(self.config_file)), exist_ok=True)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Default configuration file created: {self.config_file}")
            self.config_data = default_config
        
        except Exception as e:
            logger.error(f"Error creating default configuration: {str(e)}")
            raise
    
    def save(self):
        """
        Save configuration data to file
        
        Raises:
            IOError: File write error
        """
        try:
            # Create a backup of the existing config file if it exists
            if os.path.exists(self.config_file):
                self._backup_config()
            
            # Update the last modified timestamp
            self.config_data['last_modified'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, sort_keys=False)
            
            logger.debug(f"Configuration file saved: {self.config_file}")
        
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            raise
    
    def get(self, key, default=None):
        """
        Get the value of the specified key
        
        Args:
            key (str): Configuration key (with dot notation)
            default: Default value to return if key is not found
        
        Returns:
            Configuration value or default value
        """
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            logger.debug(f"Configuration key not found: {key}, returning default: {default}")
            return default
    
    def set(self, key, value):
        """
        Set the value of the specified key
        
        Args:
            key (str): Configuration key (with dot notation)
            value: Value to set
        """
        keys = key.split('.')
        config = self.config_data
        
        for i, k in enumerate(keys[:-1]):
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        logger.debug(f"Configuration value set: {key} = {value}")
    
    def _backup_config(self):
        """Create a backup of the current configuration file"""
        if not os.path.exists(self.config_file):
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(self.backup_dir, f"config_{timestamp}.yaml")
        
        try:
            shutil.copy2(self.config_file, backup_file)
            logger.debug(f"Configuration backup created: {backup_file}")
            
            # Clean up old backups
            self._cleanup_old_backups()
        except Exception as e:
            logger.warning(f"Failed to create configuration backup: {str(e)}")
    
    def _cleanup_old_backups(self):
        """Clean up old configuration backups"""
        retention_days = self.get("general.backup_retention_days", 7)
        if retention_days <= 0:
            return
        
        try:
            now = datetime.now()
            for backup_file in os.listdir(self.backup_dir):
                if not backup_file.startswith("config_") or not backup_file.endswith(".yaml"):
                    continue
                
                backup_path = os.path.join(self.backup_dir, backup_file)
                file_mtime = datetime.fromtimestamp(os.path.getmtime(backup_path))
                age_days = (now - file_mtime).days
                
                if age_days > retention_days:
                    os.remove(backup_path)
                    logger.debug(f"Removed old configuration backup: {backup_file} (age: {age_days} days)")
        except Exception as e:
            logger.warning(f"Failed to clean up old backups: {str(e)}")
    
    def _validate_config(self):
        """Validate the configuration structure and add missing sections"""
        required_sections = ["general", "security", "hardening", "compliance", "monitoring", "reporting"]
        
        for section in required_sections:
            if section not in self.config_data:
                logger.warning(f"Missing required section in configuration: {section}")
                # Get the section from default config
                default_config = self._get_default_config_template()
                if section in default_config:
                    self.config_data[section] = default_config[section]
                    logger.info(f"Added missing section to configuration: {section}")
    
    def _migrate_config(self, old_version):
        """Migrate configuration from an older schema version"""
        logger.info(f"Migrating configuration from version {old_version} to {self.SCHEMA_VERSION}")
        
        # Create a backup before migration
        self._backup_config()
        
        # Perform migration based on version
        # This is a simple example - in a real implementation, you would have
        # specific migration logic for each version transition
        
        # Update the schema version
        self.config_data['schema_version'] = self.SCHEMA_VERSION
        
        # Save the migrated configuration
        self.save()
        logger.info(f"Configuration successfully migrated to version {self.SCHEMA_VERSION}")
    
    def _get_default_config_template(self):
        """Get the default configuration template without creating a file"""
        # This is a simplified version - in a real implementation, you would
        # extract this from _create_default_config to avoid duplication
        return {
            "schema_version": self.SCHEMA_VERSION,
            "general": {
                "report_format": "html",
                "max_threads": 4,
                "timeout": 30,
                "log_level": "INFO"
            },
            "security": {
                "default_security_level": "medium"
            },
            "hardening": {
                "enabled": True
            },
            "compliance": {
                "enabled": True
            },
            "monitoring": {
                "enabled": False
            },
            "reporting": {
                "include_system_info": True
            }
        }
    
    def export_json(self, output_file=None):
        """Export configuration to JSON format"""
        if output_file is None:
            base_name = os.path.splitext(self.config_file)[0]
            output_file = f"{base_name}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.config_data, f, indent=2)
            
            logger.info(f"Configuration exported to JSON: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Error exporting configuration to JSON: {str(e)}")
            raise
    
    def import_json(self, input_file):
        """Import configuration from JSON format"""
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # Validate the imported configuration
            if 'schema_version' not in imported_config:
                logger.warning("No schema version in imported configuration")
                imported_config['schema_version'] = self.SCHEMA_VERSION
            
            # Backup current configuration
            self._backup_config()
            
            # Update configuration data
            self.config_data = imported_config
            
            # Save to YAML format
            self.save()
            
            logger.info(f"Configuration imported from JSON: {input_file}")
            return True
        except Exception as e:
            logger.error(f"Error importing configuration from JSON: {str(e)}")
            raise
    
    def reset_to_default(self):
        """Reset configuration to default values"""
        try:
            # Backup current configuration
            self._backup_config()
            
            # Create default configuration
            self._create_default_config()
            
            logger.info("Configuration reset to default values")
            return True
        except Exception as e:
            logger.error(f"Error resetting configuration: {str(e)}")
            raise
