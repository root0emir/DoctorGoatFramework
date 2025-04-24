#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Security monitoring module for DoctorGoatFramework
"""

import os
import sys
import logging
import time
import json
import threading
import signal
from datetime import datetime
from pathlib import Path

try:
    import pyinotify
except ImportError:
    pyinotify = None

from lib.core.exceptions import MonitoringError
from lib.utils.helpers import is_linux, run_command

logger = logging.getLogger("doctorgoat.monitoring")

class SecurityMonitor:
    """Security monitoring implementation class"""
    
    def __init__(self, config_data, alert_threshold=None):
        """
        Initialize the security monitoring module
        
        Args:
            config_data (dict): Configuration data
            alert_threshold (str, optional): Alert threshold (low, medium, high, critical)
        """
        self.config_data = config_data
        self.monitoring_enabled = config_data.get("monitoring.enabled", False)
        self.monitoring_interval = config_data.get("monitoring.interval", 300)  # seconds
        self.event_types = config_data.get("monitoring.events", ["security", "auth", "network"])
        self.alert_threshold = alert_threshold or config_data.get("monitoring.alert_threshold", "medium")
        self.log_dir = config_data.get("monitoring.log_dir", "logs/monitoring")
        self.results = {}
        self.stop_monitoring = False
    
    def monitor_events(self, event_types=None, duration=None):
        """
        Monitor security events in real-time
        
        Args:
            event_types (list, optional): List of event types to monitor
            duration (int, optional): Monitoring duration in seconds
            
        Returns:
            dict: Monitoring results
        """
        logger.info("Starting security monitoring")
        
        # Use provided event types or default from config
        event_types = event_types or self.event_types
        
        if not isinstance(event_types, list):
            event_types = [event_types]
        
        results = {
            "status": "started",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_types": event_types,
            "alert_threshold": self.alert_threshold,
            "alerts": [],
            "events": {}
        }
        
        if not is_linux():
            logger.warning("Security monitoring is only supported on Linux")
            results["status"] = "unsupported"
            results["message"] = "Security monitoring is only supported on Linux"
            return results
        
        try:
            # Create log directory if it doesn't exist
            os.makedirs(self.log_dir, exist_ok=True)
            
            # Set up monitoring threads
            monitor_threads = []
            
            # Set up event handler for each event type
            for event_type in event_types:
                if event_type == "security":
                    thread = threading.Thread(target=self._monitor_security_events, args=(results,))
                    monitor_threads.append(thread)
                    thread.start()
                
                elif event_type == "auth":
                    thread = threading.Thread(target=self._monitor_auth_events, args=(results,))
                    monitor_threads.append(thread)
                    thread.start()
                
                elif event_type == "network":
                    thread = threading.Thread(target=self._monitor_network_events, args=(results,))
                    monitor_threads.append(thread)
                    thread.start()
                
                elif event_type == "filesystem":
                    if pyinotify:
                        thread = threading.Thread(target=self._monitor_filesystem_events, args=(results,))
                        monitor_threads.append(thread)
                        thread.start()
                    else:
                        logger.warning("pyinotify module not available, filesystem monitoring disabled")
                
                else:
                    logger.warning(f"Unknown event type: {event_type}")
            
            # Set up signal handler to stop monitoring
            def signal_handler(sig, frame):
                logger.info("Stopping monitoring due to signal")
                self.stop_monitoring = True
            
            original_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, signal_handler)
            
            # Monitor for the specified duration or until stopped
            if duration:
                logger.info(f"Monitoring for {duration} seconds")
                start_time = time.time()
                
                while not self.stop_monitoring and time.time() - start_time < duration:
                    time.sleep(1)
                
                self.stop_monitoring = True
            else:
                logger.info("Monitoring until stopped")
                
                while not self.stop_monitoring:
                    time.sleep(1)
            
            # Wait for all threads to complete
            for thread in monitor_threads:
                thread.join()
            
            # Restore original signal handler
            signal.signal(signal.SIGINT, original_handler)
            
            # Update results
            results["status"] = "completed"
            results["end_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Save results to file
            results_file = os.path.join(self.log_dir, f"monitoring_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Monitoring results saved to {results_file}")
            return results
            
        except Exception as e:
            logger.error(f"Error in security monitoring: {str(e)}")
            results["status"] = "error"
            results["message"] = f"Security monitoring error: {str(e)}"
            return results
    
    def _monitor_security_events(self, results):
        """
        Monitor security events from the kernel audit system
        
        Args:
            results (dict): Results dictionary to update
        """
        logger.info("Monitoring security events")
        
        try:
            # Check if auditd is installed and running
            if not is_linux():
                logger.warning("Security events monitoring is only supported on Linux")
                return
            
            if not os.path.exists("/usr/bin/ausearch"):
                logger.warning("auditd not installed, security events monitoring disabled")
                return
            
            # Initialize events list for this type
            if "security" not in results["events"]:
                results["events"]["security"] = []
            
            # Monitor security events
            start_time = time.time()
            
            while not self.stop_monitoring:
                try:
                    # Get new security events
                    cmd = ["ausearch", "-ts", "recent", "-m", "AVC,USER_AVC,SELINUX_ERR"]
                    cmd_result = run_command(cmd)
                    
                    if cmd_result["success"] and cmd_result["stdout"]:
                        # Parse events
                        events = self._parse_audit_events(cmd_result["stdout"])
                        
                        # Process events
                        for event in events:
                            # Add event to results
                            results["events"]["security"].append(event)
                            
                            # Check if event severity is above threshold
                            if self._is_above_threshold(event["severity"], self.alert_threshold):
                                # Create alert
                                alert = {
                                    "timestamp": event["timestamp"],
                                    "type": "security",
                                    "severity": event["severity"],
                                    "message": event["message"],
                                    "details": event
                                }
                                
                                # Add alert to results
                                results["alerts"].append(alert)
                                
                                logger.warning(f"Security alert: {event['message']}")
                    
                    # Sleep for a while
                    time.sleep(10)
                    
                except Exception as e:
                    logger.error(f"Error monitoring security events: {str(e)}")
                    time.sleep(30)
            
            logger.info("Security events monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error in security events monitoring: {str(e)}")
    
    def _monitor_auth_events(self, results):
        """
        Monitor authentication events
        
        Args:
            results (dict): Results dictionary to update
        """
        logger.info("Monitoring authentication events")
        
        try:
            # Initialize events list for this type
            if "auth" not in results["events"]:
                results["events"]["auth"] = []
            
            # Check auth log file
            auth_log = "/var/log/auth.log"
            if not os.path.exists(auth_log):
                # Try alternatives
                if os.path.exists("/var/log/secure"):
                    auth_log = "/var/log/secure"
                else:
                    logger.warning("Authentication log file not found, auth events monitoring disabled")
                    return
            
            # Get current position
            file_size = os.path.getsize(auth_log)
            
            # Open log file
            with open(auth_log, 'r') as f:
                # Seek to end of file
                f.seek(file_size)
                
                # Monitor log file
                while not self.stop_monitoring:
                    # Get new log entries
                    line = f.readline()
                    
                    # If no new line, sleep and continue
                    if not line:
                        time.sleep(1)
                        continue
                    
                    # Parse log entry
                    event = self._parse_auth_log_entry(line)
                    
                    if event:
                        # Add event to results
                        results["events"]["auth"].append(event)
                        
                        # Check if event severity is above threshold
                        if self._is_above_threshold(event["severity"], self.alert_threshold):
                            # Create alert
                            alert = {
                                "timestamp": event["timestamp"],
                                "type": "auth",
                                "severity": event["severity"],
                                "message": event["message"],
                                "details": event
                            }
                            
                            # Add alert to results
                            results["alerts"].append(alert)
                            
                            logger.warning(f"Authentication alert: {event['message']}")
            
            logger.info("Authentication events monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error in authentication events monitoring: {str(e)}")
    
    def _monitor_network_events(self, results):
        """
        Monitor network events
        
        Args:
            results (dict): Results dictionary to update
        """
        logger.info("Monitoring network events")
        
        try:
            # Initialize events list for this type
            if "network" not in results["events"]:
                results["events"]["network"] = []
            
            # Monitor network events
            start_time = time.time()
            last_scan_time = start_time
            
            while not self.stop_monitoring:
                current_time = time.time()
                
                # Run port scan every 5 minutes
                if current_time - last_scan_time >= 300:
                    # Scan for open ports
                    cmd = ["netstat", "-tuln"]
                    cmd_result = run_command(cmd)
                    
                    if cmd_result["success"]:
                        # Parse open ports
                        open_ports = self._parse_netstat_output(cmd_result["stdout"])
                        
                        # Check for new ports
                        for port_info in open_ports:
                            # Add event to results
                            event = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "network",
                                "subtype": "open_port",
                                "severity": "medium",
                                "message": f"Open port: {port_info['port']} ({port_info['protocol']}) on {port_info['address']}",
                                "details": port_info
                            }
                            
                            results["events"]["network"].append(event)
                            
                            # Check if event severity is above threshold
                            if self._is_above_threshold(event["severity"], self.alert_threshold):
                                # Create alert
                                alert = {
                                    "timestamp": event["timestamp"],
                                    "type": "network",
                                    "severity": event["severity"],
                                    "message": event["message"],
                                    "details": event
                                }
                                
                                # Add alert to results
                                results["alerts"].append(alert)
                                
                                logger.warning(f"Network alert: {event['message']}")
                    
                    last_scan_time = current_time
                
                # Sleep for a while
                time.sleep(10)
            
            logger.info("Network events monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error in network events monitoring: {str(e)}")
    
    def _monitor_filesystem_events(self, results):
        """
        Monitor filesystem events
        
        Args:
            results (dict): Results dictionary to update
        """
        logger.info("Monitoring filesystem events")
        
        try:
            # Check if pyinotify is available
            if not pyinotify:
                logger.warning("pyinotify module not available, filesystem monitoring disabled")
                return
            
            # Initialize events list for this type
            if "filesystem" not in results["events"]:
                results["events"]["filesystem"] = []
            
            # Set up pyinotify
            wm = pyinotify.WatchManager()
            mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB
            
            # Define event handler
            class EventHandler(pyinotify.ProcessEvent):
                def process_default(self, event):
                    # Create event
                    fs_event = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "filesystem",
                        "subtype": event.maskname,
                        "severity": "medium",
                        "message": f"Filesystem event: {event.maskname} on {event.pathname}",
                        "details": {
                            "path": event.pathname,
                            "mask": event.mask,
                            "maskname": event.maskname
                        }
                    }
                    
                    # Add event to results
                    results["events"]["filesystem"].append(fs_event)
                    
                    # Check if event severity is above threshold
                    if self._is_above_threshold(fs_event["severity"], self.alert_threshold):
                        # Create alert
                        alert = {
                            "timestamp": fs_event["timestamp"],
                            "type": "filesystem",
                            "severity": fs_event["severity"],
                            "message": fs_event["message"],
                            "details": fs_event
                        }
                        
                        # Add alert to results
                        results["alerts"].append(alert)
                        
                        logger.warning(f"Filesystem alert: {fs_event['message']}")
            
            # Start monitoring
            handler = EventHandler()
            notifier = pyinotify.ThreadedNotifier(wm, handler)
            notifier.start()
            
            # Add watches
            wdd = wm.add_watch(["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"], mask, rec=True)
            
            # Monitor until stopped
            while not self.stop_monitoring:
                time.sleep(1)
            
            # Stop notifier
            notifier.stop()
            
            logger.info("Filesystem events monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error in filesystem events monitoring: {str(e)}")
    
    def _parse_audit_events(self, audit_output):
        """
        Parse audit events from ausearch output
        
        Args:
            audit_output (str): ausearch output
            
        Returns:
            list: Parsed events
        """
        events = []
        
        # Split output into individual events
        audit_events = audit_output.strip().split("----")
        
        for audit_event in audit_events:
            if not audit_event.strip():
                continue
            
            # Extract event details
            event = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "security",
                "subtype": "audit",
                "severity": "medium",
                "message": audit_event.strip().split("\n")[0] if audit_event.strip() else "Unknown audit event",
                "details": {
                    "raw": audit_event.strip()
                }
            }
            
            # Extract specific fields
            for line in audit_event.strip().split("\n"):
                if "type=" in line:
                    event["subtype"] = line.split("type=")[1].split(" ")[0]
                
                if "avc:" in line.lower():
                    event["severity"] = "high"
                    event["message"] = line.strip()
            
            events.append(event)
        
        return events
    
    def _parse_auth_log_entry(self, log_entry):
        """
        Parse authentication log entry
        
        Args:
            log_entry (str): Log entry line
            
        Returns:
            dict: Parsed event or None if not relevant
        """
        if not log_entry.strip():
            return None
        
        # Default event
        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "auth",
            "subtype": "unknown",
            "severity": "low",
            "message": log_entry.strip(),
            "details": {
                "raw": log_entry.strip()
            }
        }
        
        # Extract timestamp if present
        if log_entry[:15].count(":") == 2:
            event["timestamp"] = log_entry[:15]
        
        # Check for specific patterns
        if "failed password" in log_entry.lower():
            event["subtype"] = "failed_password"
            event["severity"] = "medium"
        
        elif "authentication failure" in log_entry.lower():
            event["subtype"] = "auth_failure"
            event["severity"] = "medium"
        
        elif "invalid user" in log_entry.lower():
            event["subtype"] = "invalid_user"
            event["severity"] = "medium"
        
        elif "root login" in log_entry.lower():
            event["subtype"] = "root_login"
            event["severity"] = "high"
        
        elif "sudo:" in log_entry.lower():
            event["subtype"] = "sudo"
            event["severity"] = "low"
            
            if "command not allowed" in log_entry.lower():
                event["severity"] = "high"
        
        elif "ssh" in log_entry.lower() and "opened" in log_entry.lower():
            event["subtype"] = "ssh_session"
            event["severity"] = "low"
        
        else:
            # Not a relevant auth event
            return None
        
        return event
    
    def _parse_netstat_output(self, netstat_output):
        """
        Parse netstat output to get open ports
        
        Args:
            netstat_output (str): netstat output
            
        Returns:
            list: Open ports information
        """
        open_ports = []
        
        # Skip header lines
        lines = netstat_output.strip().split("\n")[2:]
        
        for line in lines:
            parts = line.split()
            
            if len(parts) < 5:
                continue
            
            protocol = parts[0]
            local_address = parts[3]
            
            # Parse address and port
            if ":" in local_address:
                address, port = local_address.rsplit(":", 1)
            else:
                address = local_address
                port = ""
            
            # Add port information
            port_info = {
                "protocol": protocol,
                "address": address,
                "port": port,
                "state": parts[5] if len(parts) > 5 else "unknown",
                "pid": parts[6].split("/")[0] if len(parts) > 6 and "/" in parts[6] else "",
                "program": parts[6].split("/")[1] if len(parts) > 6 and "/" in parts[6] else ""
            }
            
            open_ports.append(port_info)
        
        return open_ports
    
    def _is_above_threshold(self, severity, threshold):
        """
        Check if severity is above threshold
        
        Args:
            severity (str): Event severity
            threshold (str): Alert threshold
            
        Returns:
            bool: True if severity is above threshold
        """
        severity_levels = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3
        }
        
        # Convert to lowercase
        severity = severity.lower()
        threshold = threshold.lower()
        
        # If severity or threshold is not recognized, use default values
        severity_value = severity_levels.get(severity, 1)  # Default to medium
        threshold_value = severity_levels.get(threshold, 1)  # Default to medium
        
        return severity_value >= threshold_value
