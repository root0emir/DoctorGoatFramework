#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DoctorGoatFramework - Advanced Linux System Security Audit and Hardening Framework
"""

# WARNING




import os
import sys
import argparse
import logging
import platform
import subprocess
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.prompt import Confirm

from lib.core.config import Config
from lib.core.logger import setup_logger
from lib.core.exceptions import DoctorGoatError
from lib.modules.system_info import SystemInfo
from lib.modules.security_audit import SecurityAudit
from lib.modules.system_hardening import SystemHardening
from lib.modules.compliance import ComplianceChecker
from lib.modules.monitoring import SecurityMonitor
from lib.modules.report_generator import ReportGenerator
from lib.utils.helpers import check_root, is_linux, backup_system

__version__ = "1.0"
__author__ = " root0emir - Securonis GNU/Linux Network and System Technologies Research Laboratory"

console = Console()

def show_banner():
    """Display the framework banner"""
    banner = """

    ____             __             ______            __ 
   / __ \____  _____/ /_____  _____/ ____/___  ____ _/ /_
  / / / / __ \/ ___/ __/ __ \/ ___/ / __/ __ \/ __ `/ __/
 / /_/ / /_/ / /__/ /_/ /_/ / /  / /_/ / /_/ / /_/ / /_  
/_____/\____/\___/\__/\____/_/   \____/\____/\__,_/\__/  
                                                         


                                                        
    Doctor Goat Linux Security Framework v{} - {}
    """.format(__version__, __author__)
    
    console.print(Panel(banner, style="bold blue", subtitle="Security • Compliance • Hardening"))

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="DoctorGoatFramework - Advanced Linux System Security Audit and Hardening Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Run a complete security audit
  python doctorgoat.py --scan-all
  
  # Harden system with high security level
  python doctorgoat.py --harden --level=high
  
  # Check CIS compliance
  python doctorgoat.py --compliance=cis
  
  # Monitor system in real-time
  python doctorgoat.py --monitor --events=security
"""
    )
    
    # General options
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument("--version", action="version", version=f"DoctorGoatFramework v{__version__}")
    general_group.add_argument("--config", help="Path to configuration file", default="config.yaml")
    general_group.add_argument("--output", help="Report output directory", default="reports")
    general_group.add_argument("--log-level", help="Log level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    general_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    general_group.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error messages")
    general_group.add_argument("--backup", action="store_true", help="Create system configuration backup before making changes")
    
    # Audit modules
    audit_group = parser.add_argument_group("Security Audit Options")
    audit_group.add_argument("--scan-all", action="store_true", help="Run all security audits")
    audit_group.add_argument("--system-info", action="store_true", help="Collect system information only")
    audit_group.add_argument("--user-audit", action="store_true", help="Audit user accounts and permissions")
    audit_group.add_argument("--network-audit", action="store_true", help="Audit network security")
    audit_group.add_argument("--software-audit", action="store_true", help="Audit software updates and vulnerabilities")
    audit_group.add_argument("--filesystem-audit", action="store_true", help="Audit filesystem security")
    audit_group.add_argument("--kernel-audit", action="store_true", help="Audit kernel security parameters")
    audit_group.add_argument("--service-audit", action="store_true", help="Audit service configurations")
    audit_group.add_argument("--scan-ports", action="store_true", help="Scan for open ports")
    audit_group.add_argument("--scan-vulnerabilities", action="store_true", help="Scan for known vulnerabilities")
    
    # Hardening options
    hardening_group = parser.add_argument_group("System Hardening Options")
    hardening_group.add_argument("--harden", action="store_true", help="Apply system hardening measures")
    hardening_group.add_argument("--level", choices=["low", "medium", "high", "extreme"], default="medium", 
                              help="Hardening security level")
    hardening_group.add_argument("--harden-kernel", action="store_true", help="Apply kernel security parameters")
    hardening_group.add_argument("--harden-ssh", action="store_true", help="Harden SSH configuration")
    hardening_group.add_argument("--harden-firewall", action="store_true", help="Configure and optimize firewall")
    hardening_group.add_argument("--harden-auth", action="store_true", help="Harden authentication mechanisms")
    hardening_group.add_argument("--harden-permissions", action="store_true", help="Harden file permissions")
    hardening_group.add_argument("--auto-update", action="store_true", help="Configure automatic security updates")
    
    # Compliance options
    compliance_group = parser.add_argument_group("Compliance Options")
    compliance_group.add_argument("--compliance", choices=["cis", "nist", "pci", "hipaa", "gdpr", "custom"], 
                                help="Check compliance against specified standard")
    compliance_group.add_argument("--profile", help="Path to custom compliance profile")
    compliance_group.add_argument("--remediate", action="store_true", help="Attempt to remediate compliance issues")
    
    # Monitoring options
    monitoring_group = parser.add_argument_group("Monitoring Options")
    monitoring_group.add_argument("--monitor", action="store_true", help="Enable real-time security monitoring")
    monitoring_group.add_argument("--events", choices=["all", "security", "network", "filesystem", "auth"], 
                               default="security", help="Event types to monitor")
    monitoring_group.add_argument("--duration", type=int, help="Monitoring duration in seconds")
    monitoring_group.add_argument("--alert-threshold", choices=["low", "medium", "high", "critical"], 
                                default="medium", help="Alert threshold level")
    
    return parser.parse_args()

def main():
    """Main program function"""
    show_banner()
    
    args = parse_arguments()
    
    # Configure logging
    setup_logger(args.log_level)
    logger = logging.getLogger("doctorgoat")
    
    # Check if running on Linux
    if not is_linux() and not args.system_info:
        console.print("[bold red]Error: DoctorGoatFramework is designed for Linux systems![/bold red]")
        console.print("[yellow]You can still use --system-info to collect basic system information.[/yellow]")
        return 1
    
    # Check for root privileges for certain operations
    if not check_root() and (args.harden or args.remediate or args.scan_all):
        console.print("[bold yellow]Warning: Some operations require root privileges![/bold yellow]")
        console.print("[yellow]Limited functionality will be available.[/yellow]")
        if not Confirm.ask("Continue with limited functionality?"):
            return 0
    
    # Load configuration
    try:
        config = Config(args.config)
        config_data = config.load()
        logger.debug("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        console.print(f"[bold red]Error loading configuration: {str(e)}[/bold red]")
        return 1
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(args.output, f"security_report_{timestamp}.html")
    
    # Create backup if requested
    if args.backup:
        try:
            backup_path = backup_system()
            console.print(f"[bold green]System configuration backup created: {backup_path}[/bold green]")
        except Exception as e:
            logger.error(f"Error creating backup: {str(e)}")
            console.print(f"[bold red]Error creating backup: {str(e)}[/bold red]")
            if not Confirm.ask("Continue without backup?"):
                return 1
    
    try:
        # Initialize results dictionary
        results = {
            "system_info": {},
            "audit_results": {},
            "hardening_results": {},
            "compliance_results": {},
            "monitoring_results": {}
        }
        
        # Collect system information
        if not args.quiet:
            console.print("[bold green]Collecting system information...[/bold green]")
        
        system_info = SystemInfo()
        results["system_info"] = system_info.collect()
        
        # Create progress bar for operations
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(),
            TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
            TimeElapsedColumn(),
        )
        
        # Security Audit
        if args.scan_all or args.user_audit or args.network_audit or args.software_audit or \
           args.filesystem_audit or args.kernel_audit or args.service_audit or \
           args.scan_ports or args.scan_vulnerabilities:
            
            if not args.quiet:
                console.print("\n[bold blue]Running Security Audits[/bold blue]")
            
            security_audit = SecurityAudit(config_data)
            
            with progress:
                # Calculate total tasks
                total_tasks = 0
                if args.scan_all or args.user_audit: total_tasks += 1
                if args.scan_all or args.network_audit: total_tasks += 1
                if args.scan_all or args.software_audit: total_tasks += 1
                if args.scan_all or args.filesystem_audit: total_tasks += 1
                if args.scan_all or args.kernel_audit: total_tasks += 1
                if args.scan_all or args.service_audit: total_tasks += 1
                if args.scan_all or args.scan_ports: total_tasks += 1
                if args.scan_all or args.scan_vulnerabilities: total_tasks += 1
                
                task_id = progress.add_task("Running security audits...", total=total_tasks)
                
                # User audit
                if args.scan_all or args.user_audit:
                    if not args.quiet:
                        console.print("[yellow]  → Running user and permission audit...[/yellow]")
                    results["audit_results"]["user_audit"] = security_audit.run_user_audit()
                    progress.update(task_id, advance=1)
                
                # Network audit
                if args.scan_all or args.network_audit:
                    if not args.quiet:
                        console.print("[yellow]  → Running network security audit...[/yellow]")
                    results["audit_results"]["network_audit"] = security_audit.run_network_audit()
                    progress.update(task_id, advance=1)
                
                # Software audit
                if args.scan_all or args.software_audit:
                    if not args.quiet:
                        console.print("[yellow]  → Running software update audit...[/yellow]")
                    results["audit_results"]["software_audit"] = security_audit.run_software_audit()
                    progress.update(task_id, advance=1)
                
                # Filesystem audit
                if args.scan_all or args.filesystem_audit:
                    if not args.quiet:
                        console.print("[yellow]  → Running filesystem security audit...[/yellow]")
                    results["audit_results"]["filesystem_audit"] = security_audit.run_filesystem_audit()
                    progress.update(task_id, advance=1)
                
                # Kernel audit
                if args.scan_all or args.kernel_audit:
                    if not args.quiet:
                        console.print("[yellow]  → Running kernel security audit...[/yellow]")
                    results["audit_results"]["kernel_audit"] = security_audit.run_kernel_audit()
                    progress.update(task_id, advance=1)
                
                # Service audit
                if args.scan_all or args.service_audit:
                    if not args.quiet:
                        console.print("[yellow]  → Running service configuration audit...[/yellow]")
                    results["audit_results"]["service_audit"] = security_audit.run_service_audit()
                    progress.update(task_id, advance=1)
                
                # Port scan
                if args.scan_all or args.scan_ports:
                    if not args.quiet:
                        console.print("[yellow]  → Scanning for open ports...[/yellow]")
                    results["audit_results"]["port_scan"] = security_audit.run_port_scan()
                    progress.update(task_id, advance=1)
                
                # Vulnerability scan
                if args.scan_all or args.scan_vulnerabilities:
                    if not args.quiet:
                        console.print("[yellow]  → Scanning for vulnerabilities...[/yellow]")
                    results["audit_results"]["vulnerability_scan"] = security_audit.run_vulnerability_scan()
                    progress.update(task_id, advance=1)
        
        # System Hardening
        if args.harden or args.harden_kernel or args.harden_ssh or args.harden_firewall or \
           args.harden_auth or args.harden_permissions or args.auto_update:
            
            if not args.quiet:
                console.print("\n[bold blue]Applying System Hardening[/bold blue]")
            
            # Confirm before making changes
            if not args.quiet and not Confirm.ask("Apply system hardening measures? This will modify system configuration"):
                console.print("[yellow]System hardening skipped.[/yellow]")
            else:
                system_hardening = SystemHardening(config_data, security_level=args.level)
                
                with progress:
                    # Calculate total tasks
                    total_tasks = 0
                    if args.harden or args.harden_kernel: total_tasks += 1
                    if args.harden or args.harden_ssh: total_tasks += 1
                    if args.harden or args.harden_firewall: total_tasks += 1
                    if args.harden or args.harden_auth: total_tasks += 1
                    if args.harden or args.harden_permissions: total_tasks += 1
                    if args.harden or args.auto_update: total_tasks += 1
                    
                    task_id = progress.add_task("Applying system hardening...", total=total_tasks)
                    
                    # Kernel hardening
                    if args.harden or args.harden_kernel:
                        if not args.quiet:
                            console.print("[yellow]  → Hardening kernel parameters...[/yellow]")
                        results["hardening_results"]["kernel"] = system_hardening.harden_kernel()
                        progress.update(task_id, advance=1)
                    
                    # SSH hardening
                    if args.harden or args.harden_ssh:
                        if not args.quiet:
                            console.print("[yellow]  → Hardening SSH configuration...[/yellow]")
                        results["hardening_results"]["ssh"] = system_hardening.harden_ssh()
                        progress.update(task_id, advance=1)
                    
                    # Firewall hardening
                    if args.harden or args.harden_firewall:
                        if not args.quiet:
                            console.print("[yellow]  → Configuring firewall...[/yellow]")
                        results["hardening_results"]["firewall"] = system_hardening.harden_firewall()
                        progress.update(task_id, advance=1)
                    
                    # Authentication hardening
                    if args.harden or args.harden_auth:
                        if not args.quiet:
                            console.print("[yellow]  → Hardening authentication mechanisms...[/yellow]")
                        results["hardening_results"]["auth"] = system_hardening.harden_authentication()
                        progress.update(task_id, advance=1)
                    
                    # Permissions hardening
                    if args.harden or args.harden_permissions:
                        if not args.quiet:
                            console.print("[yellow]  → Hardening file permissions...[/yellow]")
                        results["hardening_results"]["permissions"] = system_hardening.harden_permissions()
                        progress.update(task_id, advance=1)
                    
                    # Auto-update configuration
                    if args.harden or args.auto_update:
                        if not args.quiet:
                            console.print("[yellow]  → Configuring automatic updates...[/yellow]")
                        results["hardening_results"]["auto_update"] = system_hardening.configure_auto_updates()
                        progress.update(task_id, advance=1)
        
        # Compliance Checking
        if args.compliance:
            if not args.quiet:
                console.print("\n[bold blue]Checking Compliance[/bold blue]")
            
            compliance_checker = ComplianceChecker(config_data)
            
            with progress:
                task_id = progress.add_task(f"Checking {args.compliance.upper()} compliance...", total=1)
                
                if args.compliance == "custom" and args.profile:
                    results["compliance_results"] = compliance_checker.check_custom_compliance(args.profile)
                else:
                    results["compliance_results"] = compliance_checker.check_compliance(args.compliance)
                
                progress.update(task_id, advance=1)
            
            # Remediate compliance issues if requested
            if args.remediate and results["compliance_results"].get("issues", []):
                if not args.quiet:
                    console.print("[yellow]Remediating compliance issues...[/yellow]")
                
                with progress:
                    task_id = progress.add_task("Remediating compliance issues...", total=1)
                    results["compliance_results"]["remediation"] = compliance_checker.remediate_issues(
                        results["compliance_results"]["issues"]
                    )
                    progress.update(task_id, advance=1)
        
        # Security Monitoring
        if args.monitor:
            if not args.quiet:
                console.print("\n[bold blue]Starting Security Monitoring[/bold blue]")
            
            security_monitor = SecurityMonitor(config_data, alert_threshold=args.alert_threshold)
            
            try:
                if not args.quiet:
                    console.print(f"[yellow]Monitoring {args.events} events. Press Ctrl+C to stop.[/yellow]")
                
                results["monitoring_results"] = security_monitor.monitor_events(
                    event_types=args.events,
                    duration=args.duration
                )
            except KeyboardInterrupt:
                if not args.quiet:
                    console.print("\n[yellow]Monitoring stopped by user.[/yellow]")
        
        # Generate report
        if not args.quiet:
            console.print("\n[bold green]Generating security report...[/bold green]")
        
        report_generator = ReportGenerator(results)
        report_generator.generate_report(report_file)
        
        if not args.quiet:
            console.print(f"\n[bold green]Security report successfully generated:[/bold green] {report_file}")
            
            # Display summary table
            table = Table(title="Security Assessment Summary")
            table.add_column("Category", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Issues", style="red")
            
            # Add audit results to table
            if results["audit_results"]:
                total_issues = sum(len(result.get("issues", [])) for result in results["audit_results"].values())
                table.add_row("Security Audit", "✓ Completed", f"{total_issues} issues found")
            
            # Add hardening results to table
            if results["hardening_results"]:
                hardening_success = sum(1 for result in results["hardening_results"].values() if result.get("success", False))
                hardening_total = len(results["hardening_results"])
                table.add_row("System Hardening", "✓ Applied", f"{hardening_total - hardening_success} failures")
            
            # Add compliance results to table
            if results["compliance_results"]:
                compliance_issues = len(results["compliance_results"].get("issues", []))
                compliance_status = results["compliance_results"].get("status", "Unknown")
                table.add_row("Compliance", f"{compliance_status}", f"{compliance_issues} issues found")
            
            # Add monitoring results to table
            if results["monitoring_results"]:
                alerts = len(results["monitoring_results"].get("alerts", []))
                table.add_row("Security Monitoring", "✓ Completed", f"{alerts} alerts generated")
            
            console.print(table)
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user![/bold red]")
        return 1
    except DoctorGoatError as e:
        logger.error(f"DoctorGoat error: {str(e)}")
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        console.print(f"\n[bold red]Unexpected error: {str(e)}[/bold red]")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
