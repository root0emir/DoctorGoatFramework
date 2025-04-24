# DoctorGoatFramework

DoctorGoatFramework is an advanced CLI security framework designed for comprehensive security auditing and hardening of Linux-based systems.

## Features

### System Security Auditing
- System configuration assessment
- Vulnerability detection and analysis

### System Hardening
- **Multiple Security Levels**: Configure hardening with predefined levels (low, medium, high, extreme)
- **Kernel Hardening**: Apply secure sysctl configurations with backup and rollback options
- **SSH Hardening**: Secure SSH server configuration (ports, authentication methods, timeouts, etc.)
- **Firewall Configuration**: Apply default-deny rules with allowed services and ports
- **Authentication Hardening**: Strengthen password policies and authentication mechanisms
- **Filesystem Hardening**: Apply secure permissions and access controls
- **Automatic Security Updates**: Configure automatic security updates with customizable options

### Compliance Checking
- **Industry Standards**: Check compliance against CIS, NIST, PCI-DSS, HIPAA, and GDPR guidelines
- **Customizable Profiles**: Create and use custom compliance profiles for specific requirements
- **Remediation**: Automatically fix compliance issues with rollback capability
- **Compliance Reporting**: Generate detailed compliance reports with findings and recommendations

### Security Monitoring
- **Real-time Monitoring**: Monitor security events, authentication attempts, network activity, and filesystem changes
- **Alert Thresholds**: Configure alert thresholds (low, medium, high, critical)
- **Event Correlation**: Correlate events across different subsystems to detect complex threats
- **Persistent Logging**: Record security events with rotation and archive options

### Reporting
- **Multiple Formats**: Generate reports in HTML, JSON, PDF, and TXT formats
- **Customizable Content**: Configure report content, severity levels, and recommendations
- **Company Branding**: Add company information and logo to reports
- **Email Delivery**: Send reports via email to configured recipients

## 📋 Requirements

- Python 3.6 or higher
- Linux operating system (Debian, Ubuntu, CentOS, RHEL, etc.)
- Root privileges for most functionality

## 🔧 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/DoctorGoatFramework.git
cd DoctorGoatFramework

# Install dependencies
pip install -r requirements.txt

# Verify installation
python doctorgoat.py --version
```

## 📖 Usage

### Basic Commands

```bash
# Show help information
python doctorgoat.py --help

# Run a complete security audit
python doctorgoat.py --scan-all

# Harden system with specified security level
python doctorgoat.py --harden --level=high

# Check compliance against CIS benchmarks
python doctorgoat.py --compliance=cis

# Monitor security events in real-time
python doctorgoat.py --monitor --events=security,auth
```

### Audit Options

```bash
# Run specific audit modules
python doctorgoat.py --user-audit --network-audit --kernel-audit

# Run all audit modules with detailed output
python doctorgoat.py --scan-all --verbose

# Collect only system information
python doctorgoat.py --system-info
```

### Hardening Options

```bash
# Apply medium security level with backup
python doctorgoat.py --harden --level=medium --backup

# Apply only kernel hardening
python doctorgoat.py --harden-kernel

# Apply only SSH hardening
python doctorgoat.py --harden-ssh

# Restore from backup
python doctorgoat.py --restore-backup=20250424_120530
```

### Compliance Options

```bash
# Check compliance against CIS level 1
python doctorgoat.py --compliance=cis --level=1

# Check compliance with automatic remediation
python doctorgoat.py --compliance=cis --remediate

# Use custom compliance profile
python doctorgoat.py --compliance=custom --profile=myprofile
```

### Monitoring Options

```bash
# Monitor all security events
python doctorgoat.py --monitor --events=all

# Monitor with high alert threshold for 30 minutes
python doctorgoat.py --monitor --events=security,auth --alert-threshold=high --duration=1800
```

### Reporting Options

```bash
# Generate HTML report
python doctorgoat.py --scan-all --report-format=html --output=myreport.html

# Generate PDF report with company branding
python doctorgoat.py --scan-all --report-format=pdf --company="My Company"

# Email report to recipients
python doctorgoat.py --scan-all --email-report --recipients=admin@example.com
```

## 🔌 Configuration

DoctorGoatFramework uses a YAML configuration file (`config.yaml`) to customize its behavior. You can modify the default configuration or specify a custom configuration file:

```bash
python doctorgoat.py --config=custom_config.yaml
```

Key configuration sections include:

- **general**: Global settings like report format, threading, timeouts, etc.
- **security**: Security audit and hardening configurations
- **compliance**: Compliance checking settings and profiles
- **monitoring**: Security monitoring options and alert thresholds
- **reporting**: Report generation options and branding

## 🧩 Modules

### Core Modules
- **config.py**: Configuration management with validation and migration
- **logger.py**: Logging system with rotation and multiple outputs
- **exceptions.py**: Custom exceptions for error handling

### Functional Modules
- **system_info.py**: System information collection and analysis
- **security_audit.py**: Security audit implementation
- **system_hardening.py**: System hardening implementation
- **compliance.py**: Compliance checking implementation
- **monitoring.py**: Security monitoring implementation
- **report_generator.py**: Report generation in multiple formats

### Utility Modules
- **helpers.py**: Common utility functions and helpers

## 🛠️ Development

### Project Structure

```
DoctorGoatFramework/
├── doctorgoat.py        # Main CLI entry point
├── config.yaml          # Default configuration
├── requirements.txt     # Python dependencies
├── README.md            # Documentation
├── lib/
│   ├── core/            # Core framework components
│   │   ├── config.py    # Configuration management
│   │   ├── logger.py    # Logging system
│   │   └── exceptions.py # Custom exceptions
│   ├── modules/         # Functional modules
│   │   ├── system_info.py # System information
│   │   ├── security_audit.py # Security audit
│   │   ├── system_hardening.py # System hardening
│   │   ├── compliance.py # Compliance checking
│   │   ├── monitoring.py # Security monitoring
│   │   └── report_generator.py # Report generation
│   └── utils/           # Utility modules
│       └── helpers.py   # Helper functions
├── data/                # Data files
│   ├── compliance/      # Compliance benchmarks
│   └── hardening/       # Hardening templates
├── profiles/            # Custom compliance profiles
├── templates/           # Report templates
└── logs/                # Log files
```

### Adding a New Module

1. Create a new Python file in the appropriate directory
2. Import required dependencies and core modules
3. Implement the module functionality
4. Add configuration options to config.yaml
5. Update the CLI interface in doctorgoat.py

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Author

root0emir - Securonis GNU/Linux Network and System Technologies Research Laboratory
