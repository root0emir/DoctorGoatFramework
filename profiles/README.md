# Custom Compliance Profiles

This directory contains custom compliance profiles for DoctorGoatFramework. Custom profiles allow you to define your own security requirements and checks tailored to your specific environment.

## Profile Format

Custom profiles are defined in YAML format with the following structure:

```yaml
name: "My Custom Profile"
description: "Custom security profile for internal systems"
version: "1.0"
author: "Security Team"
created_at: "2025-04-24"

checks:
  - id: "CUSTOM-001"
    title: "Ensure SSH root login is disabled"
    description: "SSH root login should be disabled to prevent direct root access"
    severity: "high"
    check_type: "file_content"
    file: "/etc/ssh/sshd_config"
    pattern: "^PermitRootLogin\\s+no"
    remediation: "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'"
    
  - id: "CUSTOM-002"
    title: "Ensure firewall is enabled"
    description: "A firewall should be enabled to control network traffic"
    severity: "high"
    check_type: "command"
    command: "systemctl status firewalld"
    expected_result: 0
    remediation: "systemctl enable --now firewalld"
    
  - id: "CUSTOM-003"
    title: "Ensure password expiration is 90 days or less"
    description: "Password expiration should be set to 90 days or less"
    severity: "medium"
    check_type: "file_content"
    file: "/etc/login.defs"
    pattern: "^PASS_MAX_DAYS\\s+([0-9]+)"
    expected_match: "value <= 90"
    remediation: "Edit /etc/login.defs and set 'PASS_MAX_DAYS 90'"
```

## Using Custom Profiles

To use a custom profile, run DoctorGoatFramework with the following command:

```bash
python doctorgoat.py --compliance=custom --profile=myprofile
```

Where `myprofile` is the name of your custom profile file (without the .yaml extension).

## Creating a New Profile

1. Create a new YAML file in this directory
2. Define your profile metadata (name, description, version, etc.)
3. Define your compliance checks
4. Save the file with a descriptive name (e.g., `mycompany_security_baseline.yaml`)

## Check Types

The following check types are supported:

- `command` - Run a command and check the exit code
- `file_content` - Check file content against a pattern
- `file_permission` - Check file permissions
- `package` - Check if a package is installed
- `service` - Check if a service is running
- `sysctl` - Check a sysctl parameter value
