# Hardening Templates

This directory contains system hardening templates used by DoctorGoatFramework to apply security configurations to Linux systems.

## Security Levels

Templates are organized by security level:

- `low` - Basic security improvements with minimal impact on functionality
- `medium` - Balanced security measures suitable for most environments
- `high` - Strong security measures for sensitive environments
- `extreme` - Maximum security for high-security environments

## Template Types

- `kernel_params.yaml` - Kernel hardening parameters (sysctl)
- `ssh_config.yaml` - SSH server hardening configurations
- `firewall_rules.yaml` - Firewall rule templates
- `auth_config.yaml` - Authentication hardening settings
- `permissions.yaml` - File and directory permission templates

## Example Template

```yaml
# kernel_params.yaml - Medium security level
description: "Medium security kernel hardening parameters"
parameters:
  # Network security
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.default.accept_redirects: 0
  net.ipv4.conf.all.secure_redirects: 0
  net.ipv4.conf.default.secure_redirects: 0
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv4.conf.default.accept_source_route: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.conf.default.rp_filter: 1
  net.ipv4.icmp_echo_ignore_broadcasts: 1
  net.ipv4.icmp_ignore_bogus_error_responses: 1
  net.ipv4.tcp_syncookies: 1
  
  # Kernel hardening
  kernel.randomize_va_space: 2
  kernel.kptr_restrict: 1
  kernel.dmesg_restrict: 1
  fs.protected_hardlinks: 1
  fs.protected_symlinks: 1
```

## Creating Custom Templates

To create a custom hardening template, create a new YAML file in the appropriate subdirectory following the schema defined in the documentation.
