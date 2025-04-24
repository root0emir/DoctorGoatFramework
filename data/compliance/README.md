# Compliance Benchmarks

This directory contains compliance benchmark files used by DoctorGoatFramework to check system compliance against various security standards.

## Supported Standards

- CIS (Center for Internet Security) Benchmarks
- NIST (National Institute of Standards and Technology) Guidelines
- PCI DSS (Payment Card Industry Data Security Standard)
- HIPAA (Health Insurance Portability and Accountability Act)
- GDPR (General Data Protection Regulation)

## File Format

Benchmark files are stored in JSON format with the following naming convention:

- `cis_server_l1.json` - CIS Level 1 Server Benchmark
- `cis_workstation_l1.json` - CIS Level 1 Workstation Benchmark
- `nist_800-53.json` - NIST 800-53 Controls
- `pci_dss.json` - PCI DSS Requirements

## Adding Custom Benchmarks

To add a custom benchmark, create a new JSON file in this directory following the schema defined in the documentation.
