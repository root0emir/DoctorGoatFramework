#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exception handling for DoctorGoatFramework
"""

class DoctorGoatError(Exception):
    """Base exception class for DoctorGoatFramework"""
    
    def __init__(self, message="An error occurred in DoctorGoatFramework"):
        self.message = message
        super().__init__(self.message)


class ConfigError(DoctorGoatError):
    """Exception raised for configuration errors"""
    
    def __init__(self, message="Configuration error"):
        self.message = message
        super().__init__(self.message)


class AuditError(DoctorGoatError):
    """Exception raised for security audit errors"""
    
    def __init__(self, message="Security audit error"):
        self.message = message
        super().__init__(self.message)


class HardeningError(DoctorGoatError):
    """Exception raised for system hardening errors"""
    
    def __init__(self, message="System hardening error"):
        self.message = message
        super().__init__(self.message)


class ComplianceError(DoctorGoatError):
    """Exception raised for compliance checking errors"""
    
    def __init__(self, message="Compliance checking error"):
        self.message = message
        super().__init__(self.message)


class MonitoringError(DoctorGoatError):
    """Exception raised for security monitoring errors"""
    
    def __init__(self, message="Security monitoring error"):
        self.message = message
        super().__init__(self.message)


class PermissionError(DoctorGoatError):
    """Exception raised for permission-related errors"""
    
    def __init__(self, message="Insufficient permissions"):
        self.message = message
        super().__init__(self.message)


class SystemError(DoctorGoatError):
    """Exception raised for system-related errors"""
    
    def __init__(self, message="System error"):
        self.message = message
        super().__init__(self.message)


class NetworkError(DoctorGoatError):
    """Exception raised for network-related errors"""
    
    def __init__(self, message="Network error"):
        self.message = message
        super().__init__(self.message)


class ReportError(DoctorGoatError):
    """Exception raised for report generation errors"""
    
    def __init__(self, message="Report generation error"):
        self.message = message
        super().__init__(self.message)


class ValidationError(DoctorGoatError):
    """Exception raised for validation errors"""
    
    def __init__(self, message="Validation error"):
        self.message = message
        super().__init__(self.message)


class NotSupportedError(DoctorGoatError):
    """Exception raised for unsupported operations"""
    
    def __init__(self, message="Operation not supported"):
        self.message = message
        super().__init__(self.message)
