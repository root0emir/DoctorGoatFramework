#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logging module for DoctorGoatFramework
"""

import os
import sys
import logging
import logging.handlers
import platform
import traceback
from datetime import datetime
from pathlib import Path

# Default log format
DEFAULT_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Default log directory
DEFAULT_LOG_DIR = "logs"

# Log levels
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}

class LogFilter(logging.Filter):
    """Custom log filter to add additional context to log records"""
    
    def __init__(self, name=''):
        super().__init__(name)
        self.hostname = platform.node()
        self.username = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
    
    def filter(self, record):
        record.hostname = self.hostname
        record.username = self.username
        return True

def setup_logger(log_level="INFO", log_file=None, log_to_console=True, log_format=None, date_format=None):
    """
    Configure the logger for DoctorGoatFramework
    
    Args:
        log_level (str): Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file (str, optional): Path to log file
        log_to_console (bool): Whether to log to console
        log_format (str, optional): Custom log format
        date_format (str, optional): Custom date format
    
    Returns:
        logging.Logger: Configured logger instance
    
    Raises:
        ValueError: If invalid log level is provided
    """
    # Determine log level
    if log_level.upper() not in LOG_LEVELS:
        raise ValueError(f"Invalid log level: {log_level}. Valid levels are: {', '.join(LOG_LEVELS.keys())}")
    
    numeric_level = LOG_LEVELS[log_level.upper()]
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)  # Set root logger to WARNING to avoid noise
    
    # Configure main logger
    logger = logging.getLogger("doctorgoat")
    logger.setLevel(numeric_level)
    
    # Clear previous handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    log_format = log_format or DEFAULT_LOG_FORMAT
    date_format = date_format or DEFAULT_DATE_FORMAT
    
    # Add hostname and username to format if not present
    if '%(hostname)s' not in log_format:
        log_format = log_format.replace('%(levelname)s', '%(levelname)s - %(hostname)s - %(username)s')
    
    formatter = logging.Formatter(
        log_format,
        datefmt=date_format
    )
    
    # Add custom filter
    log_filter = LogFilter()
    logger.addFilter(log_filter)
    
    # Add console handler if requested
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # Add file handler
    if log_file:
        # Create log directory if needed
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Create file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10 MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
    else:
        # Use default log file
        logs_dir = DEFAULT_LOG_DIR
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d")
        default_log_file = os.path.join(logs_dir, f"doctorgoat_{timestamp}.log")
        
        # Create file handler
        file_handler = logging.handlers.RotatingFileHandler(
            default_log_file,
            maxBytes=10*1024*1024,  # 10 MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
    
    # Disable propagation to root logger
    logger.propagate = False
    
    # Log startup information
    logger.info(f"Logging initialized at level {log_level}")
    logger.debug(f"Python version: {platform.python_version()}")
    logger.debug(f"Platform: {platform.platform()}")
    logger.debug(f"Log file: {log_file or default_log_file}")
    
    return logger

def get_logger(name=None):
    """
    Get a logger instance with the specified name
    
    Args:
        name (str, optional): Logger name. If None, returns the main logger
    
    Returns:
        logging.Logger: Logger instance
    """
    if name:
        return logging.getLogger(f"doctorgoat.{name}")
    return logging.getLogger("doctorgoat")

def setup_exception_logging():
    """
    Set up global exception handler to log unhandled exceptions
    """
    logger = get_logger("exceptions")
    
    def exception_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            # Don't log keyboard interrupt
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logger.critical("Unhandled exception:", exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = exception_handler

def log_to_file(message, log_file, level="INFO"):
    """
    Log a message directly to a specific file
    
    Args:
        message (str): Message to log
        log_file (str): Path to log file
        level (str): Log level
    """
    # Create log directory if needed
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Get numeric level
    numeric_level = LOG_LEVELS.get(level.upper(), logging.INFO)
    
    # Create logger
    file_logger = logging.getLogger(f"doctorgoat.file.{os.path.basename(log_file)}")
    file_logger.setLevel(numeric_level)
    
    # Clear previous handlers
    for handler in file_logger.handlers[:]:
        file_logger.removeHandler(handler)
    
    # Create handler
    handler = logging.FileHandler(log_file, encoding='utf-8')
    handler.setLevel(numeric_level)
    
    # Create formatter
    formatter = logging.Formatter(
        DEFAULT_LOG_FORMAT,
        datefmt=DEFAULT_DATE_FORMAT
    )
    handler.setFormatter(formatter)
    
    # Add handler to logger
    file_logger.addHandler(handler)
    
    # Log message
    file_logger.log(numeric_level, message)
    
    # Close handler
    handler.close()
    file_logger.removeHandler(handler)
