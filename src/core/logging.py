"""
Logging configuration for Hybrid Cloud Security Framework
"""

import logging
import sys
from typing import Optional
from loguru import logger
from src.core.config import get_settings


def setup_logging(log_level: Optional[str] = None) -> None:
    """Setup application logging"""
    settings = get_settings()
    
    # Remove default handler
    logger.remove()
    
    # Add console handler
    logger.add(
        sys.stdout,
        level=log_level or settings.LOG_LEVEL,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        colorize=True
    )
    
    # Add file handler
    logger.add(
        "logs/hybrid_cloud_security.log",
        level=log_level or settings.LOG_LEVEL,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="1 day",
        retention="30 days",
        compression="zip"
    )
    
    # Configure standard logging
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def get_logger(name: str) -> logging.Logger:
    """Get logger instance"""
    return logging.getLogger(name)
