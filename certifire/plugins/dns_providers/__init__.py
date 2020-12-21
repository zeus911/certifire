import logging
from typing import Union

LoggerType = logging.Logger

def create_logger(name: str, log_level: Union[str, int]) -> LoggerType:
    """
    return a logger configured with name and log_level
    """

    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
