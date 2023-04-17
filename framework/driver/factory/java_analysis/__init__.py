import sys, logging
logger = logging.getLogger("java_analysis")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .JavaFactory               import JavaFactory