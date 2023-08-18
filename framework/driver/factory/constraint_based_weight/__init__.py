import sys, logging
logger = logging.getLogger("constraint_based_weight")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .CBWFactory               import CBWFactory