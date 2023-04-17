import sys, logging
logger = logging.getLogger("variable")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Variable import Variable