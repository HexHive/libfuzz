import sys, logging
logger = logging.getLogger("dependency")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .BackendDriver     import BackendDriver

from .pseudocode.PseudocodeBackendDriver import PseudocodeBackendDriver