import sys, logging
logger = logging.getLogger("statement")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .MethodCall import MethodCall
from .ApiInvoke import ApiInvoke
from .ClassCreate import ClassCreate
from .ArrayCreate import ArrayCreate