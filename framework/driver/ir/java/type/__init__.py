import sys, logging
logger = logging.getLogger("type")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .JavaType              import JavaType
from .ClassType             import ClassType
from .ArrayType             import ArrayType
from .ParameterizedType     import ParameterizedType