import sys, logging
logger = logging.getLogger("ir")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Statement             import Statement
from .Type                  import Type
from .PointerType           import PointerType
from .Value                 import Value
from .Variable              import Variable
from .Address               import Address
from .NullConstant          import NullConstant
from .ApiCall               import ApiCall
from .BuffDecl              import BuffDecl
from .BuffInit              import BuffInit
from .Buffer                import Buffer
