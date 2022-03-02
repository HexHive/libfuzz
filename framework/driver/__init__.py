import sys, logging
logger = logging.getLogger("dependency")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Driver                import Driver
from .Statement             import Statement
from .Value                 import Value
from .Variable              import Variable
from .Address               import Address
from .Type                  import Type
from .PointerType           import PointerType
from .ApiCall               import ApiCall
from .VarDecl               import VarDecl
from .Context               import Context
from .DriverGenerator       import DriverGenerator

# for grammar specialization
# from .type.TypeDependencyGraphGenerator import TypeDependencyGraphGenerator