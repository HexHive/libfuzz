import sys, logging
logger = logging.getLogger("java")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

import driver.ir.java.type
import driver.ir.java.statement
import driver.ir.java.variable