import sys, logging
logger = logging.getLogger("factory")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Factory               import Factory

import driver.factory.only_type
import driver.factory.java_analysis