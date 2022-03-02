import sys, logging
logger = logging.getLogger("dependency")
for func in ('debug', 'info', 'warning', 'error', 'critical'):
    setattr(sys.modules[__name__], func, getattr(logger, func))

from .Miner         import Miner
from .FeedbackTest  import FeedbackTest

from .pseudocode.PseudocodeMiner import PseudocodeMiner