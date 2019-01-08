# This idea was taken from:
# https://docs.python-guide.org/writing/structure/ 

import os,sys

sys.path.append( 
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..')
    )
)

from r2pyutils.r2ppipeutil import R2PipeUtility as r2pu
from r2pyutils.r2pfuncutil import R2FuncUtility as r2fu

from r2pyutils.funcstrings import get_func_strings
