# This idea was taken from:
# https://docs.python-guide.org/writing/structure/ 

import os,sys

sys.path.append( 
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..')
    )
)

#print (sys.path)

import r2pyutils.r2ppipeutil as r2pu
import r2pyutils.r2pfuncutil as r2fu

#from r2pyutils.funcstrings import get_func_strings
from r2pyutils.funclist import FuncList as FuncList
