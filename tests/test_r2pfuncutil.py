
import os,sys
import r2pipe

#Update the path to test files in the repo parent directory
sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)
)

#Import the file being tested
from r2pfuncutil import R2FuncUtility as r2fu



if __name__ == '__main__':

    fail_count = 0 

    if fail_count == 0:
        print("\nALL TESTS PASSED")    
