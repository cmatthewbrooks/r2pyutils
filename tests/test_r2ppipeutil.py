
import os,sys
import r2pipe

#Update the path to test files in the repo parent directory
sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)
)

#Import the file being tested
from r2ppipeutil import R2PipeUtility as r2pu



def test_get_analyzed_r2pipe_from_input():
    
    print("Testing get_analyzed_r2pipe_from_input():")

    print("\nTesting input_obj=None...")

    try:
        r2 = r2pu.get_analyzed_r2pipe_from_input()
    except Exception:
        print ("Testing input_obj=None...TEST PASSED.\n")

    print("\nTesting input_obj=R2PIPE_CLASS_NAME...")
    
    r2 = r2pipe.open("/bin/ls")
    r2 = r2pu.get_analyzed_r2pipe_from_input(r2)
    if int(r2.cmd('aflc')) == 0:
        print("Testing input_obj=R2PIPE_CLASS_NAME...TEST FAILED.\n")
    else:
        print("Analyzed func count is: ", str(r2.cmd('aflc')))
        print("Testing input_obj=R2PIPE_CLASS_NAME...TEST PASSED.\n")

    print("\nTesting input_obj=file...")

    r2 = None
    r2 = r2pu.get_analyzed_r2pipe_from_input("/bin/ls")
    if int(r2.cmd('aflc')) == 0:
        print("Testing input_obj=file...TEST FAILED.\n")
    else:
        print("Analyzed func count is: ", str(r2.cmd('aflc')))
        print("Testing input_obj=file...TEST PASSED.\n")



if __name__ == '__main__':

    test_get_analyzed_r2pipe_from_input()

