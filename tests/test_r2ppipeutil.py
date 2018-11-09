
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

    r2.quit()

    r2 = None
    r2 = r2pu.get_analyzed_r2pipe_from_input("/bin/ls")
    if int(r2.cmd('aflc')) == 0:
        print("Testing input_obj=file...TEST FAILED.\n")
    else:
        print("Analyzed func count is: ", str(r2.cmd('aflc')))
        print("Testing input_obj=file...TEST PASSED.\n")

    r2.quit()



def test_get_funcj_list():

    print("Testing get_funcj_list():")

    r2 = r2pu.get_analyzed_r2pipe_from_input("/bin/ls")
    funcj_list = r2pu.get_funcj_list(r2)
    
    if len(funcj_list) > 0:

        print("Length of funcj_list is: ", len(funcj_list))
        print("Testing get_funcj_list...TEST PASSED.")

    else:

        print("Testing get_funcj_list...TEST FAILED.")

    r2.quit()

def test_get_function_start_from_offset():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
    
    # Address 0x40100a belongs to fcn.401000
    r2.cmd("s 0x40100a")
    
    if hex(r2pu.get_function_start_from_offset(r2)) == '0x401000':
        print("TEST get_function_start_from_offset PASSED.")
    else:
        print("TEST get_function_start_from_offset FAILED.")

    # Seek back and try to manually pass the offset this time.
    r2.cmd("s-")
    
    if hex(r2pu.get_function_start_from_offset(r2,0x40100a)) == '0x401000':
        print("TEST get_function_start_from_offset PASSED.")
    else:
        print("TEST get_function_start_from_offset FAILED.")

    r2.quit()

def test_get_args_count_to_function_offset():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
    
    # Address 0x401020 is the 'add' function that takes 2 args
    r2.cmd("s 0x401020")
    
    if int(r2pu.get_args_count_to_function_offset(r2)) == 2:
        print("TEST get_args_count_to_function_offset PASSED.")
    else:
        print("TEST get_args_count_fo_function_offset FAILED.")

    # Seek back and try to manually pass the offset this time.
    r2.cmd("s-")
    
    if int(r2pu.get_args_count_to_function_offset(r2,0x40102a)) == 2:
        print("TEST get_args_count_to_function_offset PASSED.")
    else:
        print("TEST get_args_count_fo_function_offset FAILED.")
    
    r2.quit()


if __name__ == '__main__':

    #test_get_analyzed_r2pipe_from_input()
    #test_get_funcj_list()
    #test_get_function_start_from_offset()
    test_get_args_count_to_function_offset()
