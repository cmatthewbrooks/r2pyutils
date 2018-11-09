
import os,sys
import r2pipe

#Update the path to test files in the repo parent directory
sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)
)

#Import the file being tested
from r2ppipeutil import R2PipeUtility as r2pu

def test_get_analyzed_r2pipe_from_input_with_none():
    
    try:
        r2 = r2pu.get_analyzed_r2pipe_from_input()
    except Exception:
        return True

def test_get_analyzed_r2pipe_from_input_with_pipe():

    r2 = r2pipe.open("test.exe")
    r2 = r2pu.get_analyzed_r2pipe_from_input(r2)

    if int(r2.cmd('aflc')) == 0:
        r2.quit()
        return False
    else:
        r2.quit()
        return True

def test_get_analyzed_r2pipe_from_input_with_file():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")

    if int(r2.cmd('aflc')) == 0:
        r2.quit()
        return False
    else:
        r2.quit()
        return True

def test_get_funcj_list():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
    
    funcj_list = r2pu.get_funcj_list(r2)
    
    if len(funcj_list) > 0:
        r2.quit()
        return True
    else:
        r2.quit()
        return False

def test_get_function_start_from_offset_with_none():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
    
    # Address 0x40100a belongs to fcn.401000
    r2.cmd("s 0x40100a")
    
    if hex(r2pu.get_function_start_from_offset(r2)) == '0x401000':
        r2.quit()
        return True
    else:
        r2.quit()
        return False

def test_get_function_start_from_offset_with_offset():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
    
    if hex(r2pu.get_function_start_from_offset(r2,0x40100a)) == '0x401000':
        r2.quit()
        return True
    else:
        r2.quit()
        return False

def test_get_args_count_to_function_offset_with_none():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
    
    # Address 0x401020 is the 'add' function that takes 2 args
    r2.cmd("s 0x401020")
    
    if int(r2pu.get_args_count_to_function_offset(r2)) == 2:
        r2.quit()
        return True
    else:
        r2.quit()
        return False

def test_get_args_count_to_function_offset_with_offset():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
    
    if int(r2pu.get_args_count_to_function_offset(r2,0x40102a)) == 2:
        r2.quit()
        return True
    else:
        r2.quit()
        return False

def test_get_call_xref_list_to_function_offset_with_none():

    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")

    r2.cmd("s 0x401020")

    if len(r2pu.get_call_xref_list_to_function_offset(r2)) == 3:
        r2.quit()
        return True
    else:
        r2.quit()
        return False

def test_get_call_xref_list_to_function_offset_with_offset():
 
    r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")

    if len(r2pu.get_call_xref_list_to_function_offset(r2,0x401020)) == 3:
        r2.quit()
        return True
    else:
        r2.quit()
        return False   



if __name__ == '__main__':

    fail_count = 0

    if not test_get_analyzed_r2pipe_from_input_with_none():
        print("test_get_analyzed_r2pipe_from_input_with_none FAILED")
        fail_count += 1

    if not test_get_analyzed_r2pipe_from_input_with_pipe():
        print("test_get_analyzed_r2pipe_from_input_with_pipe FAILED")
        fail_count += 1

    if not test_get_analyzed_r2pipe_from_input_with_file():
        print("test_get_analyzed_r2pipe_from_input_with_file FAILED")
        fail_count += 1

    if not test_get_funcj_list():
        print("test_get_funcj_list FAILED")
        fail_count += 1

    if not test_get_function_start_from_offset_with_none():
        print("test_get_function_start_from_offset_with_none FAILED")
        fail_count += 1

    if not test_get_function_start_from_offset_with_offset():
        print("test_get_function_start_from_offset_with_offset FAILED")
        fail_count += 1

    if not test_get_args_count_to_function_offset_with_none():
        print("test_get_args_count_to_function_offset_with_none FAILED")
        fail_count += 1

    if not test_get_args_count_to_function_offset_with_offset():
        print("test_get_args_count_to_function_offset_with_offset FAILED")
        fail_count += 1

    if not test_get_call_xref_list_to_function_offset_with_none():
        print("test_get_call_xref_list_to_function_offset_with_none FAILED")
        fail_count += 1

    if not test_get_call_xref_list_to_function_offset_with_offset():
        print("test_get_call_xref_list_to_function_offset_with_offset FAILED")
        fail_count += 1

    if fail_count == 0:
        print("\nALL TESTS PASSED")
