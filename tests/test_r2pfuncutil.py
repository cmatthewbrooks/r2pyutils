
import os,sys
import json
import r2pipe

#Update the path to test files in the repo parent directory
sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)
)

#Import the file being tested
from r2pfuncutil import R2FuncUtility as r2fu

IMPORT_FUNCJ = json.loads(
"""
{"name":"fcn.10001a2c","size":6,"addr":268442156,"ops":[{"offset":268442156,"ptr":268443664,"esil":"0x10002010,[],eip,=","refptr":false,"fcn_addr":268442156,"fcn_last":268442156,"size":6,"opcode":"jmp dword [0x10002010]","disasm":"jmp dword sym.imp.KERNEL32.dll_IsProcessorFeaturePresent","bytes":"ff2510200010","family":"cpu","type":"jmp","type_num":536870913,"type2_num":0,"flags":["fcn.10001a2c"],"xrefs":[{"addr":268440913,"type":"CALL"}]}]}
""")

GLOBALASSIGN_FUNCJ = json.loads(
"""
{"name":"globalassign_fcn100014fe","size":11,"addr":268440830,"ops":[{"offset":268440830,"ptr":268455952,"val":4294967295,"esil":"4294967295,0x10005010,=[4]","refptr":true,"fcn_addr":268440830,"fcn_last":268440831,"size":10,"opcode":"mov dword [0x10005010], 0xffffffff","disasm":"mov dword [0x10005010], 0xffffffff","bytes":"c70510500010ffffffff","family":"cpu","type":"mov","type_num":9,"type2_num":0,"flags":["globalassign_fcn100014fe","r2kit_analyzed_func","global_assignment_func"],"xrefs":[{"addr":268440814,"type":"CALL"}]},{"offset":268440840,"esil":"esp,[4],eip,=,4,esp,+=","refptr":false,"fcn_addr":268440830,"fcn_last":268440840,"size":1,"opcode":"ret","disasm":"ret","bytes":"c3","family":"cpu","type":"ret","type_num":5,"type2_num":0}]}

""")

def test_check_is_import_jmp_func():

    if r2fu.check_is_import_jmp_func(IMPORT_FUNCJ):
        return True
    else:
        return False

def test_check_is_globalassign_func():
    
    if r2fu.check_is_global_assignment_func(GLOBALASSIGN_FUNCJ):
        return True
    else:
        return False



if __name__ == '__main__':

    fail_count = 0 

    if not test_check_is_import_jmp_func():
        print("test_check_is_import_jmp_func FAILED")
        fail_count += 1

    if fail_count == 0:
        print("\nALL TESTS PASSED")    
