"""
Tests TODO:

classify_func (needs all checks tested)
check_is_analysis_func (needs all checks tested)
check_is_thunk_func (need to find one)
check_is_first_round_func (need to find one)
check_is_utility_func (need to find one)
check_is_complex_func (need to find one)
get_import_from_import_jmp_func (needs the parse utility)
get_raw_call_chain_from_funcj (should maybe be in another class)
get_func_stats_list_from_afij (not implemented)
"""


import os
import sys
import json
import r2pipe
import unittest

from context import r2fu



IMPORT_FUNCJ = json.loads(
"""
{"name":"fcn.10001a2c","size":6,"addr":268442156,"ops":[{"offset":268442156,"ptr":268443664,"esil":"0x10002010,[],eip,=","refptr":false,"fcn_addr":268442156,"fcn_last":268442156,"size":6,"opcode":"jmp dword [0x10002010]","disasm":"jmp dword sym.imp.KERNEL32.dll_IsProcessorFeaturePresent","bytes":"ff2510200010","family":"cpu","type":"jmp","type_num":536870913,"type2_num":0,"flags":["fcn.10001a2c"],"xrefs":[{"addr":268440913,"type":"CALL"}]}]}
""")

GLOBALASSIGN_FUNCJ = json.loads(
"""
{"name":"globalassign_fcn100014fe","size":11,"addr":268440830,"ops":[{"offset":268440830,"ptr":268455952,"val":4294967295,"esil":"4294967295,0x10005010,=[4]","refptr":true,"fcn_addr":268440830,"fcn_last":268440831,"size":10,"opcode":"mov dword [0x10005010], 0xffffffff","disasm":"mov dword [0x10005010], 0xffffffff","bytes":"c70510500010ffffffff","family":"cpu","type":"mov","type_num":9,"type2_num":0,"flags":["globalassign_fcn100014fe","r2kit_analyzed_func","global_assignment_func"],"xrefs":[{"addr":268440814,"type":"CALL"}]},{"offset":268440840,"esil":"esp,[4],eip,=,4,esp,+=","refptr":false,"fcn_addr":268440830,"fcn_last":268440840,"size":1,"opcode":"ret","disasm":"ret","bytes":"c3","family":"cpu","type":"ret","type_num":5,"type2_num":0}]}
""")

WRAPPER_FUNCJ = json.loads(
"""
{"name":"wrapper_call_fcn.10001a14","size":9,"addr":268441705,"ops":[{"offset":268441705,"ptr":8,"val":8,"esil":"8,4,esp,-,=[4],4,esp,-=","refptr":false,"fcn_addr":268441705,"fcn_last":268441712,"size":2,"opcode":"push 8","disasm":"push 8","bytes":"6a08","family":"cpu","type":"push","type_num":13,"type2_num":0,"flags":["wrapper_call_fcn.10001a14","r2kit_analyzed_func","wrapper_func"],"xrefs":[{"addr":268441689,"type":"CALL"}]},{"offset":268441707,"esil":"268442132,eip,4,esp,-=,esp,=[],eip,=","refptr":false,"fcn_addr":268441705,"fcn_last":268441709,"size":5,"opcode":"call 0x10001a14","disasm":"call jmp_sym.imp.MSVCR110.dll__unlock","bytes":"e8a4010000","family":"cpu","type":"call","type_num":3,"type2_num":0,"jump":268442132,"fail":268441712},{"offset":268441712,"esil":"esp,[4],ecx,=,4,esp,+=","refptr":false,"fcn_addr":268441705,"fcn_last":268441713,"size":1,"opcode":"pop ecx","disasm":"pop ecx","bytes":"59","family":"cpu","type":"pop","type_num":14,"type2_num":0},{"offset":268441713,"esil":"esp,[4],eip,=,4,esp,+=","refptr":false,"fcn_addr":268441705,"fcn_last":268441713,"size":1,"opcode":"ret","disasm":"ret","bytes":"c3","family":"cpu","type":"ret","type_num":5,"type2_num":0}]}
""")



class TestR2FuncUtility(unittest.TestCase):
    
    def test_check_is_import_jmp_func(self):

        self.assertTrue(r2fu.check_is_import_jmp_func(IMPORT_FUNCJ))
         
    def test_check_is_globalassign_func(self):
        
        self.assertTrue(r2fu.check_is_global_assignment_func(GLOBALASSIGN_FUNCJ))

    def test_check_is_wrapper_func(self):

        self.assertTrue(r2fu.check_is_wrapper_func(WRAPPER_FUNCJ))

    def test_get_call_count_from_funcj(self):

        self.assertTrue(r2fu.get_call_count_from_funcj(WRAPPER_FUNCJ) == 1)
    
    

if __name__ == '__main__':
    unittest.main()
