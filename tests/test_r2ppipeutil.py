import os,sys
import unittest

import r2pipe

from context import r2pu



class TestR2PPipeUtil(unittest.TestCase):

    def test_get_analyzed_r2pipe_from_input_with_none(self):
        # As of r2pipe 1.2.0, the following error is thrown if
        # an empty pipe is opened outside a session:
        #
        # AttributeError: 'open' object has no attribute '_cmd'

        self.assertRaises(AttributeError,
                          lambda: r2pu.get_analyzed_r2pipe_from_input())

    
    def test_get_analyzed_r2pipe_from_input_with_pipe(self):
        
        r2 = r2pipe.open("test.exe")
        r2 = r2pu.get_analyzed_r2pipe_from_input(r2)

        self.assertTrue(int(r2.cmd('aflc')) > 0)
        r2.quit()
    
    
    def test_get_analyzed_r2pipe_from_input_with_file(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")

        self.assertTrue(int(r2.cmd('aflc')) > 0)
        r2.quit()
    
    def test_get_funcj_list(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
        
        funcj_list = r2pu.get_funcj_list(r2)
        
        self.assertTrue(len(funcj_list) > 0)
        r2.quit()

    def test_get_function_start_from_offset_with_none(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
        
        # Address 0x40100a belongs to fcn.401000
        r2.cmd("s 0x40100a")

        self.assertTrue(hex(r2pu.get_function_start_from_offset(r2)) == '0x401000')
        r2.quit()

    def test_get_function_start_from_offset_with_offset(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
        
        self.assertTrue(hex(r2pu.get_function_start_from_offset(r2,0x40100a)) == '0x401000')
        r2.quit()

    
    def test_get_args_count_to_function_offset_with_none(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
        
        # Address 0x401020 is the 'add' function that takes 2 args
        r2.cmd("s 0x401020")
        
        self.assertTrue(int(r2pu.get_args_count_to_function_offset(r2)) == 2)
        r2.quit()

    def test_get_args_count_to_function_offset_with_offset(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")
        
        self.assertTrue(int(r2pu.get_args_count_to_function_offset(r2,0x40102a)) == 2)
        r2.quit()
           
    def test_get_call_xref_list_to_function_offset_with_none(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")

        r2.cmd("s 0x401020")

        self.assertTrue(len(r2pu.get_call_xref_list_to_function_offset(r2)) == 3)
        r2.quit()

    def test_get_call_xref_list_to_function_offset_with_offset(self):
        
        r2 = r2pu.get_analyzed_r2pipe_from_input("test.exe")

        self.assertTrue(len(r2pu.get_call_xref_list_to_function_offset(r2,0x401020)) == 3)
        r2.quit()

if __name__ == '__main__':
    unittest.main()
