import unittest

import r2pipe

from context import get_func_strings

TEST_STRING_SET = {}

class TestFuncStrings(unittest.TestCase):

    def test_get_func_strings(self):

        r2 = r2pipe.open('test.exe')
        r2.cmd('aaa')
        
        string_sets = get_func_strings(r2)
        
        self.assertEqual(string_sets, TEST_STRING_SET)

        r2.quit()

if __name__ == '__main__':
    unittest.main()
