import os
import unittest

import r2pipe

from context import FuncList

TEST_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'test.exe'
)

class TestFuncList(unittest.TestCase):

    def test_get_first_round_list(self):

        r2 = r2pipe.open(TEST_FILE)
        r2.cmd('aaa')

        fl = FuncList('firstround', r2)
        
        self.assertEqual(len(fl.func_list), 2)
        self.assertIn('fcn.00401000', fl.func_list)
        self.assertIn('fcn.00401020', fl.func_list)

        r2.quit()

    def test_get_utility_list(self):

        r2 = r2pipe.open(TEST_FILE)
        r2.cmd('aaa')

        fl = FuncList('utility', r2)

        self.assertEqual(len(fl.func_list), 1)
        self.assertIn('fcn.00401020', fl.func_list)

        r2.quit()

if __name__ == '__main__':
    unittest.main()
