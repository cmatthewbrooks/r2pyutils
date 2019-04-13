import os
import unittest

import r2pipe

TEST_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'test.exe'
)

class TestR2Pipe(unittest.TestCase):

    def test_r2pipe_class_module(self):

        r2 = r2pipe.open(TEST_FILE)
        self.assertEqual(r2.__class__.__module__, 'r2pipe.open_sync')
        r2.quit()

    def test_r2pipe_class_name(self):

        r2 = r2pipe.open(TEST_FILE)
        self.assertEqual(r2.__class__.__name__, 'open')
        r2.quit()

    def test_empty_r2pipe_outside_r2_session(self):

        r2 = r2pipe.open()

        self.assertEqual(r2.cmdj('ij')['core']['file'],'malloc://512')

if __name__ == '__main__':
    unittest.main()
