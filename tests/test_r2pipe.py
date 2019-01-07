import unittest

import r2pipe



class TestR2Pipe(unittest.TestCase):

    def test_r2pipe_class_module(self):

        r2 = r2pipe.open('test.exe')
        self.assertEqual(r2.__class__.__module__, 'r2pipe.open_sync')
        r2.quit()

    def test_r2pipe_class_name(self):

        r2 = r2pipe.open('test.exe')
        self.assertEqual(r2.__class__.__name__, 'open')
        r2.quit()



if __name__ == '__main__':
    unittest.main()
