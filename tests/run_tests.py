# Code from:
# https://www.internalpointers.com/post/run-painless-test-suites-python-unittest

import unittest

import test_r2pipe
import test_r2ppipeutil
import test_r2pfuncutil



loader = unittest.TestLoader()
suite = unittest.TestSuite()

suite.addTests(loader.loadTestsFromModule(test_r2pipe))
suite.addTests(loader.loadTestsFromModule(test_r2ppipeutil))
suite.addTests(loader.loadTestsFromModule(test_r2pfuncutil))

runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)