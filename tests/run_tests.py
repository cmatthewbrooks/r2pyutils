# Code from:
# https://www.internalpointers.com/post/run-painless-test-suites-python-unittest

import unittest

import test_r2ppipeutil

loader = unittest.TestLoader()
suite = unittest.TestSuite()

suite.addTests(loader.loadTestsFromModule(test_r2ppipeutil))

runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)
