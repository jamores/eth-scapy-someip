import unittest
import HtmlTestRunner
from ex_00_basics import ex_00_basics

def suite():
  suite = unittest.TestSuite()
  suite.addTest(unittest.makeSuite(ex_00_basics))
  return suite

if __name__=='__main__':
  runner = HtmlTestRunner.HTMLTestRunner(output='examples')
  test_suite = suite()
  runner.run(test_suite)
