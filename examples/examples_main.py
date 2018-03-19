import unittest
import HtmlTestRunner
from ex_00_basics import ex_00_basics
from ex_01_someip import ex_01_someip

def suite():
  suite = unittest.TestSuite()
  suite.addTest(unittest.makeSuite(ex_00_basics))
  suite.addTest(unittest.makeSuite(ex_01_someip))
  return suite

if __name__=='__main__':
  #runner = HtmlTestRunner.HTMLTestRunner(output='examples')
  runner = unittest.TextTestRunner()
  test_suite = suite()
  runner.run(test_suite)
