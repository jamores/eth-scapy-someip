import unittest
import HtmlTestRunner
from ex_00_basics import ex_00_basics
from ex_01_someip import ex_01_someip
from ex_02_sd import ex_02_sd

def suite():
  suite = unittest.TestSuite()
  suite.addTest(unittest.makeSuite(ex_00_basics))
  suite.addTest(unittest.makeSuite(ex_01_someip))
  suite.addTest(unittest.makeSuite(ex_02_sd))
  return suite

if __name__=='__main__':
  # uncomment for HTML testrunner output
  #runner = HtmlTestRunner.HTMLTestRunner(output='examples')
  
  runner = unittest.TextTestRunner()
  test_suite = suite()
  runner.run(test_suite)
