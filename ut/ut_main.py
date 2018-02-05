import unittest
from ut_someip import ut_someip
#from ut_sd import ut_sd

def suite():
  suite = unittest.TestSuite()
  suite.addTest(unittest.makeSuite(ut_someip))
  #suite.addTest(unittest.makeSuite(ut_sd))
  return suite

if __name__=='__main__':
  runner = unittest.TextTestRunner()
  test_suite = suite()
  runner.run(test_suite)
