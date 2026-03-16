import unittest
from pathlib import Path
from tmautils.enrich_ip import ChromePrefetchUtil

class ChromePrefetchUtilTest(unittest.TestCase):
    def test(self):
        util = ChromePrefetchUtil(working_root=Path("/tmp"))
        assert(util.lookup('193.186.4.175').empty == False)
        print(util.lookup('193.186.4.175'))

if __name__ == '__main__':
    unittest.main()
