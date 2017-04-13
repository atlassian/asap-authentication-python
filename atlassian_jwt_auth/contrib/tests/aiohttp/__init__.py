import sys

if sys.version_info < (3, 5):
    import nose
    raise nose.SkipTest('Skipping tests for Python version < 3.5')

del sys
