import sys

import nose


if sys.version_info < (3, 5):
    raise nose.SkipTest('Skipping tests for Python version < 3.5')
else:
    try:
        import asynctest
    except ImportError:
        raise nose.SkipTest(
            'Skipping tests because asynctest is not installed')

del sys
del nose
