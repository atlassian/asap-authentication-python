import unittest

import atlassian_jwt_auth


class TestKeyModule(unittest.TestCase):

    """ tests for the key module. """

    def test_key_identifier_with_invalid_keys(self):
        """ test that invalid key identifiers are not permitted. """
        keys = ['../aha', '/a', '\c:a', 'lk2j34/#$', 'a../../a', 'a/;a',
                ' ', ' / ', ' /',
                u'dir/some\0thing', 'a/#a', 'a/a?x', 'a/a;',
                ]
        for key in keys:
            with self.assertRaises(ValueError):
                atlassian_jwt_auth.KeyIdentifier(identifier=key)

    def test_key_identifier_with_valid_keys(self):
        """ test that valid keys work as expected. """
        for key in ['oa.oo/a', 'oo.sasdf.asdf/yes', 'oo/o']:
            key_id = atlassian_jwt_auth.KeyIdentifier(identifier=key)
            self.assertEqual(key_id.key_id, key)
