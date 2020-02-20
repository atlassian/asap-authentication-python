import unittest

from atlassian_jwt_auth.frameworks.common import utils


class SettingsDictTest(unittest.TestCase):
    """ Tests for the SettingsDict class. """

    def test_hash(self):
        """ Test that SettingsDict instances can be hashed. """
        dictionary_one = {'a': 'b', '3': set([1]), 'f': None}
        dictionary_two = {'a': 'b', '3': set([1]), 'f': None}
        dictionary_three = {'a': 'b', '3': set([1]), 'diff': '333'}
        settings_one = utils.SettingsDict(dictionary_one)
        settings_two = utils.SettingsDict(dictionary_two)
        settings_three = utils.SettingsDict(dictionary_three)
        self.assertEqual(settings_one, settings_two)
        self.assertEqual(hash(settings_one), hash(settings_two))
        self.assertNotEqual(settings_one, settings_three)
        self.assertNotEqual(hash(settings_one), hash(settings_three))
