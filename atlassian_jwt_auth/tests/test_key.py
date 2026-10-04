import ntpath
import unittest
from unittest.mock import patch

import atlassian_jwt_auth
from atlassian_jwt_auth import key as key_module


class TestKeyModule(unittest.TestCase):
    """tests for the key module."""

    def test_key_identifier_with_invalid_keys(self) -> None:
        """test that invalid key identifiers are not permitted."""
        keys = [
            "../aha",
            "/a",
            r"\c:a",
            "lk2j34/#$",
            "a../../a",
            "a/;a",
            " ",
            " / ",
            " /",
            "dir/some\0thing",
            "a/#a",
            "a/a?x",
            "a/a;",
            "a//b",
            "a/./b",
            "a/../b",
            "a/b/",
        ]
        for key in keys:
            with self.assertRaises(ValueError):
                atlassian_jwt_auth.KeyIdentifier(identifier=key)

    def test_key_identifier_with_valid_keys(self) -> None:
        """test that valid keys work as expected."""
        for key in ["oa.oo/a", "oo.sasdf.asdf/yes", "oo/o"]:
            key_id = atlassian_jwt_auth.KeyIdentifier(identifier=key)
            self.assertEqual(key_id.key_id, key)

    def test_key_identifier_is_independent_of_windows_paths(self) -> None:
        with patch.object(key_module, "os") as windows_os:
            windows_os.path = ntpath
            identifier = "issuer.example/signing-key"
            self.assertEqual(
                atlassian_jwt_auth.KeyIdentifier(identifier).key_id, identifier
            )
