"""Uji kasus parsing yang mengubah arti fitur subdomain dan URL."""

import unittest

from ekstrak_fitur_url import extract_url_features, shannon_entropy


class UrlFeatureTests(unittest.TestCase):
    def test_multilevel_public_suffix(self):
        values = extract_url_features("https://kkn.uho.ac.id/login?next=%2F")
        self.assertEqual(values["subdomain_count"], 1)
        self.assertEqual(values["path_depth"], 1)
        self.assertEqual(values["sensitive_token_count"], 1)
        self.assertEqual(values["has_https_scheme"], 1)

    def test_private_suffix_treats_tenant_as_site(self):
        values = extract_url_features(
            "https://facebook-247-support.blogspot.com/account/login"
        )
        self.assertEqual(values["subdomain_count"], 0)
        self.assertEqual(values["hyphen_count"], 2)
        self.assertEqual(values["sensitive_token_count"], 2)

    def test_ip_host_and_implicit_root_path(self):
        values = extract_url_features("http://149.28.47.36")
        self.assertEqual(values["has_ip_host"], 1)
        self.assertEqual(values["path_length"], 1)
        self.assertEqual(values["has_https_scheme"], 0)

    def test_url_entropy_and_path_hyphens_are_distinct(self):
        values = extract_url_features("https://a.example.com/verify-account")
        self.assertEqual(values["path_hyphen_count"], 1)
        self.assertEqual(values["hyphen_count"], 0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertEqual(shannon_entropy("ab"), 1.0)


if __name__ == "__main__":
    unittest.main()
