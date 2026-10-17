import unittest
from modules.vuln import match_title


class MatchingTests(unittest.TestCase):
    def check(self, spec, detected, expected, product='Apache'):
        self.assertEqual(match_title(f'{product} {spec} - Example', product, detected)[0], expected)

    def test_exact_and_unrelated_versions(self):
        self.check('2.4.49', '2.4.49', 'matched')
        self.check('2.4.49', '2.4.68', 'rejected')
        self.check('2.4.6', '2.4.68', 'rejected')
        self.check('2.4.68', '2.4.68 (Debian)', 'matched')

    def test_ranges(self):
        self.check('< 2.4.50', '2.4.49', 'matched')
        self.check('< 2.4.50', '2.4.50', 'rejected')
        self.check('<= 2.4.50', '2.4.50', 'matched')
        self.check('2.4.49 - 2.4.50', '2.4.50', 'matched')
        self.check('2.4.49 - 2.4.50', '2.4.68', 'rejected')
        self.check('3.0.20 < 3.0.25rc3', '3.0.25', 'rejected', 'Samba')
        self.check('3.0.20 < 3.0.25rc3', '3.0.20-Debian', 'matched', 'Samba')

    def test_wildcards_lists_and_suffixes(self):
        self.check('2.4.x', '2.4.68', 'unverified')
        self.check('2.4.x', '2.5.0', 'rejected')
        self.check('2.4.49/2.4.50', '2.4.68', 'rejected')
        self.check('2.x/3.x/4.x', '4.7p1 Debian', 'unverified', 'OpenSSH')
        self.check('4.7p1', '4.7p2', 'rejected', 'OpenSSH')
        self.check('4.7p1', '4.7p1 Debian', 'matched', 'OpenSSH')

    def test_ambiguity_is_not_a_match(self):
        self.check('2.4', '2.4.68', 'unverified')
        self.check('', '2.4.68', 'unverified')
        self.check('2.4.x', '', 'unverified')
        self.check('2.4.x', '2.4.0 - 2.4.68', 'unverified')
        self.assertEqual(match_title('Apache Tomcat 2.4.68 - Example', 'Apache', '2.4.68')[0], 'unverified')
        self.assertEqual(match_title('nginx 2.4.68 - Example', 'Apache', '2.4.68')[0], 'rejected')


if __name__ == '__main__':
    unittest.main()
