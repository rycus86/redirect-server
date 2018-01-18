import unittest

import app
from config import Rule, RegexRule


class RulesTest(unittest.TestCase):
    def setUp(self):
        setattr(app, '_simple_rules', {})
        setattr(app, '_regex_rules', [])

        app.app.testing = True
        self.client = app.app.test_client()

    def test_simple_rules(self):
        self._set_rules([
            Rule('/sample', 'http://sample.com'),
            Rule('/testing', 'https://testing.com', code=301),
            Rule('/headers', 'http://headers.target', headers={'X-Header': 'Testing'})
        ])

        self.verify('/sample', 'http://sample.com')
        self.verify('/testing', 'https://testing.com', code=301)
        self.verify('/headers', 'http://headers.target', headers={'X-Header': 'Testing'})
        self.verify('/none', code=404)

    def test_regex_rules(self):
        self._set_rules(None, [
            RegexRule('/[0-9]+', 'http://numbers'),
            RegexRule('/[a-z]+', 'http://letters')
        ])
        
        self.verify('/123456', 'http://numbers')
        self.verify('/abcdef', 'http://letters')

    def test_mixed_rules(self):
        self._set_rules([
            Rule('/simple', 'http://simple.com'),
            Rule('/m1x3d', 'http://mixed.chars')
        ], [
            RegexRule('/[simple]+', 'http://regex.one'),
            RegexRule('/[0-9][a-z0-9]+', 'http://regex.two')
        ])

        self.verify('/simple', 'http://simple.com')
        self.verify('/m1x3d', 'http://mixed.chars')
        self.verify('/smple', 'http://regex.one')
        self.verify('/0th3rRul3', 'http://regex.two')

    def test_from_files(self):
        with open('/tmp/redirects.yml', 'w') as rules:
            rules.write("""
            rules:
              - source: /simple
                target: 'http://simple.sample/test'

              - source: /s/e/c/o/n/d
                target: 'http://second.simple'
                code: 302
              
              - source: /headers
                target: 'http://with.headers'
                headers:
                  X-Sample: sample
                  X-Testing: testing
            """)

        with open('/tmp/regex.rules', 'w') as rules:
            rules.write("""
            rules:
              - source: /[a-z]+[0-9]+
                target: http://letters.and.numbers
                regex: true
              
              - source: /api/v[1-3]/test
                target: /api/v4/test
                regex: true
            """)

        app.reload_configuration()

        self.verify('/simple', 'http://simple.sample/test')
        self.verify('/not/simple', code=404)

    def verify(self, uri, target=None, code=301, headers=None):
        response = self.client.get(uri)

        self.assertEqual(response.status_code, code)

        if target:
            self.assertEqual(response.headers.pop('Location', None), target)

        if headers:
            for key, value in headers.items():
                self.assertIn(key, headers)
                self.assertEqual(response.headers.get(key), value)

    @staticmethod
    def _set_rules(simple=None, regex=None):
        if simple:
            setattr(app, '_simple_rules', {
                rule.source: rule for rule in simple
            })
        
        if regex:
            setattr(app, '_regex_rules', regex)
