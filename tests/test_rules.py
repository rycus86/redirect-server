import os
import unittest

import app
from config import Rule, RegexRule


class RulesTest(unittest.TestCase):
    def setUp(self):
        self._set_rules([], [])

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

    def test_root_rule(self):
        self._set_rules([
            Rule('/', 'http://root.rule')
        ], [])

        self.verify('/', 'http://root.rule')

    def test_rule_ttl(self):
        with open('./ttl.rules', 'w') as rules:
            rules.write("""
            rules:
              - source: /30seconds
                target: http://30.seconds
                ttl: 30
              
              - source: /15seconds
                target: http://15.seconds
                ttl: 15s
              
              - source: /5minutes
                target: http://5.minutes
                ttl: 5m

              - source: /4hours
                target: http://4.hours
                ttl: 4h
              
              - source: /90days
                target: http://90.days
                ttl: 90d
            """)

        try:
            app.reload_configuration()

        finally:
            os.remove('./ttl.rules')

        self.verify('/30seconds', 'http://30.seconds', headers={'Cache-Control': 'max-age=30'})
        self.verify('/15seconds', 'http://15.seconds', headers={'Cache-Control': 'max-age=15'})
        self.verify('/5minutes', 'http://5.minutes', headers={'Cache-Control': 'max-age=300'})
        self.verify('/4hours', 'http://4.hours', headers={'Cache-Control': 'max-age=14400'})
        self.verify('/90days', 'http://90.days', headers={'Cache-Control': 'max-age=7776000'})

    def test_from_files(self):
        with open('./redirects.yml', 'w') as rules:
            rules.write("""
            rules:
              - source: /simple
                target: http://simple.sample/test

              - source: /s/e/c/o/n/d
                target: http://second.simple
                code: 302
              
              - source: /headers
                target: http://with.headers
                headers:
                  X-Sample: sample
                  X-Testing: testing
            """)

        with open('./regex.rules', 'w') as rules:
            rules.write("""
            rules:
              - source: /[a-z]+[0-9]+$
                target: http://letters.and.numbers
                regex: true
              
              - source: /api/v[1-3]/test
                target: /api/v4/test
                regex: true
              
              - source: ^/([0-9]+)/([a-z]+)$
                target: http://reversed/\\2/\\1
                regex: true
            """)

        try:
            app.reload_configuration()

        finally:
            os.remove('./redirects.yml')
            os.remove('./regex.rules')

        self.verify('/simple', 'http://simple.sample/test')
        self.verify('/not/simple', code=404)
        self.verify('/s/e/c/o/n/d', 'http://second.simple', code=302)
        self.verify('/headers', 'http://with.headers', headers={
            'X-Sample': 'sample',
            'X-Testing': 'testing'
        })

        self.verify('/xyz123', 'http://letters.and.numbers')
        self.verify('/xyz123zz', code=404)
        self.verify('http://example1.domain/api/v1/test', 'http://example1.domain/api/v4/test')
        self.verify('http://example2.domain/api/v2/test', 'http://example2.domain/api/v4/test')
        self.verify('http://example3.domain/api/v3/test', 'http://example3.domain/api/v4/test')
        self.verify('http://example.domain/api/v5/test', code=404)

        self.verify('/123/abcd', 'http://reversed/abcd/123')
        self.verify('/999/xyza', 'http://reversed/xyza/999')
        self.verify('/000/mmm1', code=404)

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
        if simple is not None:
            getattr(app, '_rules')['simple'] = {
                rule.source: rule for rule in simple
            }
        
        if regex is not None:
            getattr(app, '_rules')['regex'] = regex

