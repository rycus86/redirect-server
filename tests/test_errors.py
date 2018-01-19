import os
import signal
import unittest

import app
from config import Rule, RegexRule


class ErrorsTest(unittest.TestCase):
    def setUp(self):
        app.app.testing = True

    def tearDown(self):
        getattr(app, '_rules')['simple'] = {}
        getattr(app, '_rules')['regex'] = []

    def test_missing_rules(self):
        config = """
        - source: /failing
          target: /nope
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Missing top-level "rules" list', self.reload)

    def test_missing_source(self):
        config = """
        rules:
          - source: /ok
            target: /good
          
          - target: /oops
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Missing source in rule', self.reload)

    def test_missing_target(self):
        config = """
        rules:
          - source: /ok
            target: /good
          
          - source: /oops
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Missing target in rule', self.reload)

    def test_invalid_regex(self):
        config = """
        rules:
          - source: /unclosed(group
            target: /oops
            regex: true
        """

        with self.new_client(config) as client:
            self.assertRaises(Exception, self.reload)

    def test_invalid_regex_replacement(self):
        config = """
        rules:
          - source: /with/(one)/group
            target: /second/\\2
            regex: true
        """
        
        with self.new_client(config) as client:
            self.reload()

            response = client.get('/with/one/group')

            self.assertEqual(response.status_code, 500)

    def test_invalid_code(self):
        config = """
        rules:
          - source: /invalid
            target: /code
            code: 42
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Invalid response code', self.reload)

    def test_invalid_headers(self):
        config = """
        rules:
          - source: /invalid
            target: /headers
            headers: x=y
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Invalid header definition', self.reload)

    def test_invalid_ttl(self):
        config = """
        rules:
          - source: /invalid
            target: /ttl
            ttl: 17x
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Invalid TTL definition', self.reload)

    def test_duplicate_simple_rule(self):
        config = """
        rules:
          - source: /test
            target: /first

          - source: /test
            target: /second
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Rule is already defined', self.reload)

    def test_duplicate_regex_rule(self):
        config = """
        rules:
          - source: /test/[0-9]+
            target: /first
            regex: true

          - source: /test/[0-9]+
            target: /second
            regex: true
        """

        with self.new_client(config) as client:
            self.assertRaisesRegexp(Exception, 'Regex rule is already defined', self.reload)

    def test_invalid_http_method(self):
        config = """
        rules:
          - source: /only/get
            target: /ok
        """
        
        with self.new_client(config) as client:
            self.reload()

            response = client.post('/only/get')

            self.assertEqual(response.status_code, 405)

    def reload(self):
        app.handle_signal(signal.SIGHUP, None)

    def new_client(self, *configuration):
        class TestContext(object):
            def __enter__(self):
                for idx, config in enumerate(configuration):
                    with open('./config-%d.rules' % idx, 'w') as rules:
                        rules.write(config)

                return app.app.test_client()

            def __exit__(self, exc_type, exc_val, exc_tb):
                for idx in range(len(configuration)):
                    os.remove('./config-%d.rules' % idx)

        return TestContext()

