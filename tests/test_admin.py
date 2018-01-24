import os
import re
import base64
import hashlib
import unittest

import app
from config import AdminSettings, configure


class AdminTest(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.client = app.app.test_client()
        
        self._setup_admin('admin', 'admin')

    def _setup_admin(self, username, password):
        getattr(app, '_rules')['admin'] = AdminSettings(
            '/admin', username, password
        )

    def _auth(self, username='admin', password='admin'):
        login = '%s:%s' % (username, password)
        return { 
            'Authorization': 'Basic %s' % base64.encodestring(login).strip()
        }

    def tearDown(self):
        getattr(app, '_rules')['simple'] = {}
        getattr(app, '_rules')['regex'] = []

    def assertFlash(self, message, category=None):
        with self.client.session_transaction() as session:
            self.assertIn('_flashes', session)
            self.assertGreater(len(session['_flashes']), 0)

            flash_category, flash_message = session['_flashes'][0]

            self.assertTrue(
                re.match(message, flash_message),
                msg='%s does not match %s' % (flash_message, message)
            )

            if category:
                self.assertEqual(flash_category, category)

    def test_login_required(self):
        response = self.client.get('/admin')

        self.assertEqual(response.status_code, 401)

    def test_login_basic_auth(self):
        response = self.client.get('/admin', headers={
            'Authorization': 'Basic %s' % base64.encodestring('admin:admin').strip()
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.content_type)
        self.assertIn('Admin UI', str(response.data))

    def test_add_simple_rule(self):
        try:
            response = self.client.post('/admin', headers=self._auth(), data={
                'source': '/new/rule',
                'target': 'http://localhost/test-rule'
            })

            self.assertEqual(response.status_code, 302)
            self.assertIn('/new/rule', self._simple_rules)
            self.assertEquals(
                self._simple_rules['/new/rule'].target, 
                'http://localhost/test-rule'
            )

            self.assertFlash('Rule successfully added!')

        finally:
            if os.path.exists('by-admin.rules'):
                os.remove('by-admin.rules')

    def test_add_regex_rule(self):
        try:
            response = self.client.post('/admin', headers=self._auth(), data={
                'source': '/new/(rule|regex)',
                'target': 'http://localhost/test-\\1',
                'regex': 'true',
                'code': '302',
                'ttl': '1m',
                'header__name': 'X-Testing',
                'header__value': 'TestValue'
            })

            self.assertEqual(response.status_code, 302)
            self.assertEqual(len(self._regex_rules), 1)

            rule = self._regex_rules[0]

            self.assertEqual(rule.target, 'http://localhost/test-\\1')
            self.assertEqual(rule.code, 302)
            self.assertIn('Cache-Control', rule.headers)
            self.assertEqual(rule.headers['Cache-Control'], 'max-age=60')
            self.assertIn('X-Testing', rule.headers)
            self.assertEqual(rule.headers['X-Testing'], 'TestValue')

            self.assertFlash('Rule successfully added!')

        finally:
            if os.path.exists('by-admin.rules'):
                os.remove('by-admin.rules')

    def test_invalid_rules(self):
        try:
            response = self.client.post('/admin', headers=self._auth(), data={
                'target': 'missing-source'
            })

            self.assertFlash('Failed to add rule', 'error')

        finally:
            if os.path.exists('by-admin.rules'):
                os.remove('by-admin.rules')

    def test_password_md5(self):
        self._setup_admin('admin-md5', {'md5': '65ed8a5eec59a1a6f75ec845294aead8'})

        response = self.client.get(
            '/admin', headers=self._auth('admin-md5', 'md5pass')
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.content_type)
        
    def test_password_sha1(self):
        self._setup_admin('admin-sha1', {'sha1': 'b37958f21be0b97c823f63ccc45b12368235575f'})

        response = self.client.get(
            '/admin', headers=self._auth('admin-sha1', 'sha1pass')
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.content_type)

    def test_invalid_password_algorithm(self):
        self.assertRaisesRegexp(
            Exception, 'Invalid password hashing algorithm',
            self._setup_admin, 'admin', {'invalid': 'abcd'}
        )

    def test_admin_settings(self):
        try:
            with open('by-admin.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  path: /admin/ui
                  username: usr
                  password:
                    md5: abcd1234
                """)
            
            _, _, admin = configure()

            self.assertIsNotNone(admin)
            self.assertEqual(admin.path, '/admin/ui')
            self.assertEqual(admin.username, 'usr')
            self.assertEqual(admin.password, 'abcd1234')
            self.assertEqual(admin.algorithm, hashlib.md5)

        finally:
            if os.path.exists('by-admin.rules'):
                os.remove('by-admin.rules')

    def test_invalid_admin_settings(self):
        try:
            with open('by-admin.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  path: /admin
                """)

            self.assertRaisesRegexp(Exception, 'Missing username or password', configure)

            with open('by-admin.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  username: admin
                  password: admin
                """)

            self.assertRaisesRegexp(Exception, 'Missing "path"', configure)

            with open('by-admin.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  path: /admin
                  username: ''
                  password: admin
                """)

            self.assertRaisesRegexp(Exception, 'Blank admin username', configure)

            with open('by-admin.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  path: /admin
                  username: admin
                  password: ''
                """)

            self.assertRaisesRegexp(Exception, 'Blank admin password', configure)

        finally:
            if os.path.exists('by-admin.rules'):
                os.remove('by-admin.rules')

    def test_duplicate_admin_settings(self):
        try:
            with open('by-admin.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  path: /admin
                  username: admin
                  password: admin
                """)

            with open('by-admin-2.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  path: /admin
                  username: user
                  password: passwd
                """)

            self.assertRaisesRegexp(
                Exception, 'Admin settings are already defined', configure
            )

        finally:
            if os.path.exists('by-admin.rules'):
                os.remove('by-admin.rules')

            if os.path.exists('by-admin-2.rules'):
                os.remove('by-admin-2.rules')

    def test_rule_masking_admin(self):
        try:
            with open('by-admin.rules', 'w') as admin_file:
                admin_file.write("""
                admin:
                  path: /admin
                  username: admin
                  password: admin

                rules:
                  - source: /admin
                    target: /masked
                """)

            self.assertRaisesRegexp(
                Exception, 'Rule is masking the admin path', configure
            )

        finally:
            if os.path.exists('by-admin.rules'):
                os.remove('by-admin.rules')

    @property
    def _simple_rules(self):
        return getattr(app, '_rules')['simple']

    @property
    def _regex_rules(self):
        return getattr(app, '_rules')['regex']

