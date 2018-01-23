import os
import unittest

import app
from config import AdminSettings


class AdminTest(unittest.TestCase):
    def setUp(self):
        app.app.testing = True
        self.client = app.app.test_client()

        getattr(app, '_rules')['admin'] = AdminSettings(
            '/admin', 'admin', 'admin'
        )

    def tearDown(self):
        getattr(app, '_rules')['simple'] = {}
        getattr(app, '_rules')['regex'] = []

    def test_admin_ui(self):
        response = self.client.get('/admin')

        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.content_type)
        self.assertIn('Admin UI', str(response.data))

    def test_admin_change(self):
        pass

