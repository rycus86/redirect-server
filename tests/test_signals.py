import signal
import unittest

import app


class SignalsTest(unittest.TestCase):
    def test_reload(self):
        original = app.reload_configuration

        try:
            invocations = [0]

            def target():
                invocations[0] = 1

            app.reload_configuration = target

            app.handle_signal(signal.SIGHUP, 0)

            self.assertEqual(invocations[0], 1)

        finally:
            app.reload_configuration = original

    def test_exit_clean(self):
        try:
            app.handle_signal(signal.SIGTERM, 0)
            
            self.fail('Exit signal not processed')

        except SystemExit as ex:
            self.assertEqual(ex.code, 0)

    def test_exit_error(self):
        try:
            app.handle_signal(signal.SIGINT, 0)
            
            self.fail('Exit signal not processed')

        except SystemExit as ex:
            self.assertEqual(ex.code, 1)

