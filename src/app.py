import os
import sys
import signal
import logging

from flask import Flask, request, redirect
from prometheus_flask_exporter import PrometheusMetrics

from config import configure

app = Flask(__name__)
metrics = PrometheusMetrics(app)

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger('redirect-service')
logger.setLevel(logging.INFO)


_rules = {
    'simple': {},
    'regex': []
}


@app.route('/<path:_>', methods=['GET'])
def catch_all(_):
    path = request.path

    rule = _rules['simple'].get(path)

    if not rule:
        for regex_rule in _rules['regex']:
            if regex_rule.matches(path):
                rule = regex_rule
                break

    if not rule:
        return 'Not found', 404

    try:
        target = rule.get_target(path)

        response = redirect(target, code=rule.code)
        response.headers.extend(rule.headers)
        return response

    except Exception as ex:
        return 'Failed: %s' % ex, 500


def reload_configuration():
    simple, regex = configure()

    _rules['simple'] = simple
    _rules['regex'] = regex


def handle_signal(num, _):
    if num == signal.SIGHUP:
        reload_configuration()
    elif num == signal.SIGTERM:
        exit(0)
    else:
        exit(1)


if __name__ == '__main__':  # pragma: no cover
    signal.signal(signal.SIGHUP, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    reload_configuration()

    app.run(host=os.environ.get('HTTP_HOST', '127.0.0.1'),
            port=int(os.environ.get('HTTP_PORT', '5000')),
            threaded=True, debug=False)

