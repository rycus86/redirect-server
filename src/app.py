import os
import sys
import signal
import logging

from flask import Flask, request, redirect, render_template
from prometheus_flask_exporter import PrometheusMetrics

from config import configure, add_rule

app = Flask(__name__)
metrics = PrometheusMetrics(app)

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger('redirect-service')
logger.setLevel(logging.INFO)


_rules = {
    'simple': {},
    'regex': [],
    'admin': None
}


@app.route('/<path:_>', methods=['GET', 'POST'])
def catch_all(_):
    path = request.path

    admin = _rules['admin']

    if admin and admin.path == path:
        return handle_admin_request()
    
    if request.method != 'GET':
        return 'Invalid HTTP method: %s' % request.method, 405

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


def handle_admin_request():
    # TODO authenticate

    if request.method == 'GET':
        simple, regex, admin = (_rules[key] for key in ('simple', 'regex', 'admin'))
        return render_template('admin.html', 
            simple_rules=simple,
            regex_rules=regex,
            admin=admin
        )

    elif request.method == 'POST':
        admin = _rules['admin']
        if not admin:
            return 'Unexpected error: admin UI is not configured', 500

        source, target = request.form['source'], request.form['target']
        regex = 'regex' in request.form

        logger.info('%s %s %s' % (source, target, regex))  # TODO

        add_rule(source=source, target=target, regex=regex)

        reload_configuration()
        
        return redirect(admin.path, 302)

    return 'Invalid request method: %s' % request.method, 405


def reload_configuration():
    simple, regex, admin = configure()

    _rules['simple'] = simple
    _rules['regex'] = regex
    _rules['admin'] = admin

    logger.info('Reloaded %d rules' % (len(simple) + len(regex)))


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

