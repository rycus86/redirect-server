import os
import signal
import logging

from flask import Flask, g, request, redirect, render_template, flash
from flask_httpauth import HTTPBasicAuth
from prometheus_flask_exporter import PrometheusMetrics
from docker_helper import read_configuration

from config import configure, add_rule, delete_rule

app = Flask(__name__)
app.config['SECRET_KEY'] = read_configuration('SECRET_KEY', '/var/secrets/flask', 'InSecure')

auth = HTTPBasicAuth()
metrics = PrometheusMetrics(app)

metrics.info('flask_app_info', 'Application info',
             version=os.environ.get('GIT_COMMIT') or 'unknown')

metrics.info(
    'flask_app_built_at', 'Application build timestamp'
).set(
    float(os.environ.get('BUILD_TIMESTAMP') or '0')
)

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(module)s.%(funcName)s - %(message)s')
logger = logging.getLogger('redirect-service')
logger.setLevel(logging.INFO)


_rules = {
    'simple': {},
    'regex': [],
    'admin': None
}


@app.route('/', methods=['GET'], defaults={'_': None})
@app.route('/<path:_>', methods=['GET', 'POST'])
def catch_all(_):
    path = request.path

    admin = _rules['admin']

    if admin and admin.path == path:
        return handle_admin_request()

    if request.method != 'GET':
        return 'Invalid HTTP method: %s' % request.method, 405

    host_header = request.headers.get('Host', '')

    rule = _rules['simple'].get(path)

    if rule and rule.host and rule.host.lower() != host_header.lower():
        # discard this rule if the Host header does not match
        rule = None

    if not rule:
        for regex_rule in _rules['regex']:
            if regex_rule.matches(path):
                if regex_rule.host and regex_rule.host.lower() != host_header.lower():
                    # discard this rule if the Host header does not match
                    continue

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


@auth.login_required
def handle_admin_request():
    if request.method == 'GET':
        simple, regex, admin = (_rules[key] for key in ('simple', 'regex', 'admin'))
        content = render_template(
            'admin.html',
            simple_rules=simple,
            regex_rules=regex,
            admin=admin
        )

        return content, 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        }

    elif request.method == 'POST': 
        admin = _rules['admin']
        if not admin:
            return 'Unexpected error: admin UI is not configured', 500

        if 'delete' in request.form:
            source = request.form.get('delete')

            logger.info('Deleting rule: %s' % source)

            try:
                delete_rule(source)

                reload_configuration()

                flash('Rule successfully deleted')

            except Exception as ex:
                flash('Failed to delete rule: %s' % ex, category='error')

            return redirect(admin.path, 302)

        source = request.form.get('source')
        host = request.form.get('host')
        target = request.form.get('target')
        regex = 'regex' in request.form
        code = request.form.get('code')
        ttl = request.form.get('ttl')
        header_names = request.form.getlist('header__name')
        header_values = request.form.getlist('header__value')

        if code:
            code = int(code)

        headers = None

        if header_names and any(header_names) and len(header_names) == len(header_values):
            headers = dict(zip(header_names, header_values))

        try:
            logger.info(
                'Adding rule: %s -> %s [%s] regex=%s host=%s ttl=%s headers=%s' % \
                (source, target, code, regex, host, ttl, headers)
            )

            add_rule(
                source=source, target=target, regex=regex, host=host,
                code=code, ttl=ttl, headers=headers
            )

            reload_configuration()

            flash('Rule successfully added!')

        except Exception as ex:
            flash('Failed to add rule: %s' % ex, category='error')

        return redirect(admin.path, 302)

    return 'Invalid request method: %s' % request.method, 405


# authentication code from
# https://github.com/miguelgrinberg/Flask-HTTPAuth/blob/master/examples/multi_auth.py

@auth.verify_password
def verify_password(username, password):
    admin = _rules.get('admin')

    g.user = None
    if admin:
        if admin.verify_credentials(username, password):
            g.user = username
            return True
    return False


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

