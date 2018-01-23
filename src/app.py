import os
import signal
import logging

from flask import Flask, g, request, redirect, render_template, flash
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from itsdangerous import TimedJSONWebSignatureSerializer as JWT
from prometheus_flask_exporter import PrometheusMetrics
from docker_helper import read_configuration

from config import configure, add_rule

app = Flask(__name__)
app.config['SECRET_KEY'] = read_configuration('SECRET_KEY', '/var/secrets/flask', 'UnSecure')
jwt = JWT(app.config['SECRET_KEY'], expires_in=3600)

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)

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


@multi_auth.login_required
def handle_admin_request():
    if request.method == 'GET':
        simple, regex, admin = (_rules[key] for key in ('simple', 'regex', 'admin'))
        return render_template(
            'admin.html',
            simple_rules=simple,
            regex_rules=regex,
            admin=admin
        )

    elif request.method == 'POST':
        admin = _rules['admin']
        if not admin:
            return 'Unexpected error: admin UI is not configured', 500

        source = request.form['source']
        target = request.form['target']
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
                'Adding rule: %s -> %s [%d] regex=%s ttl=%s headers=%s' %
                (source, target, code, regex, ttl, headers)
            )

            add_rule(
                source=source, target=target, regex=regex,
                code=code, ttl=ttl, headers=headers
            )

            reload_configuration()

            flash('Rule successfully added!')

        except Exception as ex:
            import traceback
            traceback.print_exc()
            flash('Failed to add rule: %s' % ex, category='error')

        return redirect(admin.path, 302)

    return 'Invalid request method: %s' % request.method, 405


# authentication code from
# https://github.com/miguelgrinberg/Flask-HTTPAuth/blob/master/examples/multi_auth.py

@basic_auth.verify_password
def verify_password(username, password):
    admin = _rules.get('admin')

    g.user = None
    if admin:
        if admin.verify_credentials(username, password):
            g.user = username
            return True
    return False


@token_auth.verify_token
def verify_token(token):
    g.user = None
    try:
        data = jwt.loads(token)
    except:
        return False
    if 'username' in data:
        g.user = data['username']
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

