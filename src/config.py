import os
import re
import sys
import hashlib
import threading

import yaml

_config_lock = threading.Lock()


class Rule(object):
    def __init__(self, source, target, code=301, **kwargs):
        self.source = source
        self.target = target
        self.code = code
        self.regex = None
        self.headers = kwargs.get('headers', dict())
        self.ttl = kwargs.get('ttl')

    def get_target(self, path):
        return self.target


class RegexRule(Rule):
    def __init__(self, source, target, code=301, **kwargs):
        super(RegexRule, self).__init__(source, target, code, **kwargs)
        self.regex = re.compile(source, flags=re.IGNORECASE)

    def matches(self, path):
        return self.regex.match(path)

    def get_target(self, path):
        return self.regex.sub(self.target, path)


class AdminSettings(object):
    def __init__(self, path, username, password):
        self.path = path
        self.username = username

        if isinstance(password, dict):
            self.algorithm, self.password = next(iter(password.items()))

            try:
                self.algorithm = getattr(hashlib, self.algorithm)

            except Exception:
                raise Exception(
                    'Invalid password hashing algorithm: %s (use md5 or sha1)'
                    % self.algorithm
                )

        else:
            self.password = password
            self.algorithm = None

    def verify_credentials(self, username, password):
        if self.username != username:
            return

        if self.algorithm:
            if sys.version_info.major > 2:
                password = password.encode('utf8')

            return self.password == self.algorithm(password).hexdigest()

        else:
            return self.password == password


def _ttl_to_seconds(ttl):
    ttl = str(ttl)

    if not re.match('^[0-9]+[smhd]?$', ttl):
        raise Exception(
            'Invalid TTL definition (numbers and s/m/h/d accepted): %s' % ttl
        )

    if re.match('^[0-9]+[smhd]$', ttl):
        ttl, unit = int(ttl[:-1]), ttl[-1]

        if unit == 'm':
            ttl = ttl * 60

        elif unit == 'h':
            ttl = ttl * 60 * 60

        elif unit == 'd':
            ttl = ttl * 24 * 60 * 60

    else:
        ttl = int(ttl)

    return ttl


def read_rules(file_path):
    with open(file_path, 'r') as source_file:
        rules = yaml.load(source_file)

        admin = None

        if 'admin' in rules:
            admin = rules.pop('admin')

            if 'path' not in admin:
                raise Exception('Missing "path" in admin settings')

            path = admin['path']

            if 'username' not in admin or 'password' not in admin:
                raise Exception(
                    'Missing username or password in admin settings'
                )

            username, password = admin['username'], admin['password']

            if not username:
                raise Exception('Blank admin username')

            if not password:
                raise Exception('Blank admin password')

            yield AdminSettings(path, username, password)

        if 'rules' not in rules:
            if admin:
                return

            else:
                raise Exception(
                    'Failed to load rules from %s : Missing top-level "rules" list' % file_path
                )

        for item in rules['rules']:
            source, target = item.get('source'), item.get('target')

            if not source:
                raise Exception(
                    'Missing source in rule: %s' % item
                )

            if not target:
                raise Exception(
                    'Missing target in rule: %s' % item
                )

            if item.get('regex'):
                rule = RegexRule(source, target)
            else:
                rule = Rule(source, target)

            if 'code' in item:
                code = item['code']

                if not re.match('^[0-9]{3}$', str(code)):
                    raise Exception(
                        'Invalid response code: %s in rule: %s' % (code, item)
                    )

                rule.code = int(code)

            if 'headers' in item:
                headers = item['headers']

                if not isinstance(headers, dict):
                    raise Exception(
                        'Invalid header definition (`dict` expected) in rule: %s' % item
                    )

                rule.headers.update(headers)

            if 'ttl' in item:
                ttl = _ttl_to_seconds(item['ttl'])

                rule.headers['Cache-Control'] = 'max-age=%d' % ttl

            yield rule


def configure(base_dir=None):
    simple = {}
    regex = []
    admin = None

    if not base_dir:
        base_dir = os.environ.get('RULES_DIR', '.')
    
    for filename in os.listdir(base_dir):
        _, extension = os.path.splitext(filename)

        if extension in ('.rules', '.yml', '.yaml'):
            for rule in read_rules(os.path.join(base_dir, filename)):
                if isinstance(rule, AdminSettings):
                    if admin:
                        raise Exception(
                            'Admin settings are already defined'
                        )

                    admin = rule
                    continue

                if rule.source in simple:
                    raise Exception(
                        'Rule is already defined for %s' % rule.source
                    )

                if admin and admin.path == rule.source:
                    raise Exception(
                        'Rule is masking the admin path: %s' % rule.source
                    )

                if any(rule.source == r.source for r in regex):
                    raise Exception(
                        'Regex rule is already defined for %s' % rule.source
                    )

                if rule.regex:
                    regex.append(rule)
                else:
                    simple[rule.source] = rule

    return simple, regex, admin


def add_rule(target_file=None, base_dir=None, **kwargs):
    if not target_file:
        target_file = os.environ.get('TARGET_FILE', 'by-admin.rules')

    if not base_dir:
        base_dir = os.environ.get('RULES_DIR', '.')

    simple, regex, admin = configure(base_dir)
    
    path = os.path.join(base_dir, target_file)

    source, target = kwargs.get('source'), kwargs.get('target')

    if not source:
        raise Exception('Missing source')

    if not target:
        raise Exception('Missing target')

    if source in simple:
        raise Exception(
            'Rule is already defined for %s' % source
        )

    if admin and admin.path == source:
        raise Exception(
            'Rule is masking the admin path: %s' % source
        )

    if any(source == r.source for r in regex):
        raise Exception(
            'Regex rule is already defined for %s' % source
        )

    kwargs = {
        key: value
        for key, value in kwargs.items()
        if value is not None and value != ''
    }

    if 'ttl' in kwargs:
        kwargs['ttl'] = _ttl_to_seconds(kwargs['ttl'])

    with _config_lock:
        if os.path.exists(path):
            with open(path, 'r') as existing_file:
                config = yaml.load(existing_file)

        else:
            config = {'rules': list()}

        config['rules'].append(kwargs)

        with open(path, 'w') as new_file:
            yaml.dump(config, new_file)
