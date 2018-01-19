import os
import re
import yaml


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


def read_rules(file_path):
    with open(file_path, 'r') as source_file:
        rules = yaml.load(source_file)
        if 'rules' not in rules:
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
                ttl = str(item['ttl'])

                if not re.match('^[0-9]+[smhd]?$', ttl):
                    raise Exception(
                        'Invalid TTL definition (numbers and s/m/h/d accepted) in rule: %s' % item
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

                rule.headers['Cache-Control'] = 'max-age=%d' % ttl

            yield rule


def configure(base_dir=None):
    simple = {}
    regex = []

    if not base_dir:
        base_dir = os.environ.get('RULES_DIR', '.')
    
    for filename in os.listdir(base_dir):
        _, extension = os.path.splitext(filename)

        if extension in ('.rules', '.yml', '.yaml'):
            for rule in read_rules(os.path.join(base_dir, filename)):
                if rule.source in simple:
                    raise Exception(
                        'Rule is already defined for %s' % rule.source
                    )

                if any(rule.source == r.source for r in regex):
                    raise Exception(
                        'Regex rule is already defined for %s' % rule.source, rule
                    )

                if rule.regex:
                    regex.append(rule)
                else:
                    simple[rule.source] = rule

    return simple, regex

