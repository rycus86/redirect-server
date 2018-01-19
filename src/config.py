import os
import re
import yaml


class Rule(object):
    def __init__(self, source, target, code=301, headers=None):
        self.source = source
        self.target = target
        self.code = code
        self.regex = None
        self.headers = headers or {}

    def get_target(self, path):
        return self.target


class RegexRule(Rule):
    def __init__(self, source, target, code=301, headers=None):
        super(RegexRule, self).__init__(source, target, code, headers)
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
                rule.code = int(item['code'])

            if 'headers' in item:
                rule.headers.update(item['headers'])

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
                if rule.regex:
                    regex.append(rule)
                else:
                    simple[rule.source] = rule

    return simple, regex

