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


class RegexRule(Rule):
    def __init__(self, source, target):
        super(RegexRule, self).__init__(source, target)
        self.regex = re.compile(source, flags=re.IGNORECASE)

    def matches(self, path):
        return self.regex.match(path)


def read_rules(file_path):
    with open(file_path, 'r') as source_file:
        rules = yaml.load(source_file)
        if 'rules' not in rules:
            raise Exception(
                'Failed to load rules from %s : Missing top-level "rules" list' % file_path
            )

        for item in rules['rules']):
            if item.get('regex'):
                pass  # TODO


def configure(base_dir=os.environ.get('RULES_DIR', '.')):
    simple = {}
    regex = []
    
    for filename in os.listdir(base_dir):
        _, extension = os.path.splitext(filename)

        if extension in ('.rules', '.yml', '.yaml'):
            for rule in read_rules(os.path.join(base_dir, filename)):
                if rule.regex:
                    regex.append(rule)
                else:
                    simple[rule.source] = rule

    return simple, regex

