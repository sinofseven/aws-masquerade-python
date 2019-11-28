from configparser import ConfigParser
from pathlib import Path

EMPTY = {}
DIRECTORY_PATH = Path.home().joinpath('.config/aws_masquerade')
FILE_PATH = DIRECTORY_PATH.joinpath('config')


class Config(object):

    def __init__(self):
        self.parser = ConfigParser()
        if FILE_PATH.is_file():
            self.parser.read(str(FILE_PATH))

    def put_account(self, *, account_name, profile_name, source_profile, role_arn, mfa_arn=None, region=None, output=None):
        if account_name not in self.parser:
            self.parser.add_section(account_name)
        self.parser.set(account_name, 'profile_name', profile_name)
        self.parser.set(account_name, 'source_profile', source_profile)
        self.parser.set(account_name, 'role_arn', role_arn)
        if mfa_arn is None:
            self.parser.remove_option(account_name, 'mfa_arn')
        else:
            self.parser.set(account_name, 'mfa_arn', mfa_arn)

        if region is None:
            self.parser.remove_option(account_name, 'region')
        else:
            self.parser.set(account_name, 'region', region)

        if output is None:
            self.parser.remove_option(account_name, 'output')
        else:
            self.parser.set(account_name, 'output', output)

    def get_account(self, *, account_name):
        result = {}
        if account_name not in self.parser:
            return result
        for k, v in self.parser[account_name].items():
            result[k] = v
        return result

    def save(self):
        if not DIRECTORY_PATH.exists():
            DIRECTORY_PATH.mkdir(parents=True)
        self.parser.write(open(str(FILE_PATH), mode='w'))
