from masquerade.config import Config, EMPTY
import configparser
import click
from boto3 import Session
from uuid import uuid4
import json
from pathlib import Path
from datetime import timezone, timedelta, datetime

config = Config()
AWS_DIR_PATH = Path.home().joinpath('.aws')
CREDENTIAL_PATH = Path.home().joinpath('.aws/credentials')
CONFIG_PATH = Path.home().joinpath('.aws/config')

@click.group()
def main():
    pass


@main.command()
@click.option('--account', '-a', default='default', show_default=True, help='setting account name')
def configure(account):
    keys = {
        'profile_name': True,
        'source_profile': True,
        'role_arn': True,
        'mfa_arn': False,
        'region': False,
        'output': False
    }
    origin = config.get_account(account_name=account)
    now = {}
    for k, is_required in keys.items():
        previous = origin.get(k)
        default_text = f' [{previous}]' if k in origin else ''
        default_value = ''
        if is_required:
            default_value = previous
        value = click.prompt(f'  {k}{default_text}', default=default_value, show_default=False)
        if len(value) == 0:
            if not previous:
                continue
            delete_flag = click.confirm(f'    delete option "{k}"', default=False)
            if delete_flag:
                continue
            value = previous
        now[k] = value
    print()
    print('=' * 15)
    print()
    print(f'  account_name: {account}')
    for k in keys.keys():
        now_value = now.get(k)
        if not now_value:
            now_value = '(None)'
        if origin == EMPTY:
            print(f'  {k}: {now_value}')
        else:
            previous_value = origin.get(k)
            if not previous_value:
                previous_value = '(None)'
            print(f'  {k}: {previous_value} -> {now_value}')

    print()
    save_flag = click.confirm(f'save this account "{k}"', default=True)
    if save_flag:
        config.put_account(account_name=account, **now)
        config.save()
        print()
        print('this account is saved.')


@main.command()
@click.option('--account', '-a', default='default', show_default=True, help='setting account name')
def assume(account):
    def default(obj):
        try:
            json.dumps(obj)
            return obj
        except Exception:
            return str(obj)
    info_account = config.get_account(account_name=account)
    if info_account == EMPTY:
        print(f'account "{account}" is not configured.')
        return

    config_data = {}
    for k in ['config', 'region']:
        v = info_account.get(k)
        if v:
            config_data[k] = v

    option = {
        'RoleArn': info_account['role_arn'],
        'RoleSessionName': f'a-{uuid4()}'
    }
    if 'mfa_arn' in info_account:
        option['SerialNumber'] = info_account['mfa_arn']
        option['TokenCode'] = click.prompt('MFA Token Code')
    resp = Session(profile_name=info_account['source_profile']).client('sts').assume_role(**option)

    credential_data = {
        'aws_access_key_id': resp['Credentials']['AccessKeyId'],
        'aws_secret_access_key': resp['Credentials']['SecretAccessKey'],
        'aws_session_token': resp['Credentials']['SessionToken'],
        'aws_security_token': resp['Credentials']['SessionToken'],
        'x_principal_arn': resp['AssumedRoleUser']['Arn'],
        'x_security_token_expires': str(resp['Credentials']['Expiration'].astimezone(timezone(offset=timedelta(hours=+9))))
    }

    credential_parser = configparser.ConfigParser()
    credential_parser.read(str(CREDENTIAL_PATH))

    if account not in credential_parser:
        credential_parser.add_section(account)

    for k, v in credential_data.items():
        credential_parser.set(account, k, v)

    credential_parser.write(CREDENTIAL_PATH.open(mode='w'))

    if len(config_data.keys()) > 0:
        config_parser = configparser.ConfigParser()
        config_parser.read_file(CONFIG_PATH.open())
        profile = f'profile {account}'
        if profile not in config_parser:
            config_parser.add_section(profile)
        for k, v in config_data.items():
            config_parser.set(profile, k, v)
        config_parser.write(CONFIG_PATH.open(mode='w'))

        print(f'\nuse this profile: --profile {account}')