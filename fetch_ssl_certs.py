#!/usr/bin/env python3
import datetime
import logging as log
import os
import platform
import re
import collections
import requests

API_BASE_URL="https://porkbun.com/api/json/v3/ssl/retrieve/"


def _get_dotenv_vars():
    fp_env_vars: str=os.path.join(os.getcwd(), '.env')  # default file path for .env vars

    env_vars: dict={}
    try:
        with open(fp_env_vars, 'r') as file:
            for line in file:
                # print(line)
                line=line.strip()
                # ignore lines starting with # (comments) or [ (section headers)
                if line and not line.startswith('#') and not line.startswith('['):
                    print(f"key, value: {line.split('=', 1)}")
                    key, value=line.split('=', 1)
                    # remove leading/trailing whitespace + remove quotation characters from beg/end of value if present
                    env_vars[key.strip()]=value.strip().strip("'").strip('"')
                    print(f"env_vars: {env_vars}")

    except FileNotFoundError:
        # print(f"Error: no file found at {fp_env_vars}. Unable to read environment variables. Exiting")
        # exit(1)
        print(f"No .env file found. Continuing without .env file.")


    except PermissionError:
        print(f"Error: Permission denied to read {fp_env_vars}. Continuing without any values from .env file.")

    # return the dict of environment variables. checking for necessary variables handled elsewhere.
    return env_vars


def validate_env_vars(env_vars: dict) -> tuple[str, ...]:
    domain_pattern=re.compile(r'^[a-zA-Z0-9\-.]+$')  # checks for a valid domain name (alphanumeric, hyphen, period)
    secret_api_key_pattern=re.compile(
        r'^sk\d_[a-f0-9]{64}$')  # checks for a valid secret api key (sk followed by a number (typically 1), _,
    # and 64 hex characters)
    api_key_pattern=re.compile(r'^pk\d_[a-f0-9]{64}$')  # checks for a valid api key
    save_path_pattern=re.compile(r'^/.+$')  # checks for a full path todo - make windows compatible

    # check if all necessary variables are present in the environment variables
    if not all(key in env_vars for key in ['domain', 'api_key', 'secret_api_key', 'save_path']):
        error_msg="Error: Missing necessary environment variables. Exiting"
        log.error(error_msg)
        print(error_msg)
        exit(1)

    # ###
    # verify vars are valid and return them
    #
    # - capture vars
    domain=env_vars['domain']
    api_key=env_vars['api_key']
    secret_api_key=env_vars['secret_api_key']
    save_path=env_vars['save_path']

    # - validate vars against regex patterns
    if not domain_pattern.fullmatch(domain):
        error_msg=f"Error: Invalid domain name: {domain}. Exiting"
        log.error(error_msg)
        print(error_msg)
        exit(1)

    if not api_key_pattern.fullmatch(api_key):
        error_msg=f"Error: API key {api_key} does not match expected pattern. Exiting"
        log.error(error_msg)
        print(error_msg)
        exit(1)

    if not secret_api_key_pattern.fullmatch(secret_api_key):
        error_msg=f"Error: Secret {secret_api_key} does not match expected pattern. Exiting"
        log.error(error_msg)
        print(error_msg)
        exit(1)

    # substitute variables if present in save_path
    while match:=re.search(re.compile(r'{(\w+)}'), save_path):
        # replace {some_key} with the value of the environment variable some_key, or "placeholder" if not found
        save_path=save_path.replace(match[0], env_vars.get(match[1], "placeholder"))

    return domain, api_key, secret_api_key, save_path


def setup_log_file(env_vars: dict) -> str:
    """
    Ensure the log file exists and has write access, creating it (and any intermediate directories) if needed
    :param env_vars: dictionary of environment variables
    :type env_vars: dict
    :return: full path to validated log file
    :rtype: str
    """
    # get log filepath from env variables, if provided. if not, default log file will be
    # /var/log/porkbun_ssl_fetch.log or $(pwd)/porkbun_ssl_fetch.log,
    log_file=env_vars['log_file']

    # check if the directory for the log file exists and create it if not
    if not os.path.exists(log_path:=os.path.dirname(log_file)):
        try:
            os.makedirs(log_path)
            log.info(f'created directory for log file: {log_path}')
        except PermissionError:
            # unable to create log file directory -- print error and exit
            print(f'insufficient permissions to create directory for log file `{log_file}`. Exiting')
            exit(1)

    if os.path.exists(log_file):
        if not os.access(log_file, os.W_OK):
            # log file exists but does not have write permissions -- print error and exit
            print(f'insufficient permissions to write to log file `{log_file}`. Exiting.')
            exit(1)
    else:
        try:
            with open(log_file, 'w') as f:  # create log file with current date and time
                f.write('File created on ' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                log.info(f'created log file: {log_file}')
        except PermissionError:
            # unable to create log file -- print error and exit
            print(f'unable to create log file `{log_file}`, insufficient permissions. Exiting')
            exit(1)

    return log_file


def is_nix_os() -> bool:
    """
    Check if the current operating system is a Unix-like system (Linux, macOS, etc.)
    :return: True if the current operating system is a Unix-like system, False otherwise
    :rtype: bool
    """
    return platform.system() in ['Linux', 'Darwin', 'FreeBSD', 'OpenBSD']


def fetch_ssl_certs(env_vars: dict):
    log.info(f"fetch_ssl_certs() started: {datetime.datetime.now()}")
    # log.info(f"env_vars: {env_vars}") # uncomment to see all env vars
    domain, api_key, secret_api_key, save_path=validate_env_vars(env_vars)

    log.info(f"Domain: {domain}")
    log.info(f"Save path for certificates: {save_path}")

    api_endpoint=f"{API_BASE_URL}{domain}"

    # create payload to send with api call
    json_data={
        "secretapikey": secret_api_key,
        "apikey": api_key
    }

    log.info(f'making api call to {api_endpoint}')

    # make the request to the porkbun API
    response=requests.post(api_endpoint, json=json_data)

    log.info(f"Response code: {response.status_code}")

    if response.status_code == 200:  # if the request was successful
        log.debug(f'api response: {response.json()}')
        # print(f'api response: {response.json()}')
        data=response.json()

        # define the keys that we expect to receive from the api response with their corresponding file names ((key,
        # file_name))
        KeyFile=collections.namedtuple('KeyFile', ['key', 'file'])
        certificate_keys=[KeyFile('intermediatecertificate', 'intermediate.cert.pem'),
                          KeyFile('certificatechain', 'domain.cert.pem'),
                          KeyFile('privatekey', 'private.key.pem'),
                          KeyFile('publickey', 'public.key.pem')]

        # ensure save_path exists and has write access
        validate_save_path(save_path)

        # save the certificate bundle (full api response text) to a file
        with open(certificate_bundle_path:=os.path.join(save_path, f'certificate_bundle_{datetime.date.today()}.txt'),
            'w') as f:
            f.write(response.text)
            log.info(f'certificate bundle saved at {certificate_bundle_path}')

        # Iterate thru expected keys (see `certificate_keys`) and save if present and log error if not
        for kf in certificate_keys:
            if kf.key in data:
                # extract the certificate from the api response
                cert=data[kf.key]

                # save the certificate to a file
                with open(cert_fp:=os.path.join(save_path, kf.file), 'w') as f:
                    f.write(cert)
                    log.info(f'certificate saved at {cert_fp}')
            else:
                log.error(f'API response missing key: {kf.key}. Will continue + save any keys were received.')


def validate_save_path(save_path):
    """
    Ensure the save_path exists and has write access, creating it (and any intermediate directories) if needed
    :param save_path: full path to save directory
    :type save_path: str
    """
    if not os.path.exists(save_path):
        log.warning(f'{save_path} does not exist. will attempt to create.')
        try:
            os.makedirs(save_path)
            log.info(f'created path: {save_path}')
        except:
            log.error(f'unable to create path: {save_path}')
            exit(1)
        log.info(f'created path: {save_path}')
    if not os.access(save_path, os.W_OK):
        log.error(f'insufficient permissions to write to save path `{save_path}`. Exiting.')
        exit(1)
    log.info(f'confirmed write access to save path: {save_path}')


def get_env_vars(alt_vars: dict) -> dict:
    """
    Get environment variables from .env file and/or dict defined in main.

    Any variable defined in the dict passed in as alt_vars will override the
    corresponding variable in the .env file.

    :param alt_vars: dict of variables to override .env file variables
           (optional, initialized as empty dict)
    """
    env_vars=_get_dotenv_vars()
    print(f"get_env_vars(): env_vars: {env_vars}")

    # let alt_vars override env_vars
    return {'domain': alt_vars.get('domain') if alt_vars.get('domain') else env_vars['domain'],
            'api_key': alt_vars.get('api_key') if alt_vars.get('api_key') else env_vars['api_key'],
            'secret_api_key': alt_vars.get('secret_api_key') if alt_vars.get('secret_api_key') else
            env_vars['secret_api_key'],
            'save_path': alt_vars.get('save_path') if alt_vars.get('save_path') else
            env_vars['save_path'],
            'log_file': alt_vars.get('log_file') if alt_vars.get('log_file') else
            env_vars.get('log_file') if env_vars.get('log_file') else
            os.path.join('/var/log/' if is_nix_os() else os.getcwd(), 'porkbun_ssl_fetch.log')}


def main():
    import sys

    # if you've specified these vars in .env already, you may completely ignore this dict. this is only included
    # for users who do not want to use a separate file.
    # NOTE: any value specified here in this dict will take precedence over one defined in .env file
    alt_vars={
        'domain': None,
        'api_key': None,
        'secret_api_key': None,
        'save_path': None,
        'log_file': None
    }

    # change path to your .env file if not in the same directory as this python file
    env_vars=get_env_vars(alt_vars)

    # get the log file path from the environment variables, using current working directory as default path
    log_file=setup_log_file(env_vars)

    # if '--debug' passed as argument, change log level to debug
    if '--debug' in sys.argv or '-d' in sys.argv or env_vars.get('LOG_LEVEL') == 'DEBUG':
        log.basicConfig(filename=log_file, format='%(asctime)s - %(levelname)s - %(message)s', level=log.DEBUG,
            encoding='utf-8')
    else:
        log.basicConfig(filename=log_file, format='%(asctime)s - %(levelname)s - %(message)s', level=log.INFO,
            encoding='utf-8')

    # call the function to fetch ssl certs
    fetch_ssl_certs(env_vars)


if __name__ == "__main__":
    main()
