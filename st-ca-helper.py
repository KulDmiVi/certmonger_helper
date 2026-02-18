#!/usr/bin/env python3

import os
import sys
import gssapi
import subprocess
import requests
import logging
import urllib3
from urllib.parse import urlparse

CONF_PATH = "/usr/share/certmonger/helper/helper.conf"


def read_conf():
    """Чтение конфигурационного файла"""

    ca_url = "https://127.0.0.0"
    log_level = "info"
    log_path = "ca_helper.log"
    try:
        with open(CONF_PATH, 'r') as f:
            for line in f:
                if line.startswith('CA_URL='):
                    ca_url = line.split('=', 1)[1].strip()
                elif line.startswith('LOG_LEVEL='):
                    log_level = line.split('=', 1)[1].strip()
                elif line.startswith('LOG_PATH='):
                    log_path = line.split('=', 1)[1].strip()
    except Exception as e:
        print(f"Error reading config: {e}", file=sys.stderr)
    return ca_url, log_level, log_path


def get_logger(log_level, log_path):
    """Настройка логирования """
    if log_level == "DEBUG":
        l_level = logging.DEBUG
    elif log_level == "ERROR":
        l_level = logging.ERROR
    else:
        l_level = logging.INFO

    logging.basicConfig(
        level=l_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger()
    return logger


class SafeTechApi:
    def __init__(self, ca_url, logger):
        self.ca_url = ca_url
        self.logger = logger
        self.api_endpoint = {
            'request_certificate': '/ca-core/api/v1/api-client/certs/issue-pem',
            'get_templates': '',
        }

    def request_certificate(self, encode_token, request_data):
        """Запрос сертификата в ЦC"""
        self.logger.info('Request certificate')
        response = ''
        service_url = self.ca_url + self.api_endpoint['request_certificate']

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Negotiate {encode_token}"
        }

        try:
            urllib3.disable_warnings()
            response = requests.post(
                service_url,
                json=request_data,
                headers=headers,
                verify=False,
                timeout=10
            )
        except Exception as e:
            self.logger.error(f'Get cert request error: {e}')
        return response


class CertHelper:
    def __init__(self, api_helper, logger):
        self.api_helper = api_helper
        self.ca_url = api_helper.ca_url
        self.logger = logger

    def handler_submit(self):
        """Обрабатывает операцию SUBMIT — запрос сертификата."""

        self.logger.info("Request certificate")

        csr = os.getenv('CERTMONGER_CSR', '')
        self.logger.debug(f"Request csr: {csr}")

        req_principal = os.getenv('CERTMONGER_REQ_PRINCIPAL', '')
        self.logger.debug(f"Request principal: {req_principal}")

        parsed = urlparse(self.ca_url)
        service_hostname = parsed.hostname
        self.logger.debug(f"Service URL: {service_hostname}")

        token = self.get_token(req_principal, service_hostname)
        self.logger.debug(f"Authorization token: {token}")

    def get_token(self, principal, service_hostname):
        """Получает токен Kerberos для principal."""
        self.logger.info("Get Kerberos token.")

        if principal.startswith('host/'):
            auth_header = self.get_host_token(principal, service_hostname)
        else:
            auth_header = self.get_user_token(principal, principal)

        return auth_header

    def get_computer_account(self, principal):
        """Получение имени компьютера в домене"""
        domain_part = ''
        if '@' in principal:
            service_part = principal.split('@')[0]
            domain_part = principal.split('@')[1]
        else:
            service_part = principal

        if '/' in service_part:
            hostname_with_domain = service_part.split('/')[1]
        else:
            hostname_with_domain = service_part

        short_hostname = hostname_with_domain.split('.')[0]
        computer_account = f"{short_hostname.upper()}$"

        return computer_account, domain_part

    def get_host_token(self, principal, service_hostname):
        """Получения токена для хоста."""
        self.logger.info("Get host token")
        try:
            keytab_path = "/etc/krb5.keytab"
            computer_account, domain_part = self.get_computer_account(principal)
            kinit_cmd = ["kinit", "-k", "-t", f"{keytab_path}", f"{computer_account}@{domain_part}"]
            result = subprocess.run(kinit_cmd,
                                    capture_output=True,
                                    text=True,
                                    timeout=10
                                    )
            self.logger.debug(f"KINIT RESULT: {result}")
            principal_name = gssapi.Name(computer_account, gssapi.NameType.kerberos_principal)
            target_name = gssapi.Name(service_hostname, gssapi.NameType.kerberos_principal)
            self.logger.debug(f"PRINCIPAL NAME {principal_name}. TARGET NAME: {target_name}")
            store = {'keytab': keytab_path}
            creds = gssapi.Credentials(
                name=principal_name,
                store=store,
                usage='initiate'
            )

            ctx = gssapi.SecurityContext(name=target_name, creds=creds, usage="initiate")
            token = ctx.step()
            self.logger.debug(f"HOST TOKEN: {token}")
        except Exception as e:
            self.logger.debug(f"get host token exception {e}")
        return token

    def get_user_token(self, user_name, service_hostname):
        """Получения токена пользователя"""
        self.logger.info("get user token")
        realm = "CLIENT1@TEST.CA"
        tmp_script = f"/tmp/tmp_get_user_key.py"
        txt_script = f'''#!/usr/bin/env python3
import base64
import gssapi
import pwd
import sys
user_info = pwd.getpwnam("{user_name}")
uid = user_info.pw_uid
keyring_cache = f"KEYRING:persistent:{{uid}}"
service_principal = f"HTTP/{service_hostname}@{realm}"
target_name = gssapi.Name(service_principal, gssapi.NameType.kerberos_principal)
creds = gssapi.Credentials(usage="initiate")
ctx = gssapi.SecurityContext(name=target_name, creds=creds, usage="initiate")
token = ctx.step()
encode_token = base64.b64encode(token).decode("utf-8")
print(encode_token)
sys.exit(0)
'''
        with open(tmp_script, 'w') as f:
            f.write(txt_script)

        os.chmod(tmp_script, 0o755)

        cmd = ['su', '-', user_name, '-c', f'python3 {tmp_script}']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        key = result.stdout.replace("\n", "")
        return key

    def clean_csr(self, csr_text):
        """Подготавливаем данные для запроса сертификата"""
        self.logger.info('prepare request data')
        csr_clean = csr_text.replace('-----BEGIN CERTIFICATE REQUEST-----', '') \
            .replace('-----END CERTIFICATE REQUEST-----', '') \
            .replace('-----BEGIN NEW CERTIFICATE REQUEST-----', '') \
            .replace('-----END NEW CERTIFICATE REQUEST-----', '') \
            .strip()

        csr_clean = ''.join(csr_clean.split())
        return csr_clean


def main():
    """
    Основная точка входа в программу.
    Читает конфигурацию, настраивает логирование, определяет операцию и выполняет соответствующее действие.
    """

    ca_url, log_level, log_path = read_conf()

    logger = get_logger(log_level, log_path)

    logger.info("=== CERTMONGER HELPER STARTED ===")

    safetech_api = SafeTechApi(ca_url, logger)
    cert_helper = CertHelper(safetech_api, logger)

    operation = os.getenv('CERTMONGER_OPERATION', 'SUBMIT')

    if operation == 'SUBMIT':
        cert_helper.handler_submit()
    else:
        logger.debug(f"Unsupported operation: {operation}")
        sys.exit(6)


if __name__ == "__main__":
    main()
