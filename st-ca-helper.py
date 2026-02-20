#!/usr/bin/env python3
import base64
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


class KerberosAuthentication:

    def __init__(self, logger, keytab_path="/etc/krb5.keytab"):
        """
        Инициализация экземпляра.

        :param logger: объект логера для записи событий
        :param keytab_path: путь к keytab‑файлу (по умолчанию /etc/krb5.keytab)
        """
        self.logger = logger
        self.keytab_path = keytab_path

    def get_host_token(self, host_name, service_name):
        """
        Получает GSSAPI‑токен для аутентификации на службе.

        :param host_name: имя хоста
        :param service_name: имя целевой службы
        :return: байтовая строка токена GSSAPI
        """
        self.logger.info(f"Получения токена для аутентификации")
        try:

            upn, realm = self.parse_host_name(host_name)

            client_principal_name = f"{upn}@{realm}"
            target_principal_name = f"HTTP/{service_name}@{realm}"

            self.logger.info(f"Клиентский principal: {client_principal_name}")
            self.logger.info(f"Целевой principal: {target_principal_name}")

            kinit_cmd = [
                "kinit",
                "-k",
                "-t", self.keytab_path,
                client_principal_name
            ]

            result = subprocess.run(
                kinit_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return ""

            client_principal = gssapi.Name(
                client_principal_name,
                gssapi.NameType.kerberos_principal
            )

            target_principal = gssapi.Name(
                target_principal_name,
                gssapi.NameType.kerberos_principal
            )

            store = {'keytab': self.keytab_path}

            creds = gssapi.Credentials(
                name=client_principal,
                store=store,
                usage='initiate'
            )
            ctx = gssapi.SecurityContext(
                name=target_principal,
                creds=creds,
                usage="initiate"
            )

            token = ctx.step()

            self.logger.info("GSSAPI токен успешно получен")
            return base64.b64encode(token).decode("utf-8")
        except Exception as e:
            self.logger.error(f"Ошибка получения токена {e}")
            return ''

    def parse_host_name(self, host_name):
        """
        Формирует UPN для компьютера в домене и извлекает realm.

        :param host_name: строка с именем хоста (может содержать домен/сервис)

        :return: UPN в формате 'HOSTNAME$' (например, 'CLIENT1$')
        """

        realm = ''

        if '@' in host_name:
            parts = host_name.split('@', 1)
            host_name = parts[0]
            realm = parts[1].strip()
        if '/' in host_name:
            host_name = host_name.split('/')[1]

        short_hostname = host_name.split('.')[0]
        computer_account = f"{short_hostname.upper()}$"

        return computer_account, realm

    def get_user_token(self, user_name, service_name):

        realm = "TEST.CA"
        tmp_script = f"/tmp/tmp_get_user_key.py"
        txt_script = f'''#!/usr/bin/env python3
        import base64
        import gssapi
        import pwd
        import sys
        user_info = pwd.getpwnam("{user_name}")
        uid = user_info.pw_uid
        keyring_cache = f"KEYRING:persistent:{{uid}}"
        service_principal = f"HTTP/{service_name}@{realm}"
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


class SafeTechApi:
    def __init__(self, ca_url, logger):
        self.ca_url = ca_url
        self.logger = logger
        self.api_endpoint = {
            'request_certificate': '/ca-core/api/v1/api-client/certs/issue-pem',
            'get_templates': '',
        }

    def request_certificate(self, encoded_token, request_data):
        """
        Отправляет запрос на получение сертификата в Центр сертификации.

        :param encoded_token: Base64‑закодированный токен
        :param request_data: словарь с данными запроса
        :return: объект Response от requests или None при ошибке
        :raises: ValueError при некорректных входных данных
        """
        self.logger.info('Request certificate')
        response = ''
        service_url = self.ca_url + self.api_endpoint['request_certificate']

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Negotiate {encoded_token}"
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

        parsed_url = urlparse(self.ca_url)
        service_hostname = parsed_url.hostname
        self.logger.debug(f"Service URL: {service_hostname}")

        token = self.get_token(req_principal, service_hostname)

        template_name = os.getenv('CERTMONGER_TEMPLATE_NAME', '')

        data = {
            'template': template_name,
            'csr': self.clean_csr(csr)
        }
        response = self.api_helper.request_certificate(token, data)
        self.logger.info(f"response status code {response.status_code}")


    def get_token(self, principal, service_hostname):
        """Получает токен Kerberos для principal."""
        self.logger.info("Get Kerberos token.")
        kerberos_authentication = KerberosAuthentication(self.logger)
        if principal.startswith('host/'):
            auth_header = kerberos_authentication.get_host_token(principal, service_hostname)
        else:
            auth_header = kerberos_authentication.get_user_token(principal, principal)
        return auth_header

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

    for key, value in os.environ.items():
        if 'CERTMONGER' in key:
            logger.debug(f"Environment: {key}={value}")

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
