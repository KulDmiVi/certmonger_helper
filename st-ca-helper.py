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

    def principal_auth(self, principal, service_principal, is_host):
        """Получает токен Kerberos для principal."""
        self.logger.info("Get Kerberos token.")
        try:

            if is_host:
                token = self.get_host_token(principal, service_principal)
            else:
                token = self.get_user_token(principal, service_principal)
            return token
        except Exception as e:
            self.logger.error("Ошибка при получении токена")

    def get_host_token(self, principal, service_principal):
        """
        Получает GSSAPI‑токен для аутентификации сервисе.

        :param principal_name: имя хоста
        :param service_principal_name: имя сервиса
        :return: байтовая строка токена GSSAPI
        """
        self.logger.info(f"Получения токена для аутентификации")
        try:
            tgt_status = self.set_tgt(principal)
            client_principal = gssapi.Name(
                principal,
                gssapi.NameType.kerberos_principal
            )

            service_principal_name = gssapi.Name(
                service_principal,
                gssapi.NameType.kerberos_principal
            )

            store = {'keytab': self.keytab_path}

            creds = gssapi.Credentials(
                name=client_principal,
                store=store,
                usage='initiate'
            )
            ctx = gssapi.SecurityContext(
                name=service_principal_name,
                creds=creds,
                usage="initiate"
            )

            token = ctx.step()

            self.logger.info("GSSAPI токен успешно получен")
            return base64.b64encode(token).decode("utf-8")
        except Exception as e:
            self.logger.error(f"Ошибка получения токена компьютера {e}")
            return ''

    def get_user_token(self, principal, service_principal):
        try:
            tmp_script_path = f"/tmp/tmp_get_user_key.py"
            txt_script = f'''#!/usr/bin/env python3
            import base64
            import gssapi
            import pwd
            import sys
            user_info = pwd.getpwnam("{principal}")
            uid = user_info.pw_uid
            keyring_cache = f"KEYRING:persistent:{{uid}}"
     
            target_principal_name = gssapi.Name({service_principal}, gssapi.NameType.kerberos_principal)
            creds = gssapi.Credentials(usage="initiate")
            ctx = gssapi.SecurityContext(name=target_principal_name, creds=creds, usage="initiate")
            token = ctx.step()
            encode_token = base64.b64encode(token).decode("utf-8")
            
            print(encode_token)
            sys.exit(0)
            '''
            with open(tmp_script_path, 'w') as f:
                f.write(txt_script)

            os.chmod(tmp_script_path, 0o755)

            cmd = ['su', '-', principal, '-c', f'python3 {tmp_script_path}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            token = result.stdout.replace("\n", "")
            return token
        except Exception as e:
            self.logger.error("Ошибка при получения токена пользователя")

    def set_tgt(self, principal_name):
        kinit_cmd = [
            "kinit",
            "-k",
            "-t", self.keytab_path,
            principal_name
        ]

        result = subprocess.run(
            kinit_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            self.logger.error("TGT not aviable")
            return False
        else:
            self.logger.error("TGT для {host_principal_name} успешно получен")
            return True


class SafeTechApi:
    def __init__(self, ca_url, logger):
        self.ca_url = ca_url
        self.logger = logger
        self.api_endpoint = {
            'request_certificate': '/ca-core/api/v1/api-client/certs/issue-pem',
            'download_certificate': '/ca-core/api/v1/api-client/certs/download/',
            'get_templates': '',
        }

    def request_certificate(self, request_data, encoded_token):
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

    def download_certificate(self, request_id, encoded_token):

        service_url = self.ca_url + self.api_endpoint['download_certificate'] + request_id
        headers = {
            "Authorization": f"Negotiate {encoded_token}"
        }
        try:
            urllib3.disable_warnings()
            response = requests.get(
                service_url,
                headers=headers,
                verify=False,
                timeout=10
            )
            return response
        except Exception as e:
            self.logger.error(f'download cert request error: {e}')
            return ''


class CertHelper:
    def __init__(self, api_helper, logger, service_url):
        self.api_helper = api_helper
        self.logger = logger
        self.krb_auth = KerberosAuthentication(self.logger)
        self.service_url = service_url

    def handler_submit(self):
        """Обрабатывает операцию SUBMIT — запрос сертификата."""
        try:
            self.logger.info("Обработка запроса на получения сертификата (SUBMIT)")

            env_principal = os.getenv('CERTMONGER_REQ_PRINCIPAL', '')
            principal, realm, is_host = self.parse_principal_name(env_principal)
            parsed_url = urlparse(self.service_url)
            service_hostname = parsed_url.hostname
            service_principal = f"HTTP/{service_hostname}@{realm}"
            token = self.krb_auth.principal_auth(principal, service_principal, is_host)

            template_name = os.getenv('CERTMONGER_CA_PROFILE', '')
            env_csr = os.getenv('CERTMONGER_CSR', '')
            csr = self.clean_csr(env_csr)
            request_data = {
                "templateName": template_name,
                'csr': csr
            }
            response = self.api_helper.request_certificate(request_data, token)
            status_code = response.status_code
            self.logger.info(f"Получен ответ от сервера CA. Статус: {status_code}")

            if status_code >= 400:
                error_details = response.json()
                self.logger.error(f"Детали ошибки от CA: {error_details}")

        except Exception as e:
            error_msg = f"Критическая ошибка при обработке SUBMIT: {type(e).__name__}: {e}"
            self.logger.error(error_msg, exc_info=True)


    def handler_poll(self):
        """Обрабатывает операцию POLL — запрос сертификата."""

        self.logger.info("POLL certificate")

        # request_id = os.getenv('CERTMONGER_CA_COOKIE')
        # self.logger.debug(f"CERTMONGER_CA_COOKIE: {request_id}")
        #
        # if request_id and request_id.startswith('pending_auth_'):
        #     tgt_status = check_tgt_staus()
        #     if not tgt_status:
        #         # проверим наличие тикета через час
        #         sys.exit(5)
        #     else:
        #         # запрашиваем сертификат
        #         csr = os.getenv('CERTMONGER_CSR')
        #         template_name = os.getenv('CERTMONGER_CA_PROFILE')
        #         data = {
        #             'template': template_name,
        #             'csr': self.clean_csr(csr)
        #         }
        #         response = self.api_helper.request_certificate(data)
        #
        # response = self.api_helper.download_certificate(request_id)
        # self.logger.info(f"response status code {response.status_code}")

    def handler_identify(self):
        """Обработка операции IDENTIFY — возвращает базовую информацию о помощнике."""
        self.logger.info("=== STARTING IDENTIFY OPERATION ===")
        print(f"desc=Custom certificate helper for {self.service_url}\nurl={self.service_url}")
        sys.exit(0)

    def handler_get_new_request_requirements(self):
        """Возвращает требования для нового запроса сертификата."""
        self.logger.info("=== STARTING GET_NEW_REQUEST_REQUIREMENTS OPERATION ===")
        print("templateName=required,csr=required")
        sys.exit(0)

    def handler_get_renew_request_requirements(self):
        """Возвращает требования для продления сертификата."""
        self.logger.info("=== STARTING GET_RENEW_REQUEST_REQUIREMENTS ===")
        requirements = "existing_cert=required,new_csr=optional"
        print(requirements)

    def handler_get_supported_templates(self):
        """Возвращает список поддерживаемых шаблонов сертификатов."""
        self.logger.info("===GET_SUPPORTED_TEMPLATES===")
        templates = ["SmartCard Logon", "Server", "User", "CodeSigning"]
        for template in templates:
            print(template)
        sys.exit(0)

    def handler_get_default_template(self):
        """Возвращает шаблон сертификата по умолчанию."""
        self.logger.info("=== STARTING GET_DEFAULT_TEMPLATE ===")
        default_template = "Server"
        print(default_template)
        sys.exit(0)

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

    def parse_principal_name(self, principal):
        """
        Формирует имя и извлекает realm.

        :param host_name: строка с именем хоста (может содержать домен/сервис)

        :return: UPN в формате 'HOSTNAME$' (например, 'CLIENT1$')
        """
        try:
            realm = ''
            principal_name = ''
            is_host = False
            if '@' in principal:
                parts = principal.split('@', 1)
                principal_name = parts[0]
                realm = parts[1].strip()
            if 'host' in principal:
                host_name = principal_name.split('/')[1]
                short_hostname = host_name.split('.')[0]
                principal_name = f"{short_hostname.upper()}$"
                is_host = True

            self.logger.debug(f"Principal: {principal_name}, realm: {realm}")
            return principal_name, realm, is_host
        except Exception as e:
            self.logger.error(f"Error parse principal name: {e}")


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
    cert_helper = CertHelper(safetech_api, logger, ca_url)

    operation = os.getenv('CERTMONGER_OPERATION', 'SUBMIT')

    if operation == 'SUBMIT':
        cert_helper.handler_submit()
    elif operation == 'POLL':
        cert_helper.handler_poll()
    elif operation == 'IDENTIFY':
        cert_helper.handler_identify()
    elif operation == 'GET-NEW-REQUEST-REQUIREMENTS':
        cert_helper.handler_get_new_request_requirements()
    elif operation == 'GET-RENEW-REQUEST-REQUIREMENTS':
        cert_helper.handler_get_renew_request_requirements()
    elif operation == 'GET-SUPPORTED-TEMPLATES':
        cert_helper.handler_get_supported_templates()
    elif operation == 'GET-DEFAULT-TEMPLATE':
        cert_helper.handler_get_default_template()
    else:
        logger.debug(f"Unsupported operation: {operation}")
        sys.exit(6)


if __name__ == "__main__":
    main()
