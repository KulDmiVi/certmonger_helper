#!/usr/bin/env python3

import os
import sys
import base64
import gssapi
import pwd
import json
import subprocess
import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
import logging
import urllib3
from urllib.parse import urlparse

CONF_PATH="/usr/share/certmonger/helper/helper.conf"

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

class SafeTechApi():
    def __init__(self, ca_url, logger):
        self.ca_url = ca_url
        self.logger = logger
        self.api_endpoint = {
            'request_certificate': '/ca-core/api/v1/api-client/certs/issue-pem',
            'get_templates': '',
        }
    
    def request_serticate(self, encode_token, request_data):
        """Запрос сертификата в ЦC"""
        self.logger.info('Request certificate')

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
    

class CertHelper():
    def __init__(self, api_helper, logger):
        self.api_helper = api_helper
        self.ca_url = api_helper.ca_url
        self.logger = logger

    def handler_submit(self):
        """Обрабатывает операцию SUBMIT — запрос сертификата."""
        
        self.logger.info("Request sertificate")
        
        csr = os.getenv('CERTMONGER_CSR', '')
        self.logger.debug(f"Request csr: {csr}")

        req_principal = os.getenv('CERTMONGER_REQ_PRINCIPAL', '')
        self.logger.debug(f"Request principal: {req_principal}")
        
        parsed = urlparse(self.ca_url)
        service_hostname = parsed.hostname
        self.logger.debug(f"Service URL: {service_hostname}")
        
        token = self.get_token(req_principal, service_hostname)

    def get_token(self, principal, service_hostname):
        """Получает токен Kerberos для principal."""
        self.logger.info("Get Kerberos token.")
        auth_header = self.get_host_token(principal, service_hostname)
        #if principal.startswith('host/'):
        #    auth_header = self.get_host_token(principal, service_hostname)
        #else:
        #    auth_header = self.get_user_token(principal, principal)


    def get_host_token(self, principal, service_hostname):
        """Получения токена для хоста."""
        self.logger.info("Get host token")
        keytab_path = "/etc/krb5.keytab"
        principal = "CLIENT1$@TEST.CA"
        #env = os.environ.copy()
        #env['KRB5_CONFIG'] = '/etc/krb5.conf'
        #env['KRB5CCNAME'] = '/tmp/krb5cc_python'
        #env["KRB5_TRACE"] = "/tmp/krb.log"
        #env["KRB5_KTNAME"] = "/etc/krb5.keytab"
        self.logger.info(f"set env")        
        kinit_cmd = ["kinit", "-", "-t", f"{keytab_path}", f"{principal}"]
        result = subprocess.run(kinit_cmd, 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        self.logger.info(f"RESULT: {result}")
        principal_name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        self.logger.info(f"PRINCIPAL: {principal_name}")
        #realm = principal.split('@')[1]
        #target_service = "HTTP/{service_hostname}@{realm}"
        #self.logger.info(f"ticket: {result}")

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
        """Подгатавливаем данные для запроса сертификата"""
        logger.info('prepare request data')
        csr_clean = csr_text.replace('-----BEGIN CERTIFICATE REQUEST-----', '') \
                                 .replace('-----END CERTIFICATE REQUEST-----', '') \
                                 .replace('-----BEGIN NEW CERTIFICATE REQUEST-----', '') \
                                 .replace('-----END NEW CERTIFICATE REQUEST-----', '') \
                                 .strip()

        csr_clean = ''.join(csr_clean.split())
        return csr_clean

def main():
    ca_url, log_level, log_path = read_conf()
    logger = get_logger(log_level, log_path)
    logger.debug("=== CERTMONGER HELPER STARTED ===")
    
    safetech_api = SafeTechApi(ca_url, logger)
    cert_helper = CertHelper(safetech_api, logger)
    
    operation = os.getenv('CERTMONGER_OPERATION', 'SUBMIT')
    
    if operation == 'SUBMIT':
        cert_helper.handler_submit()
    else:
        debug_log(f"Unsupported operation: {operation}")
        sys.exit(6)

    #user_name = "ca-user"
    
    #service_hostname = "st-ca1.test.ca"
    
    #for key, value in os.environ.items():
    #    if 'CERTMONGER' in key:
    #        logger.info(f"Environment: {key}={value}")

    #csr_text = os.getenv('CERTMONGER_CSR', '')
    #cert_helper = CertHelper()
    #encode_token = cert_helper.get_user_token(user_name, service_hostname) 
    #csr_data = cert_helper.prepare_csr_data(csr_text)
    #response = cert_helper.request_serticate(encode_token, csr_data)
    #if cert_data:
    #    logger.info("Certificate received immediately, outputting")
    #    print(cert_data, end='')
    #    sys.exit(0)
    #else:
    #    logger.info(f"Certificate not ready, returning request_id: {request_id}")
    #    print('30')
    #    print(request_id)
    #    sys.exit(5)

    # cmd = ['sudo', '-u', user_name, 'KRB5CCNAME=' + keyring_cache, 'klist']
    #cmd = ['su', '-', user_name, '-c', f'KRB5CCNAME=KEYRING:persistent:{uid} klist']
    #print(cmd)
    #result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    #print(result)
    #print('start')
    #urllib3.disable_warnings()
    #kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
    #print('get tickect')
    #response = requests.get(
#	ca_info_url, 
#	auth=kerberos_auth, 
#	verify=False,
#	allow_redirects=False,
#	headers={"Accept": "application/json"}
#    )
#    print(response.headers)
#    operation = os.getenv('CERTMONGER_OPERATION', 'SUBMIT')
#    for key, value in os.environ.items():
#        logger.info(f"Environment: {key}={value}")
#        if 'CERTMONGER' in key:
#            logger.info(f"Environment: {key}={value}")
#    helper = CertHelper()
#    logger.info(f"Получена операция: {operation}")
#    try:
#        if operation == "IDENTIFY":
#            helper.handler_identify()
#        elif operation == "FETCH-ROOTS":
#            helper.handler_fetch_roots()
#        elif operation == "GET-SUPPORTED-TEMPLATES":
#            helper.handler_get_supported_templates()
#        elif operation == "GET-DEFAULT-TEMPLATES":
#            helper.handler_get_default_templates()
#        elif operation == "GET-NEW-REQUEST-REQUIREMENTS":
#            helper.handler_get_new_request_requirements()
#        elif operation == "SUBMIT":
#            helper.handler_submit()
#        elif operation == "POLL":
#            helper.handler_poll()
#        else:
#            err_msg = "Неизвестная операция"
#            logger.error(err_msg)
#            print(err_msg)
#    except Exception as e:
#        logger.exception(f"Произошла ошибка при выполнении операции {operation}: {str(e)}")
#        print(f"Ошибка: {str(e)}")


if __name__ == "__main__":
    main()
