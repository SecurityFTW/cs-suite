import json
import subprocess
from subprocess import STDOUT
import time
import webbrowser
import os
import glob
from modules import logger

log = logger.get()
account_name = subprocess.check_output(['az account list --all --query [*].[name,isDefault] --output tsv | grep True | cut -f1'], shell=True).strip()
timestmp = time.strftime("%Y%m%d-%H%M%S")

def json_to_html(file, new_file):
    with open(new_file, 'w') as f:
        with open('./tools/prowler/template1.txt', 'r') as g:
            for line in g:
                f.write(line)
        with open(file, 'r') as json_data:
             for line in json_data:
                 line = str(line)
                 final = json.loads(line)
                 f.write('<div class="col-xs-6 col-sm-3 col-md-3 item">\n')
                 f.write('<div class="thumbnail">\n')
                 f.write('<div class="caption">\n')
                 flag = 0
                 for g in final['data']:
                     if g['type'] == 'WARNING':
                         flag = 1
                 if flag == 0:
                     f.write('<div class="grid" style="background-color: green;">')
                 else:
                     f.write('<div class="grid" style="background-color: red;">')
                 f.write('<h5>%s</h5>\n' %(final['check']))
                 f.write('</div>')
                 for k in final['data']:
                     if k['type'] == 'WARNING':
                          f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['data']))
                     else:
                          f.write('<p>%s<p>\n' % (k['data']))
                 f.write('</div>')
                 f.write('</div>')
                 f.write('</div>')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line)

def merge_json():
    with open("reports/AZURE/%s/%s/final_report/final.json" %(account_name, timestmp), "w") as f:
        for file in glob.glob("reports/AZURE/%s/%s/*.json" % (account_name, timestmp)):
            with open(file, "r") as infile:
                for line in infile:
                    f.write(line)


def no_guest_user():
    """ The response is empty,need to dig in further """
    guest_user_list = subprocess.check_output(['az ad user list --query "[?additionalProperties.userType==\'Guest\']"'], shell=True)
    result = {}
    result['check'] = 'NO_GUEST_USER'
    with open('azure_output.json', 'w') as f:
        f.write(guest_user_list)

def custom_owner_role():
    """ The response is huge need to break down and analyse """
    definition_list = subprocess.check_output(['az role definition list'], shell=True)
    print definition_list

def automatic_provising_agent():
    print "2.2: Checking for Automatic Provising Agent\n\n"
    agent_provising = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'| jq \'.properties.logCollection\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'AUTOMATIC_PROVISING_AGENT'
    data = []
    j_res = {}
    j_res['check_no'] = '2.2'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'management'
    if agent_provising == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Automatic provisioning of monitoring agent is OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Automatic provisioning of monitoring agent is ON'
    data.append(j_res)
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def system_update():
    print "2.3: Checking if System Updates are enabled\n\n"
    system_update = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'| jq \'.properties.recommendations.patch\' | tr -d \'"\' '], shell=True).strip()
    result = {}
    result['check'] = 'SYSTEM_UPDATES'
    data = []
    j_res = {}
    j_res['check_no'] = '2.3'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'management'
    if system_update == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'System updates are turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'System updates are turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def security_configuration():
    print "2.4: Checking if Security Configurations are enabled\n\n"
    sec_config = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.baseline\' | tr -d \'"\' '], shell=True).strip()
    result = {}
    result['check'] = 'SECURITY_CONFIGURATIONS'
    data = []
    j_res = {}
    j_res['check_no'] = '2.4'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'security'
    if sec_config == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Security Configurations are turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Security Configurations are turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def endpoint_protection():
    print "2.5: Checking if Endpoint protection is enabled\n\n"
    end_protect = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.antimalware\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'ENDPOINT_PROTECTION'
    data = []
    j_res = {}
    j_res['check_no'] = '2.5'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'security'
    if end_protect == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Endpoint Protection are turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Endpoint Protection are turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def disk_encryption():
    print "2.6: Checking if Disk Encryption is set On\n\n"
    encrypt_disk = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.diskEncryption\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'DISK_ENCRYPTION'
    data = []
    j_res = {}
    j_res['check_no'] = '2.6'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'storage'
    if encrypt_disk == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Disk Encryption is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Disk Encryption is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def network_security():
    print "2.7: Checking if Network security groups recommendations is enabled\n\n"
    nsg = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.nsgs\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'SECURITY_GROUPS'
    data = []
    j_res = {}
    j_res['check_no'] = '2.7'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'security'
    if nsg == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Network security groups is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Network security groups is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def web_app_firewall():
    print "2.8: Checking if Web Application Firewall is Enabled\n\n"
    waf = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.waf\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'WEB_APPLICATION_FIREWALL'
    data = []
    j_res = {}
    j_res['check_no'] = '2.8'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'security'
    if waf == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Web application firewall is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Web application firewall is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def next_gen_firewall():
    print "2.9: Checking if Next generation firewall recommendations are Enabled\n\n"
    ngfw = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.ngfw\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'NEXT_GENERATION_FIREWALL'
    data = []
    j_res = {}
    j_res['check_no'] = '2.9'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'security'
    if ngfw == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Next generation firewall is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Next generation firewall is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def vuln_assessment():
    print "2.10: Checking if Vulnerability assessment recommendations are Enabled\n\n"
    va = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.vulnerabilityAssessment\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'VULNERABILITY_ASSESSMENT'
    data = []
    j_res = {}
    j_res['check_no'] = '2.10'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'security'
    if va == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Vulnerability assessment firewall is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Vulnerability assessment firewall is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def storage_encyption():
    print "2.11: Checking if Storage Encryption is Enabled\n\n"
    encrypt_disk = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.storageEncryption\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'STORAGE_ENCRYPTION'
    data = []
    j_res = {}
    j_res['check_no'] = '2.11'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'storage'
    if encrypt_disk == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Storage encryption is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Storage encryption is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def jit_network_access():
    print "2.12: Checking if JIT Network Access is set to ON\n\n"
    jit_net_access = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.jitNetworkAccess\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'JIT_NETWORK_ACCESS'
    data = []
    j_res = {}
    j_res['check_no'] = '2.12'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'network'
    if jit_net_access == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Just in Time Network Access is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Just in Time Network Access is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def adaptive_application_control():
    print "2.13: Checking if Adaptive Application Controls is set to ON\n\n"
    app_control = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.appWhitelisting\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'ADAPTIVE_APPLICATION_CONTROL'
    data = []
    j_res = {}
    j_res['check_no'] = '2.13'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'security'
    if app_control == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Adaptive Application Control is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Adaptive Application Control is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_auditing():
    print "2.14: Checking if SQL auditing & Threat detection is set to ON\n\n"
    sql_detect = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.sqlAuditing\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'SQL_AUDITING_&_THREAT_DETECTION'
    data = []
    j_res = {}
    j_res['check_no'] = '2.14'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'database'
    if sql_detect == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'SQL AUDITING AND THREAT DETECTION is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'SQL AUDITING AND THREAT DETECTION is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_encryption():
    print "2.15: Checking if SQL Encryption is set to ON\n\n"
    encrypt_sql = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.recommendations.sqlTde\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'SQL_ENCRYPTION'
    data = []
    j_res = {}
    j_res['check_no'] = '2.15'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'database'
    if encrypt_sql == "Off":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'SQL encryption is turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'SQL encryption is turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def security_email_set():
    print "2.16: Checking if Security contact emails is SET\n\n"
    email_config = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.securityContactConfiguration.securityContactEmails\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'SECURITY_CONTACT_EMAIL'
    data = []
    j_res = {}
    j_res['check_no'] = '2.16'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'management'
    if email_config == "[]":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Security Contact Email is NOT SET'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Security Contact Email is SET'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def security_contact_phone():
    print "2.17: Checking if Security contact Phone Number is SET\n\n"
    phone_config = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.securityContactConfiguration.securityContactPhone\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'SECURITY_CONTACT_PHONE'
    data = []
    j_res = {}
    j_res['check_no'] = '2.17'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'management'
    if phone_config == "":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Security Phone Contact  is NOT SET'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Security Phone Contact  is SET'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def email_for_alert():
    print "2.18: Checking if security e-mail alerts are enabled\n\n"
    alert_email = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.securityContactConfiguration.areNotificationsOn\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'SECURITY_EMAIL_ALERTS'
    data = []
    j_res = {}
    j_res['check_no'] = '2.18'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'management'
    if alert_email == "false":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Security email alerts are turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Security email alerts are turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def email_for_subs_owners():
    print "2.19: Checking if security alerts for subscription owners are enabled\n\n"
    email_owner = subprocess.check_output(['az account get-access-token --query "{subscripton:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c \'curl -s -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.Security/policies?api-version=2015-06-01-preview\' | jq \'.|.value[] | select(.name=="default")\'|jq \'.properties.securityContactConfiguration.sendToAdminOn\' | tr -d \'"\''], shell=True).strip()
    result = {}
    result['check'] = 'SECURITY EMAIL ALERTS TO OWNERS'
    data = []
    j_res = {}
    j_res['check_no'] = '2.19'
    j_res['level'] = 'INFO'
    j_res['region'] = 'null'
    j_res['score'] = 'Scored'
    j_res['category'] = 'management'
    if email_owner == "false":
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Security email alerts to subscription owners are turned OFF'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Security email alerts to subscription owners are turned ON'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def secure_transfer():
    print "3.1: Checking if storage accounts have HTTPS only traffic enabled \n\n"
    https_enabled = subprocess.check_output(['az storage account list --query \[*\].\[name,enableHttpsTrafficOnly,primaryLocation\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'SECURE TRANSFER STORAGE ACCOUNT'
    data = []
    for line in https_enabled.splitlines():
        words = line.split()
        j_res = {}
        j_res['check_no'] = '3.1'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['category'] = 'storage'
        j_res['region'] = words[2]
        if words[1] == 'False':
            j_res['type'] = 'WARNING'
            j_res['value'] = 'The storage account %s does not have HTTPS only traffic enabled' % words[0]
        else:
            j_res['type'] = 'PASS'
            j_res['value'] = 'The storage account %s does have HTTPS only traffic enabled' % words[0]
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
        data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/storage_account.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def storage_service_encryption():
    print "3.2: Checking if storage accounts has its associated BLOB service encryption enabled \n\n"
    storage_encryption = subprocess.check_output(['az storage account list --query \[*\].\[name,encryption.services.blob.enabled,primaryLocation\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'STORAGE SERVICE ENCRYPTION BLOB'
    data = []
    for line in storage_encryption.splitlines():
        words = line.split()
        j_res = {}
        j_res['check_no'] = '3.2'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['category'] = 'storage'
        j_res['region'] = words[2]
        if words[1] == 'False':
            j_res['type'] = 'WARNING'
            j_res['value'] = 'The storage account %s does not have its associated BLOB service encryption enabled' % words[0]
        else:
            j_res['type'] = 'PASS'
            j_res['value'] = 'The storage account %s does have its associated BLOB service encryption enabled' % words[0]
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/storage_account.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def access_key_rotation():
    resource_ids = subprocess.check_output(['az storage account list --query [*].[id] --output tsv'], shell=True)
    ids = []
    for resource in resource_ids.splitlines():
        ids.append(resource)

    for id in set(ids):
        time_stmp = subprocess.check_output(['az monitor activity-log list --resource-id %s --query [*].[eventTimestamp,resourceGroup] --output tsv' % id], shell=True)
        if time_stmp:
            print time_stmp.strip()

def encrption_file_service():
    print "3.6: Checking if storage accounts has its associated FILE service encryption enabled \n\n"
    file_encryption = subprocess.check_output(['az storage account list --query \[*\].\[name,encryption.services.file.enabled,primaryLocation\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'FILE_SERVICE_ENCRYPTION'
    data = []
    for line in file_encryption.splitlines():
        words = line.split()
        j_res = {}
        j_res['check_no'] = '3.6'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['category'] = 'storage'
        j_res['region'] = words[2]
        if words[1] == 'False':
            j_res['type'] = 'WARNING'
            j_res['value'] = 'The storage account %s does not have its associated FILE service encryption enabled' % words[0]
        else:
            j_res['type'] = 'PASS'
            j_res['value'] = 'The storage account %s does have its associated FILE service encryption enabled' % words[0]
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
        data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/storage_account.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def log_profile():
    print "5.1: Checking if Log profile exists or not\n\n"
    check_profile = subprocess.check_output(['az monitor log-profiles list --query [*].[id,name]'], shell=True).strip()
    result = {}
    j_res = {}
    data = []
    result['check'] = 'LOG_PPOFILE'
    j_res['check_no'] = '5.1'
    j_res['level'] = 'INFO'
    j_res['score'] = 'Scored'
    j_res['region'] ='null'
    j_res['category'] = 'management'
    if check_profile == '[]':
        j_res['type'] = 'WARNING'
        j_res['value'] = 'There is currently no LOG PROFILE enabled'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'There is LOG PROFILE which exists'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def log_retention():
    print "5.2: Checking the retention policy of the log profile\n\n"
    retention_policy = subprocess.check_output(['az monitor log-profiles list --query [*].retentionPolicy.enabled --output tsv'],shell=True).strip()
    result = {}
    j_res = {}
    data = []
    result['check'] = 'LOG_RETENTION_POLICY'
    j_res['check_no'] = '5.2'
    j_res['level'] = 'INFO'
    j_res['score'] = 'Scored'
    j_res['region'] ='null'
    j_res['category'] = 'management'
    if retention_policy in ['false', '']:
        j_res['type'] = 'WARNING'
        j_res['value'] = 'There is currently no RETENTION policy applied to the LOG PROFILE'
    else:
        days = subprocess.check_output(['az monitor log-profiles list --query [*].retentionPolicy.days --output tsv'],shell=True).strip()
        if int(days) < 365:
            j_res['type'] = 'WARNING'
            j_res['value'] = 'The LOG RETENTION policy is currently lesser than 365 days'
        else:
            j_res['type'] = 'PASS'
            j_res['value'] = 'The  LOG RETENTION policy is good'
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def alert_for_create_policy():
    print "5.3: Checking if alert for Create Policy Assignment event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'CREATE_POLICY_ASSIGNMENT'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.3'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Authorization/policyAssignments/write"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Create Policy Assignment event" % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Create Policy Assignment event" % resource_group
            j_res['type'] = 'PASS'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def alert_group_create_network():
    print "5.4: Checking if alert for Create or Update Network Security GROUP event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'CREATE_NETWORK_GROUP'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.4'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Network/networkSecurityGroups/write"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Create or Update Network Security GROUP" % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Create or Update Network Security GROUP" % resource_group
            j_res['type'] = 'PASS'
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
        data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def alert_group_network_delete():
    print "5.5: Checking if alert for Delete Network Security GROUP event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'DELETE_NETWORK_GROUP'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.5'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Network/networkSecurityGroups/delete"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Delete Network Security GROUP" % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Delete Network Security GROUP" % resource_group
            j_res['type'] = 'PASS'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def alert_rule_network_create():
    print "5.6: Checking if alert for Create or Update Network Security GROUP RULE event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'CREATE_NETWORK_RULES'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.6'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Network/securityRules/write"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Create or Update Network Security GROUP RULE" % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Create or Update Security GROUP RULE" % resource_group
            j_res['type'] = 'PASS'
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
        data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def alert_rule_network_delete():
    print "5.7: Checking if alert for Delete Network Security GROUP RULE event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'DELETE_NETWORK_RULES'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.7'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Network/networkSecurityGroups/delete"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Delete Network Security GROUP RULE" % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Delete Network Security GROUP RULE" % resource_group
            j_res['type'] = 'PASS'
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
        data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")



def alert_create_security():
    print "5.8: Checking if alert for Create/Update Security Solution event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'CREATE_SECURITY_SOLUTION'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.8'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Security/securitySolutions/write"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Create/Update Security Solution" % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Create/Update Security Solution" % resource_group
            j_res['type'] = 'PASS'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def alert_delete_security():
    print "5.9: Checking if alert for DELETE Security Solution event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'DELETE_SECURITY_SOLUTION'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.9'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Security/securitySolutions/delete"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for DELETE Security Solution" % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for DELETE Security Solution" % resource_group
            j_res['type'] = 'PASS'
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
        data.append(j_res)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def alert_create_sql_rule():
    print "5.10: Checking if alert for Create or Update SQL Server Firewall Rule event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'CREATE_SQL_FIREWALL_RULE'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.10'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Sql/servers/firewallRules/write"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Create or Update SQL Server Firewall Rule events " % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Create or Update SQL Server Firewall Rule events" % resource_group
            j_res['type'] = 'PASS'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def alert_delete_sql_rule():
    print "5.11: Checking if alert for Delete SQL Server Firewall Rule event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'DELETE_SQL_FIREWALL_RULE'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.11'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Sql/servers/firewallRules/delete"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for Delete SQL Server Firewall Rule events " % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for Delete SQL Server Firewall Rule events" % resource_group
            j_res['type'] = 'PASS'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def alert_update_security_policy():
    print "5.12: Checking if alert for changes in Security Policy event exists\n\n"
    resource_groups = subprocess.check_output(['az monitor activity-log alert list --query \[*\].\[resourceGroup\] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'UPDATE_SECURITY_POLICY'
    data = []
    for resource_group in resource_groups.splitlines():
        j_res = {}
        j_res['check_no'] = '5.12'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'management'
        check = subprocess.check_output(['az monitor activity-log alert list --resource-group %s --query [*].condition | jq \'.|.[].allOf[] | select(.equals | contains("Microsoft.Security/policies/write"))\'' % resource_group ], shell=True).strip()
        if check == "":
            j_res['value'] = "The resource group %s has NO alert for changes in Security Policy events " % resource_group
            j_res['type'] = 'WARNING'
        else:
            j_res['value'] = "The resource group %s has an alert for changes in Security Policy events" % resource_group
            j_res['type'] = 'PASS'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/logging_monitoring.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def rdp_public():
    print "6.1: Checking if any network group allows public access to RDP\n\n"
    network_list = subprocess.check_output([' az network nsg list --query [*].name --output tsv'], shell=True).strip()
    result = {}
    data =[]
    result['check'] = 'PUBLIC_RDP_ACCESS'
    for network_group in network_list.splitlines():
        flag = 0
        lines = subprocess.check_output(['az network nsg list --query "[?name==\'%s\'].[securityRules][][].[access,destinationPortRange,direction,protocol,sourceAddressPrefix]"  --output tsv' %network_group],shell=True).strip()
        for line in lines.splitlines():
            access_type, port, direction, protocol, source = line.split()
            j_res = {}
            j_res['check_no'] = '6.1'
            j_res['level'] = 'INFO'
            j_res['score'] = 'Scored'
            j_res['region'] = 'null'
            j_res['category'] = 'network'
            if port == "3389" and access_type == "Allow" and direction == "Inbound" and source in ['*', '0.0.0.0', 'internet', 'any', '<nw>/0', '/0',] :
                j_res['value'] = "Please check %s network group for RDP public access" % network_group
                j_res['type'] = 'WARNING'
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
                flag = 1
                break
        if flag == 0:
            j_res['value'] = "The network group %s does not allow public RDP access" % network_group
            j_res['type'] = 'PASS'
            j_res['category'] = 'network'
            data.append(j_res)
            log_data = dict()
            log_data = j_res
            log_data["data"] = log_data.pop("value")
            log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/network.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def ssh_public():
    print "6.2: Checking if any network group allows public access to SSH\n\n"
    network_list = subprocess.check_output([' az network nsg list --query [*].name --output tsv'], shell=True).strip()
    result = {}
    data =[]
    result['check'] = 'PUBLIC_SSH_ACCESS'
    for network_group in network_list.splitlines():
        flag = 0
        lines = subprocess.check_output(['az network nsg list --query "[?name==\'%s\'].[securityRules][][].[access,destinationPortRange,direction,protocol,sourceAddressPrefix]"  --output tsv' %network_group],shell=True).strip()
        for line in lines.splitlines():
            access_type, port, direction, protocol, source = line.split()
            j_res = {}
            j_res['check_no'] = '6.2'
            j_res['level'] = 'INFO'
            j_res['score'] = 'Scored'
            j_res['region'] = 'null'
            if port == "22" and access_type == "Allow" and direction == "Inbound" and source in ['*', '0.0.0.0', 'internet', 'any', '<nw>/0', '/0',] :
                j_res['value'] = "Please check %s network group for SSH public access" % network_group
                j_res['type'] = 'WARNING'
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
                flag = 1
                break
        if flag == 0:
            j_res['value'] = "The network group %s does not allow public SSH access" % network_group
            j_res['type'] = 'PASS'
            j_res['category'] = 'network'
            data.append(j_res)
            log_data = dict()
            log_data = j_res
            log_data["data"] = log_data.pop("value")
            log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/network.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def network_watcher():
    print "6.5: Checking if network watcher is enabled\n\n"
    check = subprocess.check_output(['az network watcher list'], shell=True).strip()
    result = {}
    data =[]
    result['check'] = 'NETWORK_WATCHER'
    j_res = {}
    j_res['check_no'] = '6.5'
    j_res['level'] = 'INFO'
    j_res['score'] = 'Scored'
    j_res['region'] = 'null'
    j_res['category'] = 'network'
    if check == '[]':
        j_res['type'] = 'WARNING'
        j_res['value'] = 'Network Watcher is not enabled for your account'
    else:
        j_res['type'] = 'PASS'
        j_res['value'] = 'Network Watcher is enabled for your account'
    data.append(j_res)
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/network.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def vm_agent():
    print "7.1: Checking if virtual agent is enabled on Virtual Machines\n\n"
    lines = subprocess.check_output(['az vm list --query [*].[resourceGroup,name] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'VM_AGENT'
    data = []
    for line in lines.splitlines():
        resource_group, name = line.split()
        check = subprocess.check_output(['az vm show -g %s -n %s --query resources[*].[virtualMachineExtensionType,provisioningState] --output tsv' % (resource_group,name)],shell=True).strip()
        j_res = {}
        j_res['check_no'] = '7.1'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'compute'
        if check == '':
            j_res['type'] = 'WARNING'
            j_res['value'] = 'The VM %s does not have virtual agent enabled' %(name)
        else:
            list = check.split()
            if list[1] == "Succeeded" and list[0] != "":
                j_res['type'] = 'PASS'
                j_res['value'] = 'The VM %s does have virtual agent enabled' % (name)
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/vm.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def vm_os_disk():
    print "7.2: Checking if OS disk encryption is enabled\n\n"
    lines = subprocess.check_output(['az vm list --query [*].[resourceGroup,name] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'VM_OS_DISK_ENCRYPTION'
    data = []
    for line in lines.splitlines():
        resource_group, name = line.split()
        check = subprocess.check_output(['az vm encryption show --resource-group %s --name %s --query osDisk  --output tsv' % (resource_group, name)], shell=True, stderr=subprocess.STDOUT).strip()
        j_res = {}
        j_res['check_no'] = '7.2'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'compute'
        if check == "WARNING: Azure Disk Encryption is not enabled":
            j_res['type'] = 'WARNING'
            j_res['value'] = 'The VM %s does not have OS DISK ENCRYPTION enabled' %(name)
        else:
            j_res['type'] = 'PASS'
            j_res['value'] = 'The VM %s does have OS DISK ENCRYPTION enabled' %(name)
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/vm.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def vm_data_disk():
    print "7.3: Checking if DATA disk encryption is enabled\n\n"
    lines = subprocess.check_output(['az vm list --query [*].[resourceGroup,name] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'VM_DATA_DISK_ENCRYPTION'
    data = []
    for line in lines.splitlines():
        resource_group, name = line.split()
        check = subprocess.check_output(['az vm encryption show --resource-group %s --name %s  --query dataDisk  --output tsv' % (resource_group, name)], shell=True, stderr=subprocess.STDOUT).strip()
        j_res = {}
        j_res['check_no'] = '7.3'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'compute'
        if check == "WARNING: Azure Disk Encryption is not enabled":
            j_res['type'] = 'WARNING'
            j_res['value'] = 'The VM %s does not have DATA DISK ENCRYPTION enabled' %(name)
        else:
            j_res['type'] = 'PASS'
            j_res['value'] = 'The VM %s does have DATA DISK ENCRYPTION enabled' %(name)
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/vm.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def approved_extension():
    print "7.4: Checking if the extensions are approved\n\n"
    lines = subprocess.check_output(['az vm list --query [*].[resourceGroup,name] --output tsv'], shell=True).strip()
    result = {}
    result['check'] = 'APPROVED_EXTENSION'
    extensions = []
    data = []
    j_res = {}
    j_res['check_no'] = '7.4'
    j_res['level'] = 'INFO'
    j_res['score'] = 'Not Scored'
    j_res['region'] = 'null'
    j_res['category'] = 'compute'
    for line in lines.splitlines():
        resource_group, name = line.split()
        check = subprocess.check_output(['az vm extension list --resource-group %s  --vm-name %s --query [*].name --output tsv' % (resource_group,  name)], shell=True).strip()
        if check != '':
            extensions = extensions + check.split()
    if len(extensions) == 0:
        j_res['type'] = "PASS"
        j_res['value'] = 'There are no extensions to evaluate'
    else:
        j_res['type'] = "WARNING"
        j_res['value'] = 'Please manually check for approval for these extensions %s' % list(set(extensions))
    data.append(j_res)
    log_data = dict()
    log_data = j_res
    log_data["data"] = log_data.pop("value")
    log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/vm.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def vault_key():
    print "8.1: Checking if expiry is enabled for vault keys\n\n"
    result = {}
    result['check'] = 'VAULT_KEY_EXPIRY'
    data = []
    j_res = {}
    check_vault_exists = subprocess.check_output(['az keyvault list --query [*].name --output tsv'], shell=True).strip()
    if check_vault_exists == '':
        j_res['type'] = 'PASS'
        j_res['value'] = 'VAULT NOT SET UP FOR THE ACCOUNT'
        j_res['check_no'] = '8.1'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['category'] = 'security'
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for vault in check_vault_exists.splitlines():
            expiry =  subprocess.check_output(['az keyvault key list --vault-name %s --query [*].[kid,attributes.expires] --output tsv' %(vault) ], shell=True).strip()
            for exp in expiry.splitlines():
                key_name , date = exp.split()
                j_res = {}
                j_res['check_no'] = '8.1'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'security'

                if date == 'None':
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'No expiry date set for key : %s' %(key_name)
                elif exp == '':
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'No keys found in vault %s' %(expiry)
                else:
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'Access Denied could not check for expiration in vault %s' %(expiry)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/vault.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def vault_secret():
    print "8.2: Checking if expiry is enabled for vault secret\n\n"
    result = {}
    result['check'] = 'VAULT_SECRET_EXPIRY'
    data = []
    j_res = {}
    check_vault_exists = subprocess.check_output(['az keyvault list --query [*].name --output tsv'], shell=True).strip()
    if check_vault_exists == '':
        j_res['check_no'] = '8.2'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'VAULT NOT SET UP FOR THE ACCOUNT'
        j_res['category'] = 'security'
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for vault in check_vault_exists.splitlines():
            expiry =  subprocess.check_output(['az keyvault secret list --vault-name %s --query [*].[id,attributes.expires] --output tsv' %(vault) ], shell=True).strip()
            for exp in expiry.splitlines():
                key_name , date = exp.split()
                j_res = {}
                j_res['check_no'] = '8.2'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'security'

                if date == 'None':
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'No expiry date set for secret : %s' %(key_name)
                elif exp == '':
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'No keys found in vault %s' %(expiry)
                else:
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'Access Denied could not check for expiration in vault %s' %(expiry)

                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/vault.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_audit():
    print "4.2.1: Checking if SQL DB has AUDIT policy enabled\n\n"
    result = {}
    result['check'] = 'SQL_DB_AUDIT'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.1'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.1'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                audit_policy = subprocess.check_output(['az sql db audit-policy show --resource-group %s --server %s --name %s --query \'state\' --output tsv' %(resource_group,name,database)], shell=True).strip()
                if audit_policy == "Disabled":
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s does not have AUDIT Policy enabled' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s does have AUDIT Policy enabled' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_threat():
    print "4.2.2: Checking if SQL DB has Threat Detection enabled\n\n"
    result = {}
    result['check'] = 'SQL_DB_THREAT_DETECTION'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.2'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.2'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'database'
                threat_policy = subprocess.check_output(['az sql db threat-policy show --resource-group %s --server %s --name %s --query \'state\' --output tsv' %(resource_group,name,database)], shell=True).strip()
                if threat_policy == "Disabled":
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s does not have Threat Detection enabled' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s does have Threat Detection enabled' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_disabled_alert():
    print "4.2.3: Checking if SQL DB has any alerts disabled\n\n"
    result = {}
    result['check'] = 'SQL_DB_DISABLED_ALERT'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.3'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.3'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'database'
                threat_policy = subprocess.check_output(['az sql db threat-policy show --resource-group %s --server %s --name %s --query \'disabledAlerts\' --output tsv' %(resource_group,name,database)], shell=True).strip()
                if threat_policy != "":
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s has some of the alerts disabled' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s does not have alerts disabled' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_send_email():
    print "4.2.4: Checking if SQL DB has any email alerts enabled\n\n"
    result = {}
    result['check'] = 'SQL_DB_EMAIL_ALERT'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.4'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.4'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'database'
                threat_policy = subprocess.check_output(['az sql db threat-policy show --resource-group %s --server %s --name %s --query \'emailAddresses\' --output tsv' %(resource_group, name, database)], shell=True).strip()
                if threat_policy == "Disabled":
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s has some no email set for alerts' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s has some email set for alerts' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_email_admin():
    print "4.2.5: Checking if SQL DB has any Admin email alerts enabled\n\n"
    result = {}
    result['check'] = 'SQL_DB_EMAIL_ADMIN'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.5'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.5'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'database'
                email_policy = subprocess.check_output(['az sql db threat-policy show --resource-group %s --server %s --name %s --query \'emailAccountAdmins\' --output tsv' %(resource_group, name, database)], shell=True).strip()
                if email_policy == "Disabled":
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s has no Admin email set for alerts' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s has some Admin email set for alerts' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_encryption():
    print "4.2.6: Checking if SQL DB has Transparent Data Encryption enabled\n\n"
    result = {}
    result['check'] = 'SQL_DB_DATA_ENCRYPTION'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.6'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.6'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'database'
                encryption = subprocess.check_output(['az sql db tde show --resource-group %s --server %s --database %s --query \'status\' --output tsv' %(resource_group, name, database)], shell=True).strip()
                if encryption == "Disabled":
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s has Transparent Data Encryption disabled' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s has Transparent Data Encryption enabled' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_audit_retention():
    print "4.2.7: Checking if SQL DB has AUDIT log retention policy greater than 90 days\n\n"
    result = {}
    result['check'] = 'SQL_DB_AUDIT_RETENTION'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.7'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.7'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'database'
                days = subprocess.check_output(['az sql db audit-policy show --resource-group %s --server %s --name %s --query \'retentionDays\' --output tsv' %(resource_group, name, database)], shell=True).strip()
                if int(days) <= 90:
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s has AUDIT log retention policy lesser than 90 days' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s has AUDIT log retention policy greater than 90 day' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def sql_db_threat_retention():
    print "4.2.8: Checking if SQL DB has THREAT log retention policy greater than 90 days\n\n"
    result = {}
    result['check'] = 'SQL_DB_THREAT_RETENTION'
    data = []
    check_server_exists = subprocess.check_output(['az sql server list --query [*].[name,resourceGroup] --output tsv'], shell=True).strip()
    if not check_server_exists:
        j_res = {}
        j_res['check_no'] = '4.2.8'
        j_res['level'] = 'INFO'
        j_res['score'] = 'Scored'
        j_res['region'] = 'null'
        j_res['type'] = 'PASS'
        j_res['value'] = 'No SQL servers/DB to AUDIT'
        j_res['category'] = 'database'
        data.append(j_res)
        log_data = dict()
        log_data = j_res
        log_data["data"] = log_data.pop("value")
        log.info("azure report", extra=log_data)
    else:
        for server in check_server_exists.splitlines():
            name,resource_group = server.split()
            databases = subprocess.check_output(['az sql db list --server %s --resource-group %s --query [*].name --output tsv' %(name,resource_group)] ,shell=True).strip()
            for database in databases.splitlines():
                j_res = {}
                j_res['check_no'] = '4.2.8'
                j_res['level'] = 'INFO'
                j_res['score'] = 'Scored'
                j_res['region'] = 'null'
                j_res['category'] = 'database'
                days = subprocess.check_output(['az sql db threat-policy show --resource-group %s --server %s --name %s --query \'retentionDays\' --output tsv' %(resource_group, name, database)], shell=True).strip()
                if int(days) <= 90:
                    j_res['type'] = 'WARNING'
                    j_res['value'] = 'The SQL DB %s on server %s has THREAT log retention policy lesser than 90 days' % (database,name)
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = 'The SQL DB %s on server %s has THREAT log retention policy greater than 90 day' % (database,name)
                data.append(j_res)
                log_data = dict()
                log_data = j_res
                log_data["data"] = log_data.pop("value")
                log.info("azure report", extra=log_data)
    result['data'] = data
    with open('./reports/AZURE/%s/%s/sql_db.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def persistent_json(json_file):

    checks = []
    with open(json_file, 'r') as f:
        for line in f:
            j = json.loads(line)
            checks.append(j['check'])
    checks = set(checks)
    dict = {}
    with open('reports/AZURE/%s/%s/final_diff.json' % (account_name, timestmp), 'w') as g:
        for check in checks:
            dict = {}
            data = []
            with open(json_file , 'r') as f:
                for line in f:
                    j = json.loads(line)
                    if j['check'] == check:
                        dict['check'] = j['check']
                        j.pop('check')
                        data.append(j)
                dict['data'] = data
                g.write("%s\n" % (json.dumps(dict)))


def persis(j1,j2):
    f=open("./reports/AZURE/%s/%s/diff.json" %(account_name, timestmp), "a+")
    for data1 in j1['data']:
        for data2 in j2['data']:
            if data1==data2:
                pers = json.dumps(data1)
                pers = json.loads(pers)
                if pers['type'] == 'WARNING':
                    pers['check'] = j1['check']
                    f.write("%s\n" % json.dumps(pers))
    persistent_json("./reports/AZURE/%s/%s/diff.json" %(account_name, timestmp))


def persistent(latest, last):
    with open("reports/AZURE/%s/%s/diff.json" %(account_name, timestmp), "a+") as h:
        with open(latest, 'r') as f:
            for line1 in f:
                data1 = json.loads(line1)
                for i in data1['data']:
                    with open(last, 'r') as g:
                        for line2 in g:
                            data2 = json.loads(line2)
                            for k in data2['data']:
                                if data1['check'] == data2['check']:
                                    if i==k:
                                        if i['type'] == "WARNING":
                                            i['check'] = data1['check']
                                            h.write("%s\n" % json.dumps(i))

    persistent_json("./reports/AZURE/%s/%s/diff.json" %(account_name, timestmp))


def persistent_files():
    dirs = os.listdir("./reports/AZURE/%s/" % (account_name))
    if len(dirs) == 1:
        print "This is the first audit run for the account, diff will be shown in the next run"
        with open("./reports/AZURE/%s/%s/diff.html" %(account_name, timestmp), 'w') as f:
            f.write("This is the first audit run for the account, diff will be shown in the next run")
    else:
        last_dir = subprocess.check_output(["ls -td -- */ | head -n 2 | cut -d'/' -f1 | sed -n 2p"], cwd='./reports/AZURE/%s' %(account_name), shell=True).strip()
        latest = "./reports/AZURE/%s/%s/final_report/final.json" %(account_name, timestmp)
        last = "./reports/AZURE/%s/%s/final_report/final.json" %(account_name, last_dir)

        persistent(latest, last)
        json_to_html('./reports/AZURE/%s/%s/final_diff.json' % (account_name, timestmp),
                     './reports/AZURE/%s/%s/diff.html' % (account_name, timestmp))


def azure_audit():
    subprocess.call(['mkdir', '-p', 'reports/AZURE/%s/%s/final_report' % (account_name, timestmp)])
    automatic_provising_agent()
    system_update()
    security_configuration()
    endpoint_protection()
    disk_encryption()
    network_security()
    web_app_firewall()
    next_gen_firewall()
    vuln_assessment()
    storage_encyption()
    jit_network_access()
    adaptive_application_control()
    sql_auditing()
    sql_encryption()
    security_email_set()
    security_contact_phone()
    email_for_alert()
    email_for_subs_owners()
    secure_transfer()
    storage_service_encryption()
    encrption_file_service()
    sql_db_audit()
    sql_db_threat()
    sql_db_disabled_alert()
    sql_db_send_email()
    sql_db_email_admin()
    sql_db_encryption()
    sql_db_audit_retention()
    sql_db_threat_retention()
    log_profile()
    log_retention()
    alert_for_create_policy()
    alert_group_create_network()
    alert_group_network_delete()
    alert_rule_network_create()
    alert_rule_network_delete()
    alert_create_security()
    alert_delete_security()
    alert_create_sql_rule()
    alert_delete_sql_rule()
    alert_update_security_policy()
    rdp_public()
    ssh_public()
    network_watcher()
    vm_agent()
    vm_os_disk()
    vm_data_disk()
    approved_extension()
    vault_key()
    vault_secret()
    json_to_html('./reports/AZURE/%s/%s/security_center.json' %(account_name, timestmp),
                        './reports/AZURE/%s/%s/final_report/security_center.html' %(account_name, timestmp))

    json_to_html('./reports/AZURE/%s/%s/storage_account.json' % (account_name, timestmp),
                        './reports/AZURE/%s/%s/final_report/storage_account.html' % (account_name, timestmp))

    json_to_html('./reports/AZURE/%s/%s/logging_monitoring.json' % (account_name, timestmp),
                        'reports/AZURE/%s/%s/final_report/logging_monitoring.html' % (account_name, timestmp))
    json_to_html('./reports/AZURE/%s/%s/network.json' % (account_name, timestmp),
                 'reports/AZURE/%s/%s/final_report/network.html' % (account_name, timestmp))
    json_to_html('./reports/AZURE/%s/%s/vm.json' % (account_name, timestmp),
                 'reports/AZURE/%s/%s/final_report/vm.html' % (account_name, timestmp))
    json_to_html('./reports/AZURE/%s/%s/vault.json' % (account_name, timestmp),
                 'reports/AZURE/%s/%s/final_report/vault.html' % (account_name, timestmp))
    json_to_html('./reports/AZURE/%s/%s/sql_db.json' % (account_name, timestmp),
                 'reports/AZURE/%s/%s/final_report/sql_db.html' % (account_name, timestmp))
    merge_json()
    persistent_files()
    subprocess.check_output(
        ['cp -R ./tools/template/* ./reports/AZURE/"%s"/%s/final_report/' % (account_name, timestmp)], shell=True)
    subprocess.check_output(['rm ./reports/AZURE/"%s"/%s/final_report/report.html' % (account_name, timestmp)], shell=True)
    webbrowser.open('file://' + os.path.realpath("./reports/AZURE/%s/%s/final_report/report_azure.html")
                    % (account_name, timestmp))
    fin = os.path.realpath("./reports/AZURE/%s/%s/final_report/report_azure.html") % (account_name, timestmp)
    print ("THE FINAL REPORT IS LOCATED AT -------->  %s" % (fin))
