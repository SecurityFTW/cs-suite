import boto3
from botocore.client import Config
import requests
import json
import time
import subprocess
import webbrowser
import os

account_name = ''
timestmp = time.strftime("%Y%m%d-%H%M%S")


def spaces_audit(do_key, do_secret):
    # Initialize a session using DigitalOcean Spaces.
    session = boto3.session.Session()
    print "\n\n*********** SPACES AUDIT **************\n\n"
    # Regions available for DigitalOcean Spaces - 'nyc3', 'ams3', etc etc
    regions = ['nyc3', 'ams3', 'sgp1', 'sfo2', 'fra1']
    result = {}
    data = []
    for region in regions:
        client = session.client('s3',
                 region_name=region,
                 endpoint_url='https://'+region+'.digitaloceanspaces.com',
                 aws_access_key_id= do_key,
                 aws_secret_access_key= do_secret)
        spaces = client.list_buckets()
        if spaces['Buckets']:
            for space in spaces['Buckets']:
                url = "http://" + space['Name'] +"."+ region +"." + "digitaloceanspaces.com"
                resp = requests.get(url)
                j_res = {}
                j_res['check_no'] = '1.1'
                j_res['level'] = 'INFO'
                j_res['region'] = region
                j_res['score'] = 'Scored'
                j_res['category'] = 'Storage'
                if resp.status_code == 200:
                    j_res['type'] = 'WARNING'
                    j_res['value'] = "WARNING! The space %s is open to the public in region %s" % (space['Name'], region)
                    print "WARNING! The space %s is open to the public in region %s\n" % (space['Name'], region)
                elif resp.status_code == 403:
                    j_res['type'] = 'PASS'
                    j_res['value'] = "OK! the space %s is not open to the public in region %s\n" % (space['Name'], region)  
                    print "OK! the space %s is not open to the public in region %s" % (space['Name'], region)
                data.append(j_res)
    result['data'] = data
    result['check'] = 'SPACES_AUDIT'
    with open('./reports/DIGITALOCEAN/%s/%s/final_report/final.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")


def database_audit(do_api):
    url = "https://api.digitalocean.com/v2/databases"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api) 
    response = requests.get(url, headers=header)
    response = json.loads(response.text)
    result = {}
    data = []
    print "\n\n*********** DATABASES AUDIT **************\n\n"
    for database in response['databases']:
        j_res = {}
        j_res['check_no'] = '1.2'
        j_res['level'] = 'INFO'
        j_res['region'] = 'null'
        j_res['score'] = 'Scored'
        j_res['category'] = 'Databases'
        id = database['id']
        if database['engine'] == 'redis':
            ev_policy_url = url + '/' + id + '/eviction_policy'
            resp = requests.get(ev_policy_url, headers=header)
            resp = json.loads(resp.text)
            if resp['eviction_policy'] == "noeviction":
                j_res['type'] = 'WARNING'
                j_res['value'] = "WARNING! The database %s has no eviction/firewall policy" % (database['name']) 
                print "WARNING! The redis cluster %s has no eviction policy\n" % (database['name'])
            else:
                j_res['type'] = 'PASS'
                j_res['value'] = "OK! The redis cluster %s has a eviction/restriction policy" %(database['name'])
                print "OK! The redis cluster %s has a eviction/restriction policy\n" %(database['name'])

        elif database['engine'] == 'mysql' or database['engine'] == 'postgresql':
            ev_policy_url = url + '/' + id + '/firewall'
            resp = requests.get(ev_policy_url, headers=header)
            resp = json.loads(resp.text)
            if not resp['rules']:
                j_res['type'] = 'WARNING'
                j_res['value'] = "WARNING! The database %s has no eviction/firewall policy" % (database['name'])
                print "WARNING! The database %s has no eviction/firewall policy\n" % (database['name'])
            else:
                j_res['type'] = 'PASS'
                j_res['value'] = "OK! The database %s has a eviction/firewall policy" % (database['name'])
                print "OK! The database %s has a eviction/firewall policy\n" % (database['name'])
        data.append(j_res)
    result['data'] = data
    result['check'] = 'DATABASES_AUDIT'
    with open('./reports/DIGITALOCEAN/%s/%s/final_report/final.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")

def firewall_audit(do_api):
    url = "https://api.digitalocean.com/v2/firewalls"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api)
    response = requests.get(url, headers=header)
    resp = json.loads(response.text)
    result = {}
    data = []
    print "\n\n*********** FIREWALL AUDIT **************\n\n"
    for firewall in resp['firewalls']:
    	j_res = {}
        j_res['check_no'] = '1.3'
        j_res['level'] = 'INFO'
        j_res['region'] = 'null'
        j_res['score'] = 'Scored'
        j_res['category'] = 'Firewall'
        name = firewall['name']
        for rules in firewall['inbound_rules']:
            for sources in rules['sources']['addresses']:
                if sources in ["0.0.0.0/0","::/0"]:
                    if rules['ports'] == "0":
                        rules['ports'] = "1-65535"
                    j_res['type'] = 'WARNING'
                    j_res['value'] = "WARNING! The firewall %s has port %s accessible to the world" %(name, rules['ports'])
                    print "WARNING! The firewall %s has port %s accessible to the world\n" %(name, rules['ports'])
                    break
                else:
                    j_res['type'] = 'PASS'
                    j_res['value'] = "OK! The firewall %s does not allow port %s accessible to the world" %(name, rules['ports'])
                    print "OK! The firewall %s does not allow port %s accessible to the world\n" %(name, rules['ports'])
            data.append(j_res.copy())
    result['data'] = data
    result['check'] = 'FIREWALL_AUDIT'
    with open('./reports/DIGITALOCEAN/%s/%s/final_report/final.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")  

def droplet_audit(do_api):
    url = "https://api.digitalocean.com/v2/droplets"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api)
    response = requests.get(url, headers=header)
    resp = json.loads(response.text)
    result = {}
    data = []
    print "\n\n*********** DROPLET AUDIT **************\n\n"
    for droplet in resp['droplets']:
    	j_res = {}
        j_res['check_no'] = '1.4'
        j_res['level'] = 'INFO'
        j_res['region'] = 'null'
        j_res['score'] = 'Scored'
        j_res['category'] = 'Server'
        if droplet['image']['slug'] in ['ubuntu-19-x64', 'fedora-30-x64', 'freebsd-12-x64-zfs', 'debian-10-x64', 'centos-7.6-x64']:
            j_res['type'] = 'PASS'
            j_res['value'] = "OK! The droplet %s has the latest version of OS being used" % droplet['name']
            print "OK! The droplet %s has the latest version of OS being used\n" % droplet['name']
        else:
            j_res['type'] = 'WARNING'
            j_res['value'] = "WARNING! The droplet %s has older version of OS being used" % droplet['name']
            print "WARNING! The droplet %s has older version of OS being used\n" % droplet['name']
        data.append(j_res)
    result['data'] = data
    result['check'] = 'DROPLET_AUDIT'
    with open('./reports/DIGITALOCEAN/%s/%s/final_report/final.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")  

def load_balancer_audit(do_api):
    url = "https://api.digitalocean.com/v2/load_balancers"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api)
    response = requests.get(url, headers=header)
    resp = json.loads(response.text)
    result = {}
    data = []
    print "\n\n*********** LOAD BALANCER AUDIT **************\n\n"
    for load_balancer in resp['load_balancers']:
    	j_res = {}
        j_res['check_no'] = '1.4'
        j_res['level'] = 'INFO'
        j_res['region'] = 'null'
        j_res['score'] = 'Scored'
        j_res['category'] = 'Networking'
        port = []
        for rule in load_balancer['forwarding_rules']:
            port.append(rule['entry_port'])
            if rule['entry_port'] == 443 and rule['tls_passthrough'] == True:
            	j_res['type'] = 'WARNING'
            	j_res['value'] = "WARNING! The load-balancer %s is running on https without SSL/TLS certificate\n" % load_balancer['name']
                print "WARNING! The load-balancer %s is running on https without SSL/TLS certificate" % load_balancer['name']
                data.append(j_res.copy())
            elif rule['entry_port'] == 443 and rule['tls_passthrough'] == False:
            	j_res['type'] = 'PASS'
            	j_res['value'] = "OK! The load-balancer %s is running on https with a SSL/TLS certificate" % load_balancer['name']
                print "OK! The load-balancer %s is running on https with a SSL/TLS certificate\n" % load_balancer['name']
                data.append(j_res.copy())
        if 80 and 443 in port:
            if load_balancer['redirect_http_to_https']:
            	j_res['type'] = 'PASS'
            	j_res['value'] = "OK! The load-balancer %s is running on https with a SSL/TLS certificate" % load_balancer['name']
                print "OK! Port 80 and 443 are open for load-balancer %s and redirect http to https is set to True\n" % load_balancer['name']
                data.append(j_res.copy())
            else:
            	j_res['type'] = 'WARNING'
            	j_res['value'] = "WARNING! The load-balancer %s is running on https without SSL/TLS certificate" % load_balancer['name']
                print "WARNING! Port 80 and 443 are open for load-balancer %s and redirect http to https is set to False\n" % load_balancer['name']
                data.append(j_res.copy())
        if (80 in port) and (443 not in port):
            j_res['type'] = 'WARNING'
            j_res['value'] = "WARNING! The load-balancer %s is running on https without SSL/TLS certificate" % load_balancer['name']
            print "WARNING! The load balancer %s is running on http only\n" % load_balancer['name']
            data.append(j_res.copy())
    result['data'] = data
    result['check'] = 'LOAD_BALANCER_AUDIT'
    with open('./reports/DIGITALOCEAN/%s/%s/final_report/final.json' %(account_name, timestmp), 'a+') as f:
        f.write(json.dumps(result))
        f.write("\n")  

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
                          f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['value']))
                     else:
                          f.write('<p>%s<p>\n' % (k['value']))
                 f.write('</div>')
                 f.write('</div>')
                 f.write('</div>')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line)

def do_audit(do_api, do_key, do_secret):
    global account_name
    url = "https://api.digitalocean.com/v2/projects"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api)
    response = requests.get(url, headers=header)
    result = json.loads(response.text)
    account_name = result['projects'][0]['name']
    subprocess.call(['mkdir', '-p', 'reports/DIGITALOCEAN/%s/%s/final_report' % (account_name, timestmp)])
    spaces_audit(do_key, do_secret)
    database_audit(do_api)
    firewall_audit(do_api)
    droplet_audit(do_api)
    load_balancer_audit(do_api)
    json_to_html('./reports/DIGITALOCEAN/%s/%s/final_report/final.json' % (account_name, timestmp),
                 'reports/DIGITALOCEAN/%s/%s/final_report/final.html' % (account_name, timestmp))
    webbrowser.open('file://' + os.path.realpath("./reports/DIGITALOCEAN/%s/%s/final_report/final.html")
                    % (account_name, timestmp))
    fin = os.path.realpath("./reports/DIGITALOCEAN/%s/%s/final_report/final.html") % (account_name, timestmp)
    print ("THE FINAL REPORT IS LOCATED AT -------->  %s\n" % (fin))
