import boto3
from botocore.client import Config
import requests
import json

def spaces_audit(do_key, do_secret):
    # Initialize a session using DigitalOcean Spaces.
    session = boto3.session.Session()
    print "\n\n*********** SPACES AUDIT **************\n\n"
    # Regions available for DigitalOcean Spaces - 'nyc3', 'ams3', etc etc
    regions = ['nyc3', 'ams3', 'sgp1', 'sfo2', 'fra1']
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
                if resp.status_code == 200:
                    print "Warning the space %s is open to the public in region %s\n" % (space['Name'], region)
                elif resp.status_code == 403:
                    print "Ok! the space %s is not open to the public in region %s\n" % (space['Name'], region)


def database_audit(do_api):
    url = "https://api.digitalocean.com/v2/databases"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api) 
    response = requests.get(url, headers=header)
    response = json.loads(response.text)
    print "\n\n*********** DATABASES AUDIT **************\n\n"
    for database in response['databases']:
        id = database['id']
        if database['engine'] == 'redis':
            ev_policy_url = url + '/' + id + '/eviction_policy'
            result = requests.get(ev_policy_url, headers=header)
            result = json.loads(result.text)
            if result['eviction_policy'] == "noeviction":
                print "Warning the redis cluster %s has no eviction policy\n" % (database['name'])
            else:
                print "Ok! The redis cluster %s has a eviction/restriction policy\n" %(database['name'])

        elif database['engine'] == 'mysql' or database['engine'] == 'postgresql':
            ev_policy_url = url + '/' + id + '/firewall'
            result = requests.get(ev_policy_url, headers=header)
            result = json.loads(result.text)
            if not result['rules']:
                print "Warning the database %s has no eviction/firewall policy\n" % (database['name'])
            else:
                print "Ok! the database %s has a eviction/firewall policy\n" % (database['name'])

def firewall_audit(do_api):
    url = "https://api.digitalocean.com/v2/firewalls"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api)
    response = requests.get(url, headers=header)
    result = json.loads(response.text)
    print "\n\n*********** FIREWALL AUDIT **************\n\n"
    for firewall in result['firewalls']:
        name = firewall['name']
        for rules in firewall['inbound_rules']:
            for sources in rules['sources']['addresses']:
                if sources in ["0.0.0.0/0","::/0"]:
                    if rules['ports'] == "0":
                        rules['ports'] = "1-65535"
                    print "Warning! the firewall %s has allowed world access to the port %s\n" %(name, rules['ports'])
                    break
                else:
                    print "Ok! the firewall %s does not allow access to the world\n" %(name)

def droplet_audit(do_api):
    url = "https://api.digitalocean.com/v2/droplets"
    header={"Content-Type": "application/json"}
    header['Authorization'] = "Bearer %s" %(do_api)
    response = requests.get(url, headers=header)
    result = json.loads(response.text)
    print "\n\n*********** DROPLET AUDIT **************\n\n"
    for droplet in result['droplets']:
        if droplet['image']['slug'] in ['ubuntu-19-x64', 'fedora-30-x64', 'freebsd-12-x64-zfs', 'debian-10-x64', 'centos-7.6-x64']:
            print "Ok! The droplet %s has the latest version of OS being used\n" % droplet['name']
        else:
            print "Warning! The droplet %s has older version of OS being used\n" % droplet['name']

def do_audit(do_api, do_key, do_secret):
    spaces_audit(do_key, do_secret)
    database_audit(do_api)
    firewall_audit(do_api)
    droplet_audit(do_api)
