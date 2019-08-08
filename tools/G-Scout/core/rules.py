import datetime

from googleapiclient import discovery
from oauth2client.file import Storage

from tinydb import TinyDB

from core import add_finding
from categories.firewalls import test_allowed
from categories.service_account_keys import key_is_old

from core.utility import object_id_to_directory_name
from core.utility import get_gcloud_creds


def rules(projectId):
    db = TinyDB("project_dbs/" + object_id_to_directory_name(projectId) + ".json")

    class Rule:
        def __init__(self, rule_title, category, filter_func):
            try:
                formatted_title = rule_title
#                formatted_title = "%s - %s" % (category, rule_title)
                # print("Inserting %s" % (formatted_title))
                db.table('Rule').insert({"title": formatted_title, "category": category})
                for entity in list(filter(filter_func, db.table(category).all())):
                    add_finding.add_finding(db, category, entity.eid, rule_title)
            except Exception as e:
                print("Error inserting %s: %s" % (rule_title, e))
            except KeyError:
                pass

    Rule("Unused Network", "Network",
         lambda network: not network.get('members'))

    Rule("VPC Flow Logs Disabled for Subnet", "Subnet",
        lambda subnet: not 'enableFlowLogs' in subnet.keys() or not subnet['enableFlowLogs'])

    # This isn't really a security finding, but there's not a good way to include it as informational without changing a bunch of other things
    Rule("VPC Flow Logs Enabled for Subnet", "Subnet",
        lambda subnet: 'enableFlowLogs' in subnet.keys() and subnet['enableFlowLogs'])
        
    Rule("Unrestriced Internal Traffic", "Network",
        lambda network: network.get('firewallRules')
                     and [True for rule in network['firewallRules']
                          if "10.128.0.0/9" in rule['sourceRanges']
                          and [True for allow in rule['allowed']
                               if not allow.get('ports') or "0-65535" in allow['ports']]])

    Rule("Primitive Roles in Use", "Role",
         lambda role: role['role'] in ["roles/owner", "roles/editor", "roles/viewer"])


    try:    
        Rule("Role Assigned Directly to User", "Role",
            lambda role: [True for member in role['members'] if ((len(member) > 4) and (member[:4] == "user"))])
    except Exception as e:
        print("Error adding 'Role Assigned Directly to User' rule: %s" % (e))
    
    Rule("Bucket Grants Access to allUsers", "Bucket",
         lambda bucket: 'acls' in bucket.keys() and [True for acl in bucket['acls'] if acl['scope'] == "allUsers"])

    Rule("Bucket Grants Access to allAuthenticatedUsers", "Bucket",
         lambda bucket: 'acls' in bucket.keys() and [True for acl in bucket['acls'] if acl['scope'] == "allAuthenticatedUsers"])

    try:
        Rule("User Assigned Bucket Permissions Directly", "Bucket",
            lambda bucket: 'acls' in bucket.keys() and [True for acl in bucket['acls'] if acl['scope'][:4] == "user"])
    except Exception as e:
        print("Error adding 'User Assigned Bucket Permissions Directly' rule: %s" % (e))

    Rule("Bucket Logging Not Enabled", "Bucket", lambda bucket: "logging" not in bucket)

    Rule("Bucket Versioning Not Enabled", "Bucket",
         lambda bucket: "versioning" not in bucket)

    Rule("Owner Role for allUsers in Bucket Default ACL", "Bucket",
         lambda bucket: bucket.get('defacls') and [True for defacl in bucket['defacls'] if
                         defacl['scope'] == "allUsers" and defacl['permission'] == "OWNER"])

    Rule("Read Role for allUsers in Bucket Default ACL", "Bucket",
         lambda bucket: bucket.get('defacls') and [True for defacl in bucket['defacls'] if
                         defacl['scope'] == "allUsers" and defacl['permission'] == "READER"])
    try:
        Rule("No Recent Compute Engine Backup Images", "Compute Engine",
             lambda instance: db.table('Snapshot').all()
                              and [True for snapshot in db.table('Snapshot').all()
                                   if not [True for disk in instance['disks']
                                           if snapshot['sourceDisk'] in disk.values()]
                                   and 'creationTimestamp' in snapshot.keys() and len(snapshot['creationTimestamp']) > 10 and datetime.datetime.strptime(snapshot['creationTimestamp'][:10], "%Y-%m-%d")
                                   < datetime.datetime.now() - datetime.timedelta(days=30)])
    except Exception as e:
        print("Error creating 'No Recent Compute Engine Backup Images' rule: %s" % (e))

    try:
 #       Rule("Allows full access to all Cloud APIs", "Compute Engine", lambda instance: "https://www.googleapis.com/auth/cloud-platform" in instance['serviceAccounts'][0]['scopes'])
        # This is kind of a bad check, because it doesn't take into account the IAM policies which apply to the service accounts.
        # Access scopes are also a "legacy" method according to Google: https://cloud.google.com/compute/docs/access/service-accounts
        # Having it is arguably better than not having it, but it's misleading.
        # On the other hand, trying to take the IAM policies into account would also be a challenge.
        Rule("Service Account is Allowed Full Access to all Cloud APIs via Instance", "Compute Engine", lambda instance: 'serviceAccounts' in instance.keys() and [ True for service_account in instance['serviceAccounts'] if 'scopes' in service_account.keys() and "https://www.googleapis.com/auth/cloud-platform" in service_account['scopes'] ])
    except Exception as e:
        print("Error adding rule 'Allows full access to all Cloud APIs': %s" % (e))

    Rule("Compute Engine with Serial Port Enabled", "Compute Engine", lambda instance: instance.get("metadata").get("items")
        and [True for item in instance.get("metadata").get("items") if item['key']=="serial-port-enable" and item['value']=='true'])

    Rule("Cloud SQL Automatic Backup Disabled", "SQL Instance",
#         lambda instance: not instance.get('settings').get('backupConfiguration').get('enabled'))
        # Ignore this rule for replicas
         lambda instance: 'REPLICA' not in instance.get('instanceType') and not instance.get('settings').get('backupConfiguration').get('enabled'))

    Rule("Cloud SQL Binary Log Disabled", "SQL Instance",
        # Ignore this rule for replicas
        # PostgreSQL on GCP does not currently support binary logging
         lambda instance: 'POSTGRES' not in instance.get('databaseVersion') and 'REPLICA' not in instance.get('instanceType') and not instance.get('settings').get('backupConfiguration').get('binaryLogEnabled'))

    Rule("Cloud SQL Instance does not Require TLS Connections", "SQL Instance",
         lambda instance: not instance.get('settings').get('ipConfiguration').get('requireSsl'))

    Rule("Service Account with Unrotated Keys", "Service Account",
         lambda account: account.get('keys')
                         and [True for key in account.get('keys') if key_is_old(key)])

    Rule("Service Account with allUsers Permission", "Service Account",
         lambda account: account.get('iam_policies')
                         and [True for policy in account.get('iam_policies')
                              if "allUsers" in policy['scope']])

    Rule("MongoDB Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "27017" in rule['ports']])

    Rule("PostgreSQL Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "54322" in rule['ports']])

    Rule("Oracle Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "1521" in rule['ports']])

    # "MySQL" and "MS SQL" are not the same thing
    Rule("MySQL Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and test_allowed(firewall, "tcp", [3306]))

    Rule("Microsoft SQL Server Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and test_allowed(firewall, "tcp", [1433]))

    Rule("DNS Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "53" in rule['ports']])

    Rule("FTP Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "21" in rule['ports']])

    Rule("Telnet Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "23" in rule['ports']])

    Rule("RDP Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "3389" in rule['ports']])

    Rule("SSH Port Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and [True for rule in firewall['allowed'] if rule.get('ports')
                               and "22" in rule['ports']])

    Rule("All Ports Open to All", "Firewall",
         lambda firewall: firewall.get("sourceRanges")
                          and "0.0.0.0/0" in firewall['sourceRanges']
                          and (not firewall.get('allowed')[0].get('ports')
                               or [True for rule in firewall['allowed'] if rule.get('ports')
                                   and '0-65535' in rule.get('ports')]))

    Rule("Use of Port Ranges in Firewall Rule", "Firewall",
         lambda firewall: [allow for allow in firewall['allowed']
                           if allow.get('ports') and [port for port in allow['ports'] if "-" in port]])

    Rule("Unused Firewall Rules", "Firewall",
         lambda firewall: not firewall.get('affectedInstances'))

    #GKE
    Rule("Legacy ABAC in Use", "Cluster", lambda cluster: cluster.get("legacyAbac"))
    Rule("Basic Authentication Enabled", "Cluster", lambda cluster: cluster.get("masterAuth").get("username"))
    Rule("Client Certificate Enabled", "Cluster", lambda cluster: cluster.get("masterAuth").get("clientCertificate"))
    Rule("No Network Policy", "Cluster", 
        lambda cluster: cluster.get("addonsConfig").get("networkPolicyConfig").get("disabled"))
    #I don't know why this is here too, since node version is in node pools. (same with service account and imageType)
    # Rule("Node Version Outdated", "Cluster", lambda cluster: cluster.get('currentNodeVersion') != '')
    Rule("Not Using Private Cluster Master", "Cluster", lambda cluster: not cluster.get('privateClusterConfig'))
    Rule("Not Using Private Cluster Nodes", "Cluster", lambda cluster: not cluster.get('enablePrivateNodes'))
    Rule("Stackdriver Logging Disabled", "Cluster", lambda cluster: not cluster.get('loggingService') or (cluster.get("loggingService") == "none"))
    #Rule("Istio Not Enabled", "Cluster", lambda cluster: )
    Rule("Dashboard Configured", "Cluster", lambda cluster: cluster.get("addonsConfig").get("kubernetesDashboard")) 
    Rule("No Pod Security Policy", "Cluster", lambda cluster: not cluster.get("podSecurityPolicyConfig"))

    #Node Pools
    Rule("Auto Upgrade Disabled", "Cluster", lambda cluster: cluster.get("nodePools") and [True for nodePool in cluster.get("nodePools") if nodePool.get('management').get('autoUpgrade')])
    Rule("Image Type not Container Optimized OS", "Cluster", 
        lambda cluster: cluster.get("nodePools") and [True for nodePool in cluster.get("nodePools") if nodePool.get("config").get("imageType") != "COS"])
    Rule("Node Uses Default Service Account", "Cluster",
        lambda cluster: cluster.get("nodePools") and [True for nodePool in cluster.get("nodePools") if "default" in nodePool.get("config").get("serviceAccount")])
    Rule("Node Version Outdated", "Cluster", 
        lambda cluster: cluster.get("nodePools") and [True for nodePool in cluster.get("nodePools") if nodePool.get("version") != "1.11.5-gke.5"])
