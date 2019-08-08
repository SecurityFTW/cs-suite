from googleapiclient import discovery
from oauth2client.file import Storage

from core.utility import get_gcloud_creds

storage = Storage('creds.data')
service = discovery.build('storage', 'v1', credentials=get_gcloud_creds())


def insert_acls(db):
    for bucket in db.table('Bucket').all():
        request = service.bucketAccessControls().list(bucket=bucket['name'])
        try:
            response = request.execute()
            if 'items' in response.keys():
                for acl in response['items']:
                    acl_role = ""
                    acl_entity = ""
                    if 'role' in acl.keys():
                        acl_role = acl['role']
                    if 'entity' in acl.keys():
                        acl_entity = acl['entity']
                    db.table('Bucket').update(
                        add_acl({"permission": acl_role, "scope": acl_entity}), eids=[bucket.eid])
        except Exception as e:
            print("Error getting bucket ACLs for bucket '%s': %s" % (bucket, e))


def insert_defacls(db):
    for bucket in db.table('Bucket').all():
        request = service.defaultObjectAccessControls().list(bucket=bucket['name'])
        try:
            response = request.execute()
            if 'items' in response.keys():
                for defacl in response['items']:
                    acl_role = ""
                    acl_entity = ""
                    if 'role' in defacl.keys():
                        acl_role = defacl['role']
                    if 'entity' in defacl.keys():
                        acl_entity = defacl['entity']
                    db.table('Bucket').update(
                        add_defacl({"permission": acl_role, "scope": acl_entity}), eids=[bucket.eid])
        except Exception as e:
            print("Error getting default ACLs for bucket '%s': %s" % (bucket, e))


# Function to pass Tinydb for the update query
def add_acl(acl):
    def transform(element):
        if 'acls' in element.keys():
            element['acls'].append(acl)
        else:
            element['acls'] = [acl]
    return transform


def add_defacl(defacl):
    def transform(element):
        if 'defacls' in element.keys():
            element['defacls'].append(defacl)
        else:
            element['defacls'] = [defacl]

    return transform
