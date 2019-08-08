import json
from googleapiclient import discovery
from core.utility import get_gcloud_creds

service = discovery.build('cloudresourcemanager', 'v1', credentials=get_gcloud_creds())

def insert_roles(projectId, db):
    try:
        try:
            request = service.projects().getIamPolicy(resource=projectId, body={})
            role_list = request.execute()['bindings']
        except Exception as e:
            print("Error obtaining role list: %s" % (e))
        if role_list:
            for role in role_list:
                try:
                    db.table('Role').insert(role)
                except Exception as e:
                    print("Error inserting role into database: %s" % (e))
    except Exception as e:
        print("Error enumerating roles: %s" % (e))