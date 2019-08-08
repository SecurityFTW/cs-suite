from oauth2client.file import Storage

storage = Storage('creds.data')
from httplib2 import Http
import json
from core.utility import get_gcloud_creds

headers = {"Content-Length": 0}


def insert_sa_policies(projectId, db):
    service_accounts = db.table("Service Account").all()
    for account in service_accounts:
        resp, content = get_gcloud_creds().authorize(Http()).request(
            "https://iam.googleapis.com/v1/projects/" + projectId + "/serviceAccounts/" + account[
                'uniqueId'] + ":getIamPolicy", "POST", headers=headers)
        try:
            for policy in json.loads(content)['bindings']:
                db.table('Service Account').update(
                    add_policy({
                        "permission": policy['role'],
                        "scope": policy['members']
                    }),
                    eids=[account.eid])
        except KeyError:
            pass


# Function to pass Tinydb for the update query
def add_policy(policy):
    def transform(element):
        try:
            element['iam_policies'].append(policy)
        except KeyError:
            element['iam_policies'] = [policy]

    return transform
