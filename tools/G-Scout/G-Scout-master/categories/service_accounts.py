import json

from oauth2client.file import Storage

def add_role(role):
    def transform(element):
        try:
            element['roles'].append(role)
        except KeyError:
            element['roles'] = [role]

    return transform


def insert_sa_roles(projectId, db):
    for role in db.table('Role').all():
        for sa in db.table('Service Account').all():
            if "serviceAccount:" + str.split(str(sa['name']), '/')[-1] in role['members']:
                db.table("Service Account").update(
                    add_role(role['role']),
                    eids=[sa.eid])