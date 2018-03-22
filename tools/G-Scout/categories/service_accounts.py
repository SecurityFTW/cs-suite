from oauth2client.service_account import ServiceAccountCredentials
import json
from oauth2client.file import Storage
storage = Storage('creds.data')
from httplib2 import Http
from tinydb import TinyDB, Query

def insert_service_accounts(projectId, db):
	resp, content = storage.get().authorize(Http()).request("https://iam.googleapis.com/v1/projects/"+ projectId +"/serviceAccounts/","GET")
	for account in json.loads(content)['accounts']:
		db.table("Service Account").insert(account)

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
			if "serviceAccount:" + str.split(str(sa['name']),'/')[-1] in role['members']:
				db.table("Service Account").update(
					add_role(role['role']),
					eids=[sa.eid])

