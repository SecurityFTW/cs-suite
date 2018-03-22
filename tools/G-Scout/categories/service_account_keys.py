from oauth2client.service_account import ServiceAccountCredentials
from httplib2 import Http
from tinydb import TinyDB, Query
import json
import datetime
import add_finding
from oauth2client.file import Storage
storage = Storage('creds.data')
	
def insert_service_account_keys(projectId, db):
	service_accounts = db.table("Service Account").all()
	for sa in service_accounts:
		sa_keys = list_service_account_keys(sa,projectId)
		for sa_key in sa_keys:
			db.table('Service Account').update(
					add_key({
						"keyAlgorithm":sa_key['keyAlgorithm'], 
						"validBeforeTime":sa_key['validBeforeTime'],
						"validAfterTime":sa_key['validAfterTime']
						}),
					eids=[sa.eid])

def list_service_account_keys(sa, projectId):
	resp, content = storage.get().authorize(Http()).request("https://iam.googleapis.com/v1/projects/" + projectId + "/serviceAccounts/"+ sa['uniqueId'] +"/keys","GET")
	return json.loads(content)['keys']

# Function to pass Tinydb for the update query
def add_key(key):
	def transform(element):
		try:
			element['keys'].append(key)
		except KeyError:
			element['keys'] = [key]
	return transform

def key_is_old(key):
	creation_date = datetime.datetime.strptime(key['validAfterTime'][:10], "%Y-%m-%d")
	if creation_date < datetime.datetime.now() - datetime.timedelta(days=90):
		return True
	return False