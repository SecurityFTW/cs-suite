from googleapiclient import discovery
import json
from tinydb import TinyDB, Query
import add_finding
from httplib2 import Http
from oauth2client.file import Storage
storage = Storage('creds.data')
service = discovery.build('cloudresourcemanager', 'v1', credentials=storage.get())

def insert_roles(projectId, db):
	headers = {"Content-Length":0}
	resp, content = storage.get().authorize(Http()).request("https://cloudresourcemanager.googleapis.com/v1/projects/" + projectId + ":getIamPolicy","POST", headers=headers)
	for role in json.loads(content)['bindings']:
		db.table('Role').insert(role)
#this does not support pagination of results

#service.projects().getIamPolicy(body="",resource="gscout-test").execute()
#gives error Root element must be a message