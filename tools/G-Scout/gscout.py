from tinydb import TinyDB, Query
from oauth2client.file import Storage
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.client import ApplicationDefaultCredentialsError
from googleapiclient import discovery
storage = Storage('creds.data')
import logging
logging.basicConfig(filename="log.txt")
logging.getLogger().setLevel(logging.ERROR)
# Silence some errors
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
import os
import sys
from fetch import fetch
from rules import rules

try:
	os.remove("projects.json")
except:
	pass
db = TinyDB('projects.json')

def list_projects(project_or_org,specifier):
	service = discovery.build('cloudresourcemanager',
		'v1',credentials=storage.get())

	if project_or_org=="organization":
		request = service.projects().list(filter='parent.id:%s' % specifier)
	elif project_or_org=="project":
		request = service.projects().list(filter='name:%s' % specifier)
	else:
		raise Exception('Organization or Project not specified.')
	while request is not None:
		response = request.execute()
		for project in response['projects']:
			if (project['lifecycleState'] != "DELETE_REQUESTED"):
				db.table('Project').insert(project)

		request = service.projects().\
		list_next(previous_request=request,previous_response=response)


def fetch_all(project):
	try:
		os.makedirs("project_dbs")
	except:
		pass
	try:
		os.makedirs("Report Output/" + project['projectId'])
	except:
		pass
	try:
		fetch(project['projectId'])
	except Exception as e:
		print("Error fetching ",project['projectId'])
		logging.exception(e)

try:
	os.makedirs("Report Output")
except:
	pass
try:
	list_projects(sys.argv[1],sys.argv[2])
except (HttpAccessTokenRefreshError, ApplicationDefaultCredentialsError):
	import config
	list_projects(sys.argv[1],sys.argv[2])
for project in db.table("Project").all():
	print("Scouting ",project['projectId'])
	fetch_all(project)
