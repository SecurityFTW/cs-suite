from googleapiclient import discovery
from tinydb import TinyDB, Query
from oauth2client.file import Storage
db = TinyDB('projects.json')
storage = Storage('creds.data')
from httplib2 import Http
service = discovery.build("storage", "v1", credentials=storage.get())
import json

def get_buckets(project):
	request = service.buckets().list(project=project['projectId'])
	response = request.execute()
	buckets = []
	if (response.get('items')):
		for bucket in response['items']:
			if "logging" not in bucket:
				buckets.append(bucket)
	return buckets				
