from googleapiclient import discovery
from oauth2client.file import Storage
from tinydb import TinyDB

db = TinyDB('projects.json')
storage = Storage('creds.data')
from core.utility import get_gcloud_creds

service = discovery.build("storage", "v1", credentials=get_gcloud_creds())


def get_buckets(project):
    request = service.buckets().list(project=project['projectId'])
    response = request.execute()
    buckets = []
    if (response.get('items')):
        for bucket in response['items']:
            if "logging" not in bucket:
                buckets.append(bucket)
    return buckets
