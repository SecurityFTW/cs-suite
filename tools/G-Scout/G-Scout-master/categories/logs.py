import json

from oauth2client.file import Storage

from core.utility import get_gcloud_creds

storage = Storage('creds.data')
from httplib2 import Http
from tinydb import TinyDB

db = TinyDB('entities.json')


def list_log_services():
    projectId = TinyDB('projects.json').table("Project").all()
    resp, content = get_gcloud_creds().authorize(Http()).request(
        "https://logging.googleapis.com/v1beta3/projects/" + projectId + "/logServices", "GET")
    return [service['name'] for service in json.loads(content)['logServices']]
