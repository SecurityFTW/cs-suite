from googleapiclient import discovery
from tinydb import TinyDB

from core.utility import get_gcloud_creds

db = TinyDB('entities.json')
group_table = db.table('Instance Groups')
template_table = db.table('Instance Templates')
credentials = GoogleCredentials.get_application_default()
from oauth2client.file import Storage

storage = Storage('creds.data')
service = discovery.build('compute', 'v1', credentials=get_gcloud_creds())
instanceGroups = service.instances()
instanceTemplates = service.instanceTemplates()
zones = service.zones()


def insert_templates():
    projectId = TinyDB('projects.json').table("Project").all()
    request = instanceTemplates.list(project=projectId)
    try:
        while request is not None:
            response = request.execute()
            for instanceTemplate in response['items']:
                template_table.insert(instanceTemplate)
            request = instanceTemplates.list_next(previous_request=request, previous_response=response)
    except KeyError:
        pass


def insert_instance_groups():
    projectId = TinyDB('projects.json').table("Project").all()
    for zone in get_zones():
        request = instanceGroups.list(project=projectId, zone=zone)
        try:
            while request is not None:
                response = request.execute()
                for instanceGroup in response['items']:
                    group_table.insert(instanceGroup)
                request = instanceGroups.list_next(previous_request=request, previous_response=response)
        except KeyError:
            pass


def get_zones():
    projectId = TinyDB('projects.json').table("Project").all()
    results = []
    request = zones.list(project=projectId)
    response = request.execute()['items']
    for result in response:
        results.append(result['name'])
    return results
