from googleapiclient import discovery
from oauth2client.client import GoogleCredentials
from core.utility import get_gcloud_creds

service = discovery.build('compute', 'v1', credentials=get_gcloud_creds())

def insert_addresses(projectId, db):
    project = projectId
    regions = ['us-central1','us-east1','us-east4','us-west1','us-west2']
    #add more regions as desired

    for region in regions:
        try:
            request = service.addresses().list(project=project, region=region)
            while request is not None:
                response = request.execute()
                for address in response['items']:
                    db.table("Address").insert(address)
                request = service.addresses().list_next(previous_request=request, previous_response=response)
        except KeyError:
            pass