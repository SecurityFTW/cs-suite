from googleapiclient import discovery
from tinydb import TinyDB, Query
from core.utility import object_id_to_directory_name
from core.utility import get_gcloud_creds


def insert_entity(projectId, product, categories, table_name, version="v1", prefix="", items="items", suffix=""):
    db = TinyDB("project_dbs/" + object_id_to_directory_name(projectId) + ".json")
    service = discovery.build(product, version, credentials=get_gcloud_creds())
    while categories:
        api_entity = getattr(service, categories.pop(0))()
        service = api_entity
    try:
        request = api_entity.list(project=prefix + projectId + suffix)
    except TypeError:
        try:
            request = api_entity.list(name=prefix + projectId + suffix)
        except TypeError:
            request = api_entity.list(parent=prefix + projectId + suffix)
    try:
        while request is not None:
            response = request.execute()
            for item in response[items]:
                db.table(table_name).insert(item)
            try:
                request = api_entity.list_next(previous_request=request, previous_response=response)
            except AttributeError:
                request = None
    except KeyError:
        pass

#discovery.build('compute', 'v1', credentials=Storage('creds.data').get()).networks().get(project=projectId, network=network.get('name')).execute()["subnetworks"]

def insert_subnet_entities(projectId, version="v1", prefix="", items="items"):
    product = "compute"
    categories = ["subnetworks"]
    table_name = "Subnet"
    db = TinyDB("project_dbs/" + object_id_to_directory_name(projectId) + ".json")
    service = discovery.build("compute", version, credentials=get_gcloud_creds())
    region_list = []
    request = service.regions().list(project=projectId)
    while request is not None:
        response = request.execute()
        if 'items' in response.keys():
            for region in response['items']:
                #print("Debug: %s" % (region))
                if 'description' in region.keys():
                    region_list.append(region['description'])
        else:
            print("Warning: no regions found for project '%s'" % (projectId))
        request = service.regions().list_next(previous_request=request, previous_response=response)
        
    subnet_count = 0
    for region in region_list:
        request = service.subnetworks().list(project=projectId, region=region)
        while request is not None:
            response = request.execute()
            
            if 'items' in response.keys():
                for subnetwork in response['items']:
                    #print("Debug: %s" % (subnetwork))
                    db.table(table_name).insert(subnetwork)
                    subnet_count = subnet_count + 1
            request = service.subnetworks().list_next(previous_request=request, previous_response=response)
    if subnet_count == 0:
        print("Warning: no subnets found for project '%s'" % (projectId))
