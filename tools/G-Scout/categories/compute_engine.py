from googleapiclient import discovery
from tinydb import TinyDB, Query
from oauth2client.file import Storage
storage = Storage('creds.data')
service = discovery.build('compute', 'v1', credentials=storage.get())
instances = service.instances()
instanceGroups = service.instanceGroups()
instanceTemplates = service.instanceTemplates()
zones = service.zones()

def insert_instances(projectId, db):
	for zone in get_zones(projectId):
		request = service.instances().list(project=projectId,zone=zone)
		while request is not None:
			response = request.execute()
			if (response.get('items')):
				for instance in response['items']:
					db.table('Compute Engine').insert(instance)
			try:
				request = service.instances().list.next(previous_request=request, previous_response=response)	
			except AttributeError:
				request = None

def insert_instance_groups(projectId, db):
	request = instanceGroups.aggregatedList(project=projectId)
	try:
		while request is not None:
			response = request.execute()
			for region, group_list in response['items'].items():
				if "warning" not in group_list:
					for group in group_list['instanceGroups']:
						db.table('Instance Group').insert(group)
			request = instanceGroups.list_next(previous_request=request, previous_response=response)
	except KeyError:
		pass

def get_zones(projectId):
	results = []
	request = zones.list(project=projectId)
	response = request.execute()['items']
	for result in response:
		results.append(result['name'])
	return results

# Function to pass Tinydb for the update query
def add_member(member):
	def transform(element):
		try:
			element['members'].append(member)
		except KeyError:
			element['members'] = [member]
	return transform

def add_member_instances(projectId, db):
	for instance in db.table('Compute Engine').all():
		db.table('Network').update(
					add_member({
						"kind":instance['kind'],
						"selfLink":instance['selfLink'],
						"tags":instance.get('tags',{}).get('items'),
						"name":instance['name']
						}),
					eids=[db.table('Network').get(
						Query().selfLink==instance['networkInterfaces'][0]['network']
						).eid])

def add_member_instance_groups(projectId, db):
	for group in db.table('Instance Group').all():
		db.table('Network').update(
					add_member({
						"kind":group['kind'],
						"selfLink":group['selfLink'],
						"tags":group.get('tags',{}).get('items'),
						"name":group['name']
						}),
					eids=[db.table('Network').get(
						Query().selfLink==group['network']
						).eid])

def add_member_instance_templates(projectId, db):
	for template in db.table('Instance Template').all():
		db.table('Network').update(
					add_member({
						"kind":template['kind'],
						"selfLink":template['selfLink'],
						"tags":template.get('tags',{}).get('items'),
						"name":template['name']
						}),
					eids=[db.table('Network').get(
						Query().selfLink==template['properties']['networkInterfaces'][0]['network']
						).eid])
