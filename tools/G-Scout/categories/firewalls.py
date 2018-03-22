from googleapiclient import discovery
from tinydb import TinyDB, Query

def add_network_rules(projectId, db):
	for firewall in db.table('Firewall').all():
		try:
			if not firewall.get('sourceRanges'):
				firewall['sourceRanges'] = firewall['sourceTags']
		except KeyError:
				firewall['sourceRanges'] = "N/A"
		try:
			if not firewall.get('destinationRanges'):
				firewall['destinationRanges'] = firewall['destinationTags']
		except KeyError:
				firewall['destinationRanges'] = "N/A"
		db.table('Network').update(
					add_rule({
						"name":firewall['name'], 
						"allowed":firewall['allowed'],
						"sourceRanges":firewall['sourceRanges'],
						"destinationRanges":firewall['destinationRanges'],
						"tags":firewall.get('targetTags')
						}),
					eids=[db.table('Network').get(
						Query().selfLink==firewall['network']
						).eid])

def add_affected_instances(projectId, db):
	for firewall in db.table('Firewall').all():
		try:
			for instance in db.table('Network').get(Query().selfLink==firewall['network'])['members']:
				try:
					if not firewall.get('targetTags'):
						db.table('Firewall').update(
						add_instance({
						"kind":instance['kind'],
						"selfLink":instance['selfLink'],
#						"tags":instance.get('tags'),
						"name":instance['name']
						}),eids=[firewall.eid])
					try:
						for tag in instance.get('tags'):
							if tag in firewall.get('targetTags'):
								db.table('Firewall').update(
							add_instance({
							"kind":instance['kind'],
							"selfLink":instance['selfLink'],
#							"tags":instance.get('tags'),
							"name":instance['name']
							}),eids=[firewall.eid])
					except TypeError:
						continue
				except KeyError:
					continue
		except KeyError:
			continue

# Function to pass Tinydb for the update query
def add_instance(instance):
	def transform(element):
		try:
			element['affectedInstances'].append(instance)
		except KeyError:
			element['affectedInstances'] = [instance]
	return transform

def add_rule(rule):
	def transform(element):
		try:
			element['firewallRules'].append(rule)
		except KeyError:
			element['firewallRules'] = [rule]
	return transform

def port_in_range(port,ranges):
	for range in ranges:
		if "-" in range:
			range_split = str.split(str(range),"-")
			if int(range_split[0]) <= int(port) <= int(range_split[1]):
				return True
		elif int(port) == int(range):
			return True

def test_allowed(rule,IPProtocol,ports):
	for allow in rule['allowed']:
		if not allow['IPProtocol'] == IPProtocol:
			continue
		for port in ports:
			if allow.get('ports') and port_in_range(port,allow['ports']):
				return True
		if not allow.get('ports'):
			return True
