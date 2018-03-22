from tinydb import TinyDB, Query
from jinja2 import Template, Environment, PackageLoader
import json
import logging
logging.basicConfig(filename="log.txt")
env = Environment(loader=PackageLoader('assets', 'templates'),extensions=['jinja2.ext.do'])
def pretty_print(dict):
        try:
                return json.dumps(dict, sort_keys=True, indent=4, separators=(',', ': '))
        except:
                return dict
env.filters['pretty_print'] = pretty_print
def display_results(db, projectId):
	def add_to_dropdown(category):
		rules = set([])
		for rule in db.table("Rule").search(Query().category==category):
			if db.table('Finding').search(Query().rule.id==rule.eid):
				rules.add(rule['title'])
		return rules

	def generate_entities_page(category, header, fields,dropdowns):
		records = db.table(category).all()
		template = env.get_template("entity_template.html")
		file = open("Report Output/" + projectId + "/" + category  + "s.html", "w+")
		file.write(template.render(**{"records":records,"dropdowns":dropdowns,"header":header,"fields":fields}))
		file.close()

	def generate_findings_page(category, header, fields,dropdowns):
		try:
			for rule_title in dropdowns[category]:
				rule = db.table("Rule").get(Query().title==rule_title)
				findings = db.table("Finding").search(Query().rule.id==rule.eid)
				findings = [db.table(finding['entity']['table']).get(eid=finding['entity']['id']) for finding in findings]
				template = env.get_template("finding_template.html")
				file = open("Report Output/" + projectId + "/" + rule_title + ".html", "w+")
				file.write(template.render(**{"records":findings,"dropdowns":dropdowns,"header":header,"fields":fields, "text":rule['title']}))
				file.close()
		except KeyError:
			print("No " + category + " rules in rule.py")


	#The following would place only categories with findings in the navbar
	# for finding in findings_table.all():
	#         categories.add(finding['entity']['table'])
	# for category in categories:
	#         dropdowns[category] = add_to_dropdown(category)

	#The header is the name of the field that will be bolded
	def generate_pages(category,header,fields,dropdowns):
		try:
			generate_findings_page(category,header,fields,dropdowns)
		except Exception as e:
			logging.exception("findings page")
		try:
			generate_entities_page(category,header,fields,dropdowns)
		except Exception as e:
			logging.exception("entities page")

	#Navbar dropdowns
	dropdowns = {}
	categories = set([])

	for rule in db.table("Rule").all():
		categories.add(rule['category'])
	for category in categories:
		dropdowns[category] = add_to_dropdown(category)
	generate_pages("Bucket","name",["name","location","storageClass","selfLink","acls","defacls"],dropdowns)
	generate_pages("Firewall","name",["network","sourceRanges","direction","destinationRanges","allowed","description","targetTags","affectedInstances"],dropdowns)
	generate_pages("Network","name",["firewallRules","members"],dropdowns)
	generate_pages("Role","role",["members"],dropdowns)
	generate_pages("Compute Engine","name", ["zone","key", "networkInterfaces","tags"],dropdowns)
	generate_pages("SQL Instance","selfLink", ["connectionName","databaseVersion",["settings","backupConfiguration"],["settings","ipConfiguration"]],dropdowns)
	generate_pages("Service Account","name", ["keys","iam_policies","uniqueId","roles"],dropdowns)

