import json
import os
import logging
from jinja2 import Environment, PackageLoader
from tinydb import TinyDB, Query

logging.basicConfig(filename="log.txt")
env = Environment(loader=PackageLoader('assets', 'templates'), extensions=['jinja2.ext.do'])

def pretty_print(dict):
    try:
        return json.dumps(dict, sort_keys=True, indent=4, separators=(',', ': '))
    except:
        return dict

env.filters['pretty_print'] = pretty_print

def generate_cross_project_page(header, fields, dropdowns, findings, rule_title):
    template = env.get_template("finding_template.html")
    output_dir = "Report Output/cross-project/rules/"
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir)
        except Exception as e:
            msg = "could not make output directory '%s'. The error encountered was: %s%s%sStack trace:%s%s" % (output_dir, e, os.linesep, os.linesep, os.linesep, traceback.format_exc())
            print("Error: %s" % (msg))
            logging.exception(msg)

    file = open("Report Output/cross-project/rules/" + rule_title + ".html", "w+")
    file.write(template.render(
        **{"records": findings, "dropdowns": dropdowns, "header": header, "fields": fields,
            "text": rule_title}))
    file.close()

rules = ["Primitive Roles in Use","Bucket Logging Not Enabled"] #change to any list of rules
def x_project_findings(rules):
    db = TinyDB("projects.json")
    project_list = []
    for project in db.table("Project").all():
        project_list.append(project['projectId'])

    for rule_title in rules:
        findings = []
        entity = {}
        for projectId in project_list:
            project_db = TinyDB("project_dbs/" + projectId + ".json")
            res = project_db.table("Rule").get(Query().title == rule_title)
            for finding in project_db.table("Finding").all():
                if finding['rule']['id'] == res.eid:
                    entity = project_db.table(finding['entity']['table']).get(doc_id = finding['entity']['id'])
                    entity['projectId'] = projectId
                    findings.append(entity)
        generate_cross_project_page("", entity.keys(), {}, findings, rule_title)
x_project_findings(rules)
# This is just to get numbers of resources
# for projectId in project_list:
#     project_db = TinyDB("project_dbs/" + projectId + ".json")
#     print(len(project_db.table("Bucket").all()))
