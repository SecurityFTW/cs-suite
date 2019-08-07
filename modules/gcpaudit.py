from __future__ import print_function
import subprocess
import os
import time
import webbrowser
import json
from modules import logger

log = logger.get()

timestmp = time.strftime("%Y%m%d-%H%M%S")

def gcp_audit(project_name):
    """ This function just calls the G-Scout to Audit GCP """
    subprocess.call(['mkdir', '-p', 'reports/GCP/%s/%s' % (project_name, timestmp)])
    print ("Starting GCP Audit")
    subprocess.call(['python', 'gscout.py', '--overwrite', '--project-id', project_name], cwd='tools/G-Scout')
    if os.path.exists("tools/G-Scout/Report Output/%s" % (project_name)):
        log.info("REPORT FOUND PROCESSING INTO LOG")
        report = "tools/G-Scout/Report Output/%s/reports.json" % (project_name)
        with open(report) as json_file:
            report = json.load(json_file)
            for i in report:
                log.info("gcp final report", extra=i)
        subprocess.check_output(['mv tools/G-Scout/Report\ Output/%s/Findings/* reports/GCP/%s/%s/' % (project_name, project_name, timestmp)], shell=True)
        subprocess.check_output(['mv tools/G-Scout/Report\ Output/%s/Information/* reports/GCP/%s/%s/' % (project_name, project_name, timestmp)], shell=True)

        # subprocess.check_output(['rm -rf tools/G-Scout/Report\ Output/%s' % (project_name)], shell=True)
        webbrowser.open('file://' + os.path.realpath("./reports/GCP/%s/%s/All Ports Open to All.html") % (project_name, timestmp))
        fin = os.path.realpath("./reports/GCP/%s/%s/All\ Ports\ Open\ to\ All.html") % (project_name, timestmp)
        print ("THE FINAL REPORT IS LOCATED AT -------->  %s" % (fin))

