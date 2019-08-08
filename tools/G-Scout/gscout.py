from googleapiclient import discovery
from oauth2client.client import ApplicationDefaultCredentialsError
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.file import Storage
from tinydb import TinyDB
import os
from core.fetch import fetch
from core.utility import object_id_to_directory_name
import logging
import urllib
import argparse
import shutil
import sys
import traceback

storage = Storage('creds.data')

from core.utility import get_gcloud_creds

logging.basicConfig(filename="log.txt")
logging.getLogger().setLevel(logging.ERROR)
# Silence some errors
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

project_db_name = "projects.json"
if os.path.isfile(project_db_name):
    try:
        os.remove(project_db_name)
    except Exception as e:
        msg = "could not remove the existing project database file '%s'. No further processing will take place. The error encountered was: %s" % (project_db_name, e)
        print("Error: %s" % (msg))
        logging.error(msg)
        sys.exit(1)
db = TinyDB(project_db_name)


def list_projects(project_or_org, specifier):
    service = discovery.build('cloudresourcemanager', 'v1', credentials=get_gcloud_creds())
    service2 = discovery.build('cloudresourcemanager', 'v2',credentials=get_gcloud_creds())
    # the filter criteria need double-quotes around them in case they contain special characters, like colons
    # this was not documented ANYWHERE that I could find when I made this change
    # but if the double-quotes are not there, you'll get errors like the following:
    
    # googleapiclient.errors.HttpError: <HttpError 400 when requesting https://cloudresourcemanager.googleapis.com/v1/projects?filter=id%3Adatadog%3Aproject&alt=json 
    # returned "Request contains an invalid argument.">
    
    # HttpError 400 when requesting https://cloudresourcemanager.googleapis.com/v1/projects?filter=id%3Adatadog%3Aproject&alt=json 
    # returned "field [query] has issue [Invalid filter query: resourceType="cloudresourcemanager.projects" AND (projectId = datadog:project)]"
    
    if project_or_org == "organization":
        child = service2.folders().list(parent='organizations/%s' % specifier)
        child_response = child.execute()
        request = service.projects().list(filter='parent.id:"%s"' % specifier)
        if 'folders' in child_response.keys() :
            for folder in child_response['folders'] :
                list_projects("folder-id", folder['name'].strip(u'folders/'))
    elif project_or_org == "project-name":
        request = service.projects().list(filter='name:"%s"' % specifier)
    elif project_or_org == "project-id":
        request = service.projects().list(filter='id:"%s"' % specifier)
    elif project_or_org=="folder-id":
        child = service2.folders().list(parent='folders/%s' % specifier)
        child_response = child.execute()
        request = service.projects().list(filter='parent.id:%s' % specifier)
        if 'folders' in child_response.keys() :
            for folder in child_response['folders'] :
                list_projects("folder-id", folder['name'].strip(u'folders/'))
    else:
        raise Exception('Organization or Project not specified.')
    add_projects(request, service)
 
def add_projects(request, service):
    while request is not None:
        response = request.execute()
        if 'projects' in response.keys():
            for project in response['projects']:
                if (project['lifecycleState'] != "DELETE_REQUESTED"):
                    db.table('Project').insert(project)

        request = service.projects().list_next(previous_request=request,
                                               previous_response=response)


def fetch_all(project, overwrite_existing):
    continue_fetching = True
    project_db_dir = "project_dbs"
    if not os.path.isdir(project_db_dir):
        try:
            os.makedirs(project_db_dir)
        except Exception as e:
            msg = "could not make project database directory '%s'. No further processing will take place. The error encountered was: %s" % (project_db_dir, e)
            print("Error: %s" % (msg))
            logging.error(msg)
            continue_fetching = False
    if continue_fetching:
        project_output_dir = os.path.join("Report Output", object_id_to_directory_name(project['projectId']))
        make_project_output_dir = True
        # Don't overwrite existing output unless the user has requested to do so
        if os.path.isdir(project_output_dir):
            if overwrite_existing:
                msg = "overwriting existing data and output for project '%s'" % (project['projectId'])
                print("Warning: %s" % (msg))
                logging.warning(msg)
                # Delete any existing output files to avoid confusion
                try:
                    shutil.rmtree(project_output_dir)
                except Exception as e:
                    msg = "could not delete existing output directory '%s'. No further processing will take place. The error encountered was: %s" % (project_output_dir, e)
                    print("Error: %s" % (msg))
                    logging.error(msg)
                    continue_fetching = False
            else:
                msg = "there is an existing output directory for project '%s' ('%s'). Rerun with --overwrite to delete and recreate the content." % (project['projectId'], project_output_dir)
                print("Error: %s" % (msg))
                logging.error(msg)
                make_project_output_dir = False
                continue_fetching = False
        if make_project_output_dir:
            try:
                os.makedirs(project_output_dir)
            except Exception as e:
                msg = "could not make project output directory '%s'. No further processing will take place. The error encountered was: %s" % (project_output_dir, e)
                print("Error: %s" % (msg))
                logging.error(msg)
                continue_fetching = False
    if continue_fetching:
    #    fetch(project['projectId'])
        try:
            fetch(project['projectId'])
        except Exception as e:
            msg = "could not fetch project '%s'. The error encountered was: %s%s%sStack trace:%s%s" % (project['projectId'], e, os.linesep, os.linesep, os.linesep, traceback.format_exc())
            print("Error: %s" % (msg))
            logging.exception(msg)

def main():
    # configure command line parameters
    parser = argparse.ArgumentParser(description='Google Cloud Platform Security Tool')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite existing output for the same projects')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--project-name', '-p-name', help='Project name to scan')
    group.add_argument('--project-id', '-p-id', help='Project id to scan')
    group.add_argument('--organization', '-o', help='Organization id to scan')
    group.add_argument('--folder-id', '-f-id', help='Folder id to scan')
    args = parser.parse_args()

    output_dir = "Report Output"
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir)
        except Exception as e:
            msg = "could not make output directory '%s'. The error encountered was: %s%s%sStack trace:%s%s" % (output_dir, e, os.linesep, os.linesep, os.linesep, traceback.format_exc())
            print("Error: %s" % (msg))
            logging.exception(msg)
    try:
        if args.project_name :
            list_projects(project_or_org='project-name', specifier=args.project_name)
        elif args.project_id :
            list_projects(project_or_org='project-id', specifier=args.project_id)
        elif args.folder_id :
            list_projects(project_or_org='folder-id', specifier=args.folder_id)
        else:
            list_projects(project_or_org='organization', specifier=args.organization)
    except (HttpAccessTokenRefreshError, ApplicationDefaultCredentialsError):
        from core import config
        list_projects(project_or_org='project' if args.project else 'organization',
                      specifier=args.project if args.project else args.organization)

    for project in db.table("Project").all():
        print("Scouting ", project['projectId'])
        fetch_all(project, args.overwrite)


if __name__ == "__main__":
    main()