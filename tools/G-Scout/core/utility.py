#!/usr/bin/env python

import re
import os

from oauth2client.client import GoogleCredentials

# GCP object IDs, names, etc., may contain characters which are not valid in directory names.
# e.g. myproject:part2
def object_id_to_directory_name(object_id):
	rex = re.compile(r"[^a-z0-9_\-\.()]", re.IGNORECASE)
	return rex.sub("_", object_id)
	
def get_gcloud_creds():
	base_script_directory = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
	keyfile_path = os.path.join(base_script_directory, 'keyfile.json')
	if os.path.isfile(keyfile_path):
		os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = keyfile_path
	creds = GoogleCredentials.get_application_default()
	return creds
