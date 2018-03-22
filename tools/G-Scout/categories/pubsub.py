from googleapiclient import discovery
from tinydb import TinyDB, Query
import add_finding
from insert_entity import insert_entity

db = TinyDB('entities.json')
from oauth2client.file import Storage
storage = Storage('creds.data')
service = discovery.build('pubsub', 'v1', credentials=storage.get())
request = service.projects().topics().list(project="projects/goat-sounds")
request = service.projects().subscriptions().list(project="projects/goat-sounds")
request = service.projects().subscriptions().getIamPolicy(resource="projects/goat-sounds/subscriptions/baaaa")
insert_entity("pubsub",["projects","topics"],"Topics","v1",{"project":"projects/"+projectId},"topics")
insert_entity("pubsub","subscriptions","Pub/Sub","v1",{"project":"projects/"+projectId},"subscriptions")