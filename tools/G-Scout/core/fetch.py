import logging
import sys

logging.basicConfig(filename="log.txt")
from tinydb import TinyDB

from core.utility import object_id_to_directory_name
from core.utility import get_gcloud_creds

def fetch(projectId):
    db = TinyDB("project_dbs/" + object_id_to_directory_name(projectId) + ".json")
    from rules import rules
    from display_results import display_results
    from insert_entity import insert_entity, insert_subnet_entities
    from categories.firewalls import add_affected_instances, add_network_rules
    from categories.roles import insert_roles
    import categories.compute_engine
    from categories.service_account_keys import insert_service_account_keys
    import categories.service_accounts
    import categories.service_account_IAM_policy
    import categories.buckets
    from categories.addresses import insert_addresses
    
    # initialize the entity database tables for the project, so that running G-Scout more than once against the same project doesn't result in duplicated data
    # I did this as an explicit list of tables so that if future versions store data that should persist between runs, those aren't deleted.
    entity_table_names = ["Address", "Bucket", "Cluster", "Compute Engine", "Finding", "Firewall", "Instance Template", "Network", "Pub/Sub", "Role", "Rule", "Service Account", "Snapshot", "SQL Instance", "Subnet", "Topics"]
    for tn in entity_table_names:
        db.purge_table(tn)

    try:
        insert_entity(projectId, "compute", ["networks"], "Network")
    except Exception as e:
        print("Failed to fetch networks.")
        logging.exception("networks")

    try:
        insert_subnet_entities(projectId)
    except Exception as e:
        print("Failed to fetch subnets: %s" % (e))
        logging.exception("subnets: %s" % (e))
        
    try:
        insert_entity(projectId, "compute", ["firewalls"], "Firewall")
    except Exception as e:
        print("Failed to fetch firewalls.")
        logging.exception("firewalls")

    try:
        insert_roles(projectId, db)
    except Exception as e:
        print("Failed to fetch roles.")
        logging.exception("roles")

    try:
        insert_entity(projectId, "iam", ["projects","serviceAccounts"], "Service Account", "v1", "projects/", "accounts")
        categories.service_accounts.insert_sa_roles(projectId, db)
    except Exception as e:
        print("Failed to fetch service accounts.")
        logging.exception("service accounts")

    try:
        insert_service_account_keys(projectId, db)
    except Exception as e:
        print("Failed to fetch service account keys.")
        logging.exception("service account keys")

    try:
        categories.service_account_IAM_policy.insert_sa_policies(projectId, db)
    except Exception as e:
        print("Failed to fetch service account IAM policies.")
        logging.exception("service account IAM policies")

    try:
        insert_entity(projectId, "storage", ["buckets"], "Bucket")
    except Exception as e:
        print("Failed to fetch buckets.")
        logging.exception("buckets")

    try:
        categories.buckets.insert_acls(db)
        categories.buckets.insert_defacls(db)
    except Exception as e:
        print("Failed to fetch bucket ACLS/Default ACLS: %s" % (e))
        logging.exception("bucket ACLS/Default ACLS: %s" % (e))

    try:
        categories.compute_engine.insert_instances(projectId, db)
        insert_entity(projectId, "compute", ["instanceTemplates"], "Instance Template")
        categories.compute_engine.insert_instance_groups(projectId, db)
    except Exception as e:
        print("Failed to fetch compute engine instances.")
        logging.exception("compute engine instances")
    try:
        categories.compute_engine.add_member_instances(projectId, db)
    except Exception as e:
        print("Failed add member instances to compute engine instances.")
        logging.exception("compute engine instances")
    try:
        add_network_rules(projectId, db)
        add_affected_instances(projectId, db)
    except Exception as e:
        print("Failed to display instances/rules with instances.")  
    try:
        insert_addresses(projectId, db)
    except Exception as e:
        print("Failed to fetch IP addresses")
        print(e)
    try:
        insert_entity(projectId, "compute", ["snapshots"], "Snapshot")
    except Exception as e:
        print("Failed to fetch instance snapshots.")
        logging.exception("snapshots")

    try:
        insert_entity(projectId, "sqladmin", ["instances"], "SQL Instance", "v1beta4")
    except Exception as e:
        print("Failed to fetch SQL instances.")
        logging.exception("SQL instances")

    try:
        insert_entity(projectId, "pubsub", ["projects", "topics"], "Topics", "v1", "projects/", "topics")
        insert_entity(projectId, "pubsub", ["projects", "subscriptions"], "Pub/Sub", "v1", "projects/", "subscriptions")
    except Exception as e:
        print("Failed to fetch Pub/Sub topics/subscriptions.")
        logging.exception("pub/sub")
    try:
        insert_entity(projectId, "container", ['projects','locations','clusters'],"Cluster","v1beta1","projects/","clusters","/locations/-")
    except:
        print("Failed to fetch clusters")
        logging.exception("GKE")
    try:
        rules(projectId)
    except Exception as e:
        logging.exception(e)
    display_results(db, projectId)
