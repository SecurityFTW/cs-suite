from tinydb import Query


def add_finding(db, entity_table, entity_id, rule_title):
    finding_table = db.table('Finding')
    rule_table = db.table('Rule')
    rule_id = ""
    try:
        rule_id_list = rule_table.search(Query().title == rule_title)
        if rule_id_list:
            if len(rule_id_list) > 0:
                rule_id_entry = rule_id_list[0]
                rule_id = rule_id_entry.eid
            else:
                print("Error: could not get rule ID for '%s' / '%s'" % (entity_id, rule_title))
    except Exception as e:
        print("Error adding finding: %s" % (e))
            
    finding_table.insert({
        "entity": {"table": entity_table, "id": entity_id},
        "rule": {"table": "rule", "id": rule_id}
    })
