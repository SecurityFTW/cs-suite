from tinydb import TinyDB, Query
def add_finding(db,entity_table, entity_id, rule_title):
	finding_table = db.table('Finding')
	rule_table = db.table('Rule')
	finding_table.insert({
            	"entity": {"table":entity_table,"id":entity_id} ,
            	"rule": {"table":"rule","id":rule_table.search(Query().title==rule_title)[0].eid}
            	})
