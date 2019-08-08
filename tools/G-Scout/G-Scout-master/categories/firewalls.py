from tinydb import Query


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
                "name": firewall['name'],
                "allowed": firewall.get('allowed'),
                "sourceRanges": firewall['sourceRanges'],
                "destinationRanges": firewall['destinationRanges'],
                "tags": firewall.get('targetTags')
            }),
            eids=[db.table('Network').get(
                Query().selfLink == firewall['network']
            ).eid])


def add_affected_instances(projectId, db):
    for firewall in db.table('Firewall').all():
        try:
            for instance in db.table('Network').get(Query().selfLink == firewall['network'])['members']:
                try:
                    if not firewall.get('targetTags'):
                        db.table('Firewall').update(
                            add_instance({
                                "kind": instance['kind'],
                                "selfLink": instance['selfLink'],
                                #						"tags":instance.get('tags'),
                                "name": instance['name']
                            }), eids=[firewall.eid])
                    try:
                        for tag in instance.get('tags'):
                            if tag in firewall.get('targetTags'):
                                db.table('Firewall').update(
                                    add_instance({
                                        "kind": instance['kind'],
                                        "selfLink": instance['selfLink'],
                                        #							"tags":instance.get('tags'),
                                        "name": instance['name']
                                    }), eids=[firewall.eid])
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


def port_in_range(port, ranges):
    for range in ranges:
        if "-" in range:
            range_split = str.split(str(range), "-")
            if int(range_split[0]) <= int(port) <= int(range_split[1]):
                return True
        elif int(port) == int(range):
            return True


def test_allowed(rule, IPProtocol, ports):
    for allow in rule['allowed']:
        if not allow['IPProtocol'] == IPProtocol:
            continue
        for port in ports:
            if allow.get('ports') and port_in_range(port, allow['ports']):
                return True
        if not allow.get('ports'):
            return True
            
#It's messy but it seems to work. Will tell you whether another firewall rule overrides the given one
#Hopefully there will soon be an API endpoint to replace this. Not being used by default.
from ipaddress import IPv4Network
def overriden(firewall):
    priority = firewall['priority']
    for comparison_rule in db.table("Firewall").all():
        if comparison_rule['priority'] < priority \
        or (comparison_rule['priority'] == priority and firewall.get("allowed")):
            allow_or_deny = "allowed" if firewall.get("allowed") else "denied"
            if allow_or_deny not in comparison_rule:
                if tags_encompassed(firewall, comparison_rule):
                    if firewall['direction'] == comparison_rule['direction']:
                        if allow_or_deny == "allowed":
                            opposite = "denied"
                        else:
                            opposite = "allowed"
                        if ports_fully_encompassed(firewall[allow_or_deny], comparison_rule[opposite]):
                            higher_priority_cidr = comparison_rule.get("sourceRanges") or comparison_rule.get("destinationRanges")
                            lower_priority_cidr = firewall.get("sourceRanges") or firewall.get("destinationRanges")
                            if ips_fully_encompassed(lower_priority_cidr, higher_priority_cidr):
                                #overriden by comparison_rule
                                return True                         
    return False

def ports_fully_encompassed(lower_priority_ports, higher_priority_ports):
    ledger = []
    for lower in lower_priority_ports:
        for higher in higher_priority_ports:
            if lower['IPProtocol'] == higher['IPProtocol']:
                for lower_port in lower['ports']:
                    encompassed = False
                    for higher_port in higher['ports']:
                        if range_fully_encompassed(lower_port, higher_port):
                            encompassed = True
                    ledger.append(encompassed)
    if False in ledger:
        return False
    else:
        return True

def range_fully_encompassed(lower_range_or_num, higher_range_or_num):
    if "-" not in lower_range_or_num and "-" not in higher_range_or_num and lower_range_or_num != higher_range_or_num:
        return False
    if "-" in lower_range_or_num and "-" not in higher_range_or_num:
        return False
    if "-" in higher_range_or_num and "-" not in lower_range_or_num:
        ends = higher_range_or_num.split("-")
        if int(lower_range_or_num) < int(ends[0]) or int(lower_range_or_num) > int(ends[1]):
            return False
    if "-" in lower_range_or_num and "-" in higher_range_or_num:
        lower_ends = lower_range_or_num.split("-")
        higher_ends = higher_range_or_num.split("-")
        if int(lower_ends[0]) < int(higher_ends[0]) or int(lower_ends[1]) > int(higher_ends[1]):
            return False
    return True

import ipaddress
def ips_fully_encompassed(lower_priority_cidr, higher_priority_cidr):
    ledger = []
    if lower_priority_cidr and not higher_priority_cidr:
        return False
    if higher_priority_cidr and not lower_priority_cidr:
        return False
    if not lower_priority_cidr and not higher_priority_cidr:
        return True
    for lower_cidr in lower_priority_cidr:
        encompassed = False
        for higher_cidr in higher_priority_cidr:
            if IPv4Network(lower_cidr).subnet_of(IPv4Network(higher_cidr)):
                encompassed = True
        ledger.append(encompassed)
    if False in ledger:
        return False
    else:
        return True

def tags_encompassed(firewall, comparison_rule):
    if comparison_rule.get('targetTags') and not firewall.get('targetTags'):
        return False
    if not comparison_rule.get('targetTags') and firewall.get('targetTags'):
        return True
    if comparison_rule.get('targetTags') and firewall.get('targetTags'):
        if set(firewall['targetTags']).issubset(set(comparison_rule['targetTags'])):
            return True
    if comparison_rule.get('sourceTags') and not firewall.get('sourceTags'):
        return False
    if not comparison_rule.get('sourceTags') and firewall.get('sourceTags'):
        return True
    if comparison_rule.get('sourceTags') and firewall.get('sourceTags'):
        if set(firewall['sourceTags']).issubset(set(comparison_rule['sourceTags'])):
            return True
    return False