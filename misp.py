#/usr/bin/env python3
import json
import gzip
import uuid

def calculate(iocs):
    tags_map = {}
    uniq_tags_counter = 0
    for i in iocs:
        for t in i["tags"]:
            if t not in tags_map:
                tags_map[t] = {"id": str(uniq_tags_counter), "name": t, "colour": "#87ea43", "exportable": True, "user_id": "0", "hide_tag": False, "numerical_value": None, "is_galaxy": False, "is_custom_galaxy": False, "local_only": False, "local": False, "relationship_type": None}
                uniq_tags_counter += 1
    attributes = []
    attributes_counter = 0
    tags_counter = 0
    for i in iocs:
        attributes.append({"id": str(attributes_counter),"type": i["type"], "category": "Payload delivery" if i["type"] in ["md5", "sha256"] else "Network Activity", "to_ids": True, "uuid": str(uuid.uuid4()), "event_id": "1", "distribution": "1", "timestamp": "1742853555", "comment": "", "sharing_group_id": "0", "deleted": False, "disable_correlation": False, "object_id": "0", "object_relation": None, "first_seen": None, "last_seen": None, "value": i["value"], "Galaxy": [], "ShadowAttribute": [], "Tag": [tags_map[t] for t in i["tags"]]})
        tags_counter += len(i["tags"])
        attributes_counter += 1
    result = {"response": [{"Event": {"id": "1", "orgc_id": "1", "org_id": "1", "date": "2025-03-24", "threat_level_id": "4", "info": "TweetFeed IoCs - 2025-03-24", "published": True, "uuid": "1fea0bf5-1e6b-4be9-b4cb-2f9704a80f89", "attribute_count": len(attributes), "analysis": "1", "timestamp": "1742853555", "distribution": "1", "proposal_email_lock": False, "locked": False, "publish_timestamp": "1742853555", "sharing_group_id": "0", "disable_correlation": False, "extends_uuid": "", "protected": None, "event_creator_email": "admin@admin.test", "Org": {"id": "1", "name": "ORGNAME", "uuid": "19997cb7-160f-4315-bbb1-0c39450c5ba8", "local": True}, "Orgc": {"id": "1", "name": "ORGNAME", "uuid": "19997cb7-160f-4315-bbb1-0c39450c5ba8", "local": True}, "Attribute": attributes}}]}
    return len(iocs), len(json.dumps(result, indent=3)), len(json.dumps(result)), len(gzip.compress(json.dumps(result).encode())), tags_counter

if __name__ == "__main__":
    iocs = []
    with open("parsed_year_iocs.json", "r") as f:
        iocs = json.load(f)
    for i in range(0, len(iocs), 4):
        tmp = calculate(iocs[:i])
        print("%s, %s, %s, %s, %s" % (tmp[0], tmp[1], tmp[2], tmp[3], tmp[4]))
