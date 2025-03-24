#/usr/bin/env python3
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, Identity, ExternalReference)
import uuid
import csv
from dateutil.parser import parse as parse_date
from datetime import datetime
import json

def gen_uuid(data_type, data):
    return "%s--%s" % (data_type, uuid.uuid5(uuid.NAMESPACE_URL, data))

def as_zulu(date):
    return date.strftime('%Y-%m-%dT%H:%M:%SZ')

iocs = []
with open("iocs.csv", "r") as f:
    csvFile = csv.reader(f)
    for lines in csvFile:
        iocs.append({"time": as_zulu(parse_date(lines[0])), "reporter": lines[1], "type": lines[2], "data": lines[3], "tags": [e.strip() for e in lines[4].split()], "link": lines[5]})

identities_names = []
for ioc in iocs:
    identities_names.append(ioc["reporter"])
identities_names = list(set(identities_names))
identities_list = []
identities = {}
for identity in identities_names:
    iid = gen_uuid("identity", identity)
    tmp = Identity(id=gen_uuid("identity", identity), created=as_zulu(datetime.now()), modified=as_zulu(datetime.now()), spec_version="2.1", name=identity, identity_class="individual", contact_information=("https://x.com/%s" % identity))
    identities[identity] = tmp
    identities_list.append(tmp)

indicators = []
for ioc in iocs:
    iid = gen_uuid("indicator", ioc["data"])
    pattern = ""
    if ioc["type"] == "md5":
        pattern = "[file:hashes.MD5 = '%s']" % ioc["data"]
    elif ioc["type"] == "ip":
        pattern = "[ipv4-addr:value = '%s']" % ioc["data"]
    elif ioc["type"] == "domain":
        pattern = "[domain-name:value = '%s']" % ioc["data"]
    elif ioc["type"] == "url":
        pattern = "[url:value = '%s']" % ioc["data"]
    created_by_ref = identities[ioc["reporter"]].id
    if len(ioc["tags"]) > 0:
        indicators.append(Indicator(id=iid, created=ioc["time"], modified=ioc["time"], spec_version="2.1", pattern=pattern, pattern_type="stix", valid_from=as_zulu(datetime.now()), created_by_ref=created_by_ref, labels=ioc["tags"], external_references=[ExternalReference(source_name="x.com", url=ioc["link"])]))
    else:
        indicators.append(Indicator(id=iid, created=ioc["time"], modified=ioc["time"], spec_version="2.1", pattern=pattern, pattern_type="stix", valid_from=as_zulu(datetime.now()), created_by_ref=created_by_ref, external_references=[ExternalReference(source_name="x.com", url=ioc["link"])]))

objects = []
objects.extend(identities_list)
objects.extend(indicators)
bundle = Bundle(objects=objects)
print(json.dumps(json.loads(bundle.serialize()), indent=3))
