#/usr/bin/env python3
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, Identity, ExternalReference)
import uuid
import csv
from dateutil.parser import parse as parse_date
from datetime import datetime
import json
import gzip

def gen_uuid(data_type, data):
    return "%s--%s" % (data_type, uuid.uuid5(uuid.NAMESPACE_URL, data))

def as_zulu(date):
    return date.strftime('%Y-%m-%dT%H:%M:%SZ')


def calculate(iocs):
    tags_counter = 0
    identities_names = []
    for ioc in iocs:
        identities_names.append(ioc["user"])
        tags_counter += len(ioc["tags"])
    identities_names = list(set(identities_names))
    identities_counter = len(identities_names)
    identities_list = []
    identities = {}
    for identity in identities_names:
        iid = gen_uuid("identity", identity)
        tmp = Identity(id=gen_uuid("identity", identity), created=as_zulu(datetime.now()), modified=as_zulu(datetime.now()), spec_version="2.1", name=identity, identity_class="individual", contact_information=("https://x.com/%s" % identity))
        identities[identity] = tmp
        identities_list.append(tmp)

    indicators = []
    for ioc in iocs:
        iid = gen_uuid("indicator", ioc["value"])
        pattern = ""
        if ioc["type"] == "md5":
            pattern = "[file:hashes.MD5 = '%s']" % ioc["value"]
        elif ioc["type"] == "sha256":
            pattern = "[file:hashes.'SHA-256' = '%s']" % ioc["value"]
        elif ioc["type"] == "ip":
            pattern = "[ipv4-addr:value = '%s']" % ioc["value"]
        elif ioc["type"] == "domain":
            pattern = "[domain-name:value = '%s']" % ioc["value"]
        elif ioc["type"] == "url":
            pattern = "[url:value = '%s']" % ioc["value"]
        created_by_ref = identities[ioc["user"]].id
        if len(ioc["tags"]) > 0:
            indicators.append(
                    Indicator(
                        id=iid,
                        created=ioc["date"],
                        modified=ioc["date"],
                        spec_version="2.1",
                        pattern=pattern,
                        pattern_type="stix",
                        valid_from=as_zulu(datetime.now()),
                        created_by_ref=created_by_ref,
                        labels=ioc["tags"],
                        external_references=[ExternalReference(source_name="x.com", url=ioc["tweet"])]
                    )
                )
        else:
            indicators.append(
                    Indicator(
                        id=iid,
                        created=ioc["date"],
                        modified=ioc["date"],
                        spec_version="2.1",
                        pattern=pattern,
                        pattern_type="stix",
                        valid_from=as_zulu(datetime.now()),
                        created_by_ref=created_by_ref,
                        external_references=[ExternalReference(source_name="x.com", url=ioc["tweet"])]
                    )
                )
    
    objects = []
    objects.extend(identities_list)
    objects.extend(indicators)
    bundle = Bundle(objects=objects)
    tmp = json.dumps(json.loads(bundle.serialize()))
    return len(iocs), len(json.dumps(json.loads(bundle.serialize()), indent=3)), len(tmp), len(gzip.compress(tmp.encode())), tags_counter, identities_counter

if __name__ == "__main__":
    iocs = []
    with open("parsed_year_iocs.json", "r") as f:
        iocs = json.load(f)
    for ioc in iocs:
        ioc["date"] = as_zulu(parse_date(ioc["date"]))
    for i in range(0, len(iocs), 4):
        tmp = calculate(iocs[:i])
        print("%s, %s, %s, %s, %s, %s" % (tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]))
