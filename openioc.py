#/usr/bin/env python3
import json
import gzip
import bs4
import uuid

def calculate(iocs):
    result_string = """<?xml version="1.0" encoding="utf-8"?>""" + '\n' + """<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="009fd4f9-4f68-4e02-8a37-b3dcd5ed3e2b" last-modified="2025-03-24T10:00:50" xmlns="http://schemas.mandiant.com/2010/ioc"><short_description>Filtered indicator list</short_description><description>Filtered indicator list</description><keywords /><authored_by>ORGNAME</authored_by><authored_date>2025-03-24T10:00:50</authored_date><links /><definition><Indicator operator="OR" id="2b99279b-1e38-4d16-adcf-23b7fcc0d703">"""
    for ioc in iocs:
        ioc_string = """<IndicatorItem id=""" + ('"%s"' % uuid.uuid4()) + """ condition="is">"""
        if ioc["type"] == "ip":
            ioc_string += """<Context document="RouteEntryItem" search="RouteEntryItem/Destination" type="mir" />"""
            ioc_string += """<Content type="IP">""" + ioc["value"] +"</Content>"
        elif ioc["type"] == "url":
            ioc_string += """<Context document="UrlHistoryItem" search="UrlHistoryItem/URL" type="mir" />"""
            ioc_string += """<Content type="string">""" + ioc["value"] +"</Content>"
        elif ioc["type"] == "dns":
            ioc_string += """<Context document="Network" search="Network/DNS" type="mir" />"""
            ioc_string += """<Content type="string">""" + ioc["value"] +"</Content>"
        elif ioc["type"] == "md5":
            ioc_string += """<Context document="FileItem" search="FileItem/Md5sum" type="mir" />"""
            ioc_string += """<Content type="md5">""" + ioc["value"] +"</Content>"
        elif ioc["type"] == "sha256":
            ioc_string += """<Context document="FileItem" search="FileItem/Sha256sum" type="mir" />"""
            ioc_string += """<Content type="sha256">""" + ioc["value"] +"</Content>"
        ioc_string += """</IndicatorItem>"""
        result_string += ioc_string
    result_string += """</Indicator></definition></ioc>"""
    xml_p = bs4.BeautifulSoup(result_string, 'lxml')
    formatter = bs4.formatter.XMLFormatter(indent=3)
    pretty_xml = xml_p.prettify(formatter=formatter)
    return len(iocs), len(pretty_xml), len(result_string), len(gzip.compress(result_string.encode())) 

if __name__ == "__main__":
    iocs = []
    with open("parsed_year_iocs.json", "r") as f:
        iocs = json.load(f)
    for i in range(0, len(iocs), 4):
        tmp = calculate(iocs[:i])
        print("%s, %s, %s, %s" % (tmp[0], tmp[1], tmp[2], tmp[3]))
