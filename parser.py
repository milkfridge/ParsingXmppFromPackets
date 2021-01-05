import json
from lxml import etree

with open(r'C:\path\source.json') as f:
    jdata = json.load(f)
    for item in jdata:
        if "data" not in item["_source"]["layers"]:
            continue
        hex_str = (item["_source"]["layers"]["data"])
        clean_str = bytearray.fromhex(hex_str[0]).decode()  # Decode hex
        clean_str = clean_str.replace('\n','')
        clean_str = clean_str.replace('\r','')
        clean_str = clean_str.replace('db:','')
        ts =  item["_source"]["layers"]["frame.time"][0] ## save timestamp to variable
        src_ip = item["_source"]["layers"]["ip.src"][0] ## save source IP to variable

        toServerList, fromServerList, toList, fromList = [], [], [], []  # Prepare lists for these items found in XML
        jid = ""
        status = ""

        ## Parse XML
        parser = etree.XMLParser(recover=True)
        root = etree.fromstring("<xml>"+clean_str+"</xml>", parser=parser)

        for child in root:
            if (child.tag == "presence"):
                fr = child.attrib['from']
                if fr not in fromList:
                    fromList.append(fr)
                to = child.attrib['to']
                if to not in toList:
                    toList.append(to)
                for c2 in root.find('.//presence'):
                    if(c2.tag == "status"):
                        status = (c2.text).encode('utf-8')                        
            elif (child.tag == "message"):
                # Type == message
                for c2 in root.find('.//message'):
                    # Does this message contain Addresses?
                    if(c2.tag == "{http://jabber.org/protocol/address}addresses"):
                        for c3 in root.find('.//message/{http://jabber.org/protocol/address}addresses'):
                            jid = c3.attrib['jid']  # Message::Address::JID
                fr = child.attrib['from']
                if fr not in fromList:
                    fromList.append(fr)
                to = child.attrib['to']
                if to not in toList:
                    toList.append(to)
            elif (child.tag == "iq"):
                fr = child.attrib['from']
                if fr not in fromServerList:
                    fromServerList.append(fr)
                to = child.attrib['to']
                if to not in toServerList:
                    toServerList.append(to)
            elif (child.tag == "verify"):
                fr = child.attrib['from']
                if fr not in fromServerList:
                    fromServerList.append(fr)
                to = child.attrib['to']
                if to not in toServerList:
                    toServerList.append(to)
            elif (child.tag == "{http://etherx.jabber.org/streams}stream"):
                fr = child.attrib['from']
                if fr not in fromServerList:
                    fromServerList.append(fr)
                to = child.attrib['to']
                if to not in toServerList:
                    toServerList.append(to)
            elif (child.tag == "result"):
                fr = child.attrib['from']
                if fr not in fromServerList:
                    fromServerList.append(fr)
                to = child.attrib['to']
                if to not in toServerList:
                    toServerList.append(to)            
        # Print out the data we pulled from each packet onto a parse-able line
        print('|'.join([ts, src_ip, jid, str(status), ','.join(toServerList), ','.join(fromServerList), ','.join(toList), ','.join(fromList)]))
