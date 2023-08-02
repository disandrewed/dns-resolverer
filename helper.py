from socket import *
import random
import sys


def queryMake(site, qtype):

        #create message byte array
    clientMessage = bytearray(2)

        #add dns query id
    queryID = random.randint(0, 100)
    clientMessage[0:2] = queryID.to_bytes(2, byteorder='big')

        #add header flags
    header = 0
    if len(site.encode('utf-8')) > 512:
        header = 1024
    clientMessage.extend(header.to_bytes(2, byteorder='big'))

        #add QCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    clientMessage.extend(0x0001.to_bytes(2, byteorder='big'))
    clientMessage.extend(0x0000.to_bytes(2, byteorder='big'))
    clientMessage.extend(0x0000.to_bytes(2, byteorder='big'))
    clientMessage.extend(0x0000.to_bytes(2, byteorder='big'))

        #add client question
    for s in site.split('.'):
        clientMessage.append(len(s))
        clientMessage.extend(bytes(s, 'utf-8'))
        
    if qtype == 'PTR':
        ad = '.in-addr.arpa'
        for s in ad.split('.'):
            clientMessage.append(len(s))
            clientMessage.extend(bytes(s, 'utf-8'))
    clientMessage.append(0)
        #add type and class
    
    if qtype == 'A':
        clientMessage.append(0)
        clientMessage.append(1)
    elif qtype == 'CNAME':
        clientMessage.append(0)
        clientMessage.append(5)
    elif qtype == 'MX':
        clientMessage.append(0)
        clientMessage.append(15)
    elif qtype == 'NS':
        clientMessage.append(0)
        clientMessage.append(2)
    elif qtype == 'PTR':
        clientMessage.append(0)
        clientMessage.append(12)
    
    clientMessage.append(0)
    clientMessage.append(1)

    return clientMessage

def queryNumToStr(qtype):
    if qtype == 1:
        return 'A'
    elif qtype == 5:
        return 'CNAME'
    elif qtype == 15:
        return 'MX'
    elif qtype == 2:
        return 'NS'
    elif qtype == 12:
        return 'PTR'
    return 'A'