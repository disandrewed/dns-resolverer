from socket import *
from socket import gethostbyname, gaierror
import sys
import struct
import helper
import copy

#get flags and put into dictionary
def getFlags(dns_response):
    id, misc, qdcount, ancount, nscount, arcount = struct.unpack_from('!6H', dns_response)

    aa = (misc & 0x0400) != 0
    rcode = misc & 0xF
    result = {
        "id": id,
        "is_authoritative": aa,
        "response_code": rcode,
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount
    }
    return result


def decodeString(dns_response, begin):
    s = ''
    start = begin

    while True:
        #print(start)
        length, = struct.unpack_from("!B", dns_response, start)
        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", dns_response, start)
            start += 2
            s1, l1 = decodeString(dns_response, pointer & 0x3FFF)
            return s + s1, start - begin
        start += 1
        if length == 0:
            break
        st = struct.unpack_from("!%ds" % length, dns_response, start)
        for part in st:
            s += part.decode('utf-8')
            s += '.'
        start += length
        
    return s, start - begin
   
 
def decodeIP(dns_response, begin):
    start = begin
    s = ''
    for i in range(4):
        st, = struct.unpack_from("!B", dns_response, start + i)
        s += str(st)
        s += '.'
    return s


def getAnswers(dns_response, dns_query, total):
    result = []
    
    start = int(len(dns_query))
    response = dns_response[start:]
    offset = 0
    
    for i in range(total):
        
        next_offset = 0
        
        s, l = decodeString(dns_response, start + offset)
        s = s[:-1]
        offset += l
        
        rtype, = struct.unpack_from("!H", response, offset)
        rclass, = struct.unpack_from("!H", response, offset + 2)
        ttl, = struct.unpack_from("!I", response, offset + 4)
        dlength, = struct.unpack_from("!H", response, offset + 8)
        
        next_offset += 10
        
        s1 = ''
        l1 = 0
        pref = 0
        if int(rtype) == 2 or int(rtype) == 5:
            s1, l1 = decodeString(dns_response, start + offset + 10)
        elif int(rtype) == 1:
            s1 = decodeIP(response, offset + 10)
        elif int(rtype) == 15:
            pref, = struct.unpack_from("!H", response, offset + 10)
            s1, l1 = decodeString(dns_response, start + offset + 12)
            
        s1 = s1[:-1]
        
        next_offset += int(dlength)
        
        '''
        if int(rtype) == 2 or int(rtype) == 1 or int(rtype) == 5 or int(rtype) == 15:
            print('name: '+ s)
            print('rtype: ' + str(rtype))
            print('rclass: ' + hex(rclass))
            print('ttl: ' + hex(ttl))
            print('dlength: ' + str(dlength))
            print('answer: ' + s1)
            print()
        '''
        
        offset += next_offset
        if int(rtype) == 2 or int(rtype) == 1 or int(rtype) == 5 or int(rtype) == 15:
            result.append({
                'name': s,
                'rtype': int(rtype),
                'rclass': rclass,
                'ttl': ttl,
                'dlength': dlength,
                'answer': s1,
                'preference': pref
            })
            
    return result


if __name__ == '__main__':
    #check if arguments are correct
    if len(sys.argv) != 2:
        print("Error: invalid arguments")
        print("Usage: resolver resolver_port")
        sys.exit()
    if sys.argv[1].isnumeric() == False:
        print("Error: invalid arguments")
        print("Usage: client resolver_ip resolver_port name [type = A] [timeout = 5]")
        sys.exit()
    
    #start udp socket
    serverPort = int(sys.argv[1])
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind(('localhost', serverPort))
    
    #read in the named.root file
    f = open('named.root', 'r')
    roots = []
    for line in f.readlines():
        if line[0] == ';':
            continue
        elif 'A    ' in line:
            roots.append(line[44:-1])
    roots.reverse()
   
    #start receiving messages
    print('the server is ready to receive on port number: ' + str(serverPort))
    while 1:
        #receive message from client and decode
        clientMessage, clientAddress = serverSocket.recvfrom(2048)
        dnsQuery = clientMessage.decode('utf-8')

        #copy roots list and initialise variables for final answer
        serverstoQuery = roots.copy()
        alreadyQueried = []
        final_answer = []
        response_code = 0
        dnsSocket = socket(AF_INET, SOCK_DGRAM)
        
        question, length = decodeString(clientMessage, 12)
        
        #start loop to iterate down dns tree
        while 1:
            #if no more servers to query then break
            if len(serverstoQuery) == 0:
                break
            
            #get server from top and pop from server list
            dnsServer = str(serverstoQuery[-1])
            serverstoQuery.pop()
            
            #intialise socket and send 
            
            dnsSocket.settimeout(1)
            print('sending to:' + dnsServer + '!')
            try:
                dnsSocket.sendto(dnsQuery.encode('utf-8'), (dnsServer, 53))
            except:
                continue
            alreadyQueried.append(dnsServer)
            
            
            #try to receive but if timeout then move to next server
            try:
                dnsResponse, dnsAddress = dnsSocket.recvfrom(2048)
            except KeyboardInterrupt:
                sys.exit()
            except:
                continue
            
            #get flags then question then answers
            flags = getFlags(dnsResponse)
            
            qu, l = decodeString(dnsResponse, 12)
            qtype, qclass = struct.unpack_from('!2H', dnsResponse, 12 + l)
            #print('question: ' + qu)
            #print('qtype: ' + str(qtype))
            #print()
            #print('qclass: ' + str(qclass))
            
            answers = []
            if flags['response_code'] == 0:
                answers = getAnswers(dnsResponse, dnsQuery, flags['authority_count'] + flags['answer_count'] + flags['additional_count'])

            #error code handling
            rcode = flags['response_code']
            #response code = 0 then OK
            if rcode == 0:
                #get all answers
                answer_found = False
                if flags['answer_count'] > 0:
                    answer_found = True
                    for a in answers:
                        cons = str(a['preference']) + ' ' + a['answer'] + '.'
                        if a['rtype'] == qtype and a['answer'] not in final_answer and a['rtype'] != 15:
                            final_answer.append(a['answer'])
                        elif a['rtype'] == 15 and a['answer'] not in final_answer:
                            final_answer.append(cons)
                else:
                    for a in answers:
                        if a['rtype'] == qtype and a['answer'] not in final_answer and a['name'] == qu[:-1]:
                            cons = str(a['preference']) + ' ' + a['answer'] + '.'
                            if str(qtype) == '15':
                                final_answer.append(cons)
                            else:
                                final_answer.append(a['answer'])
                            answer_found = True
                    
                #if answer found then break
                if answer_found == True and len(final_answer) != 0:
                    final_answer.insert(0, 'Answer Section:')
                    break
                
                
                #if no answer found then get all next servers and continue loop
                for a in answers:
                    if a['rtype'] == 5:
                        qmakearg = helper.queryNumToStr(qtype)
                        dnsQuery = helper.queryMake(a['answer'], qmakearg).decode('utf-8')
                        print('changed query to:' + a['answer'] + '!')
                        serverstoQuery = roots.copy()
                        alreadyQueried = []
                        break
                    if a['rtype'] == 2 and a['answer'] not in alreadyQueried:
                        serverstoQuery.append(a['answer'])
            #response code = 2 then go to next server in list
            elif rcode == 2:
                continue
            #response code = not 0 or 2 then break because error
            else:
                response_code = rcode
                break
            
        dnsSocket.close()
        #create response
        reply = ''
        if response_code == 0:
            print('answer found')
            reply += 'Answer Found: \n'
            for ans in final_answer:
                reply += ans + '\n'
            if reply == 'Answer Found: \n':
                reply += 'No answer: Reached SOA Record\n'
        elif response_code == 1:
            print('error found: ' + str(response_code))
            reply += 'Format Error: Server unable to interpret query format.'
        elif response_code == 2:
            print('error found: ' + str(response_code))
            reply += 'Server Error: Server failure.'
        elif response_code == 3:
            print('error found: ' + str(response_code))
            reply += 'Name Error: Server cannot find: ' + question + '\n'
        else:
            print('error found: ' + str(response_code))
            reply += 'Other Error: Response code is: ' + str(response_code) + '\n'
            
        #send response and wait for next query
        serverSocket.sendto(reply.encode('utf-8'), clientAddress)
        #print("\nawaiting next query...\n\n")
        
            
        
        
        
