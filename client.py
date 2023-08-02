from socket import *
import helper
import sys
import time

#check if arguments are correct
if len(sys.argv) != 4 and len(sys.argv) != 5 and len(sys.argv) != 6:
	print("Error: invalid arguments")
	print("Usage: client resolver_ip resolver_port name [type = A] [timeout = 5]")
	sys.exit()

timeout_time = 8
query_type = 'A'

#5 argument check
if len(sys.argv) == 5 and sys.argv[4].isnumeric() == False:
    check_this = sys.argv[4]
    check_this = check_this.upper()
    if check_this != 'A' and check_this != 'NS' and check_this != 'MX' and check_this != 'CNAME' and check_this != 'PTR':
        print("Error: invalid arguments")
        print("Usage: query type argument (argument 4) must be a valid type.")
        sys.exit()
        
if len(sys.argv) == 5 and sys.argv[4].isnumeric():
    timeout_time = int(sys.argv[4])
elif len(sys.argv) == 5 and sys.argv[4].isnumeric() == False:
    query_type = sys.argv[4].upper()

#6 argument check
if len(sys.argv) == 6:
    check_this = sys.argv[4]
    check_this = check_this.upper()
    if check_this != 'A' and check_this != 'NS' and check_this != 'MX' and check_this != 'CNAME' and check_this != 'PTR':
        print("Error: invalid arguments")
        print("Usage: query type argument (argument 4) must be a valid type.")
        sys.exit()
    if sys.argv[5].isnumeric() == False:
        print("Error: invalid arguments")
        print("Usage: timeout argument (argument 5) must be a valid number.")
        sys.exit()

if len(sys.argv) == 6:
    timeout_time = int(sys.argv[5])
    query_type = sys.argv[4].upper()

#print(timeout_time)
#print(query_type)

#get other arguments
if sys.argv[2].isnumeric() == False:
    print("Error: invalid arguments")
    print("Usage: client resolver_ip resolver_port name [type = A] [timeout = 5]")
    sys.exit()
serverName = sys.argv[1]
serverPort = int(sys.argv[2])
clientQuestion = sys.argv[3]

#make query
clientMessage = helper.queryMake(clientQuestion, query_type)

#connect socket and set dns query
print ('Sending for: ' + clientQuestion + ' for type: ' + query_type)
clientSocket = socket(AF_INET, SOCK_DGRAM)
clientSocket.settimeout(timeout_time)
clientSocket.sendto(clientMessage,(serverName, serverPort))

#start timer
serverReply = ''
start = time.perf_counter()

#receive dns answer
try:
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
    serverReply = modifiedMessage.decode('utf-8')
except KeyboardInterrupt:
    print('Keyboard Interrupt!')
    sys.exit()
except:
    print("Time Error: Timed out.")
    sys.exit() 
    
#stop timer and record
finish = time.perf_counter()
print(f"Recieved result in {finish - start:0.4f} seconds")

print(serverReply)

clientSocket.close()