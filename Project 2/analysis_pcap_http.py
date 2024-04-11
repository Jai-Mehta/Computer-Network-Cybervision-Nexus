# from re import I
# from tkinter import E
import sys
# g = open('PARTCOUTPUT.txt','w')
# sys.stdout = g
import dpkt
import struct
def convertfrombytes(buf, fmt, pos, size):
    if(len(buf) > pos):
        return str(int.from_bytes(buf[pos:pos+size], byteorder='big'))
class Packet:
    isValid = True
    headerSize = ""
    srcIp = ""
    destIp = ""
    srcPort = ""
    destPort = ""
    postresponse = ""
    getrequest = ""
    syn = ""
    ack = ""
    wndsize = ""
    seqNum = ""
    ackNum = ""
    fin = ""
    size = ""
    timestamp = 0
    mss = ""
    payload = ""
    

    def packetparse(self, timestamp, buf):
        try:
            # packetarray = []
            # self.length=len(buf)
            # for character in bytes(buf):
            #     #print("hii")
            #     packetarray.append(character)
            # #print("1")
            # self.startipheader = 14
            # ipheader=(hex(packetarray[14]))
            # pointertcpheader=ipheader[-1]
            # starttcp=self.startipheader+int(pointertcpheader, 16)*4
            # startdestport=starttcp+2
            # self.totallength=hex(packetarray[self.startipheader+2])[2:]+hex(packetarray[self.startipheader+3])[2:]
            # self.a=(int(pointertcpheader,16)+int(hex(packetarray[startdestport+10])[2],16))*4
            # self.datalen1=int(self.totallength,16)-self.a



            # packetarray = []
            # for character in bytes(buf):
            #     packetarray.append(ord(character))
            # self.startipheader = 14
            # self.headerlen = hex(packetarray[self.startipheader+2])[2:]+hex(packetarray[self.startipheader+3])[2:]
            # ipheader=(hex(packetarray[self.startipheader]))
            # pointertcpheader=ipheader[-1]
            # starttcp=self.startipheader+int(pointertcpheader, 16)*4
            # startdestport=starttcp+2
            # self.a=(int(pointertcpheader,16)+int(hex(packetarray[startdestport+10])[2],16))*4
            # self.datalen=int(self.headerlen,16)-self.a
            self.headerSize = convertfrombytes(buf, ">B", 46, 1)
            self.srcIp = convertfrombytes(buf, ">B", 26, 1) + \
							"." + convertfrombytes(buf, ">B", 27, 1) + \
							"." + convertfrombytes(buf, ">B", 28, 1) + \
							"." + convertfrombytes(buf, ">B", 29, 1)

            self.destIp = convertfrombytes(buf, ">B", 30, 1) + \
							"." + convertfrombytes(buf, ">B", 31, 1) + \
							"." + convertfrombytes(buf, ">B", 32, 1) + \
							"." + convertfrombytes(buf, ">B", 33, 1)

            self.srcPort = convertfrombytes(buf, ">H", 34, 2)
            self.destPort = convertfrombytes(buf, ">H", 36, 2)
            
            option = "{0:16b}".format(int(convertfrombytes(buf, ">H", 46, 2)))
            self.syn = option[14]
            self.ack = option[11]
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP :
                ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP :
               tcp = ip.data
            
            self.fin = str(( tcp.flags & dpkt.tcp.TH_FIN ))
            self.seqNum = convertfrombytes(buf, ">I", 38, 4)
            self.ackNum = convertfrombytes(buf, ">I", 42, 4)
            self.wndsize = convertfrombytes(buf, ">H", 48, 2)
            self.size = len(buf)
            self.timestamp = timestamp
            head_len          = int.from_bytes(buf[46:47], byteorder='big')
            self.head_len     = 4*(head_len>>4)
            self.payload     = (buf[34+self.head_len:])
            self.payloadlen     = len(buf[34+self.head_len:])
            self.mss = convertfrombytes(buf, ">H", 56, 2)
        except:
            self.isValid = False
    # def parsehttp(self, timestamp, buf):
    #     try:
    #         self.getrequest = str(convertfrombytes(buf, ">s", 66, 1)) + str(convertfrombytes(buf, ">s", 67, 1)) + str(convertfrombytes(buf, ">s", 68, 1))
    #         # str(struct.unpack(fmt, buf[pos:pos+size])[0])
    #         self.postresponse = str(convertfrombytes(buf, ">s", 66, 1)) + str(convertfrombytes(buf, ">s", 67, 1)) + str(convertfrombytes(buf, ">s", 68, 1)) + str(convertfrombytes(buf, ">s", 69, 1))
    #     except:
    #         pass
file = open('http_1080.pcap','rb')
# file = open('tls.pcap','rb')

pcap = dpkt.pcap.Reader(file)

# print("Open and Reading")
packet_list = []
for line in pcap:
    timestamp = line[0]
    header = line[1]
    packet = Packet()
    packet.packetparse(timestamp,header)
    # packet.parsehttp(timestamp,header)
    packet_list.append(packet)
file.close()
# print(len(packet_list))
# Finding total number of connections and flow ports   
def number_of_connections(pl):
    flowports = dict()
    noc = 0
    for ele in pl:
        if ele.syn=="1" and ele.ack=="1":
            noc = noc+1
            # This line gives us the flow. For this packet the destination will be the sender of the SYN
            flowports[str(ele.destPort)] = str(ele.srcPort)
    return noc,flowports
connections,flows = number_of_connections(packet_list)
# print(connections)
from queue import Queue
#Dividing the transactions according to flow and storing them in variable transaction_list
def flow_transactions(flows,packetlist):
    grouped_transactions = []
    for ele in flows:
        trans = []
        for p in packetlist:
            if p.srcPort == ele and p.destPort == flows[ele]:
                trans.append(p)
        grouped_transactions.append(trans)
    return grouped_transactions
transactions_list = (flow_transactions(flows,packet_list))



flows_grouped = []
for j in flows:
    temp_flow = []
    for pkt in packet_list:
        if pkt.srcPort == j or pkt.destPort==j:
            temp_flow.append(pkt)
    flows_grouped.append(temp_flow)


# print("#######################")
# print(len(flows_grouped))
# print("#######################")

# def ParsePcapFile(pcap):
#     db = []
#     for timestamp, buf in pcap:
#         packet = Packet()
#         packet.packetparse(timestamp, buf)
#         # packet.parsehttp(timestamp, buf)
#         if packet.isValid:	
#             db.append(packet) #few of packet are invalid because of emtpy fields or packet len small
#     return db

# def CheckHTTP(db):
# 	#Count the number of TCP connections
#     tcpconnections = 0
#     packetCount = 0
#     totalPayload = 0
#     for packet in db:
#         packetCount += 1
#         totalPayload += packet.size
#         if packet.syn == "1" and packet.ack == "1":
# 			# print packet.srcIp + ":" + packet.srcPort + "-->" + packet.destIp + ":" + packet.destPort + "  " + packet.seqNum + "  " + packet.ackNum
#             tcpconnections += 1
	
#     print("No of tcp connections : " + str(tcpconnections))
#     print("Time Taken : " + str(db[len(db)-1].timestamp-db[0].timestamp))
#     print("Packet Count : " + str(packetCount))
#     print("Raw data size : " + str(totalPayload))
    


# def Task1(db):
#     que = []
#     responseDict = {}
#     for packet in db:
#         if str(packet.payload).find('GET')!=-1:
#             que.append(packet)
#         elif str(packet.payload).find('HTTP')!=-1:
#             deq = que.pop(0)
#             responseDict[deq] = packet
#     for e in responseDict:
#         key = e
#         value = responseDict[key]
#         print("GET           " + key.srcIp + " " + key.destIp + " " + key.seqNum + " " + key.ackNum)
#         print("HTTP RESPONSE " + value.srcIp + " " + value.destIp + " " + value.seqNum + " " + value.ackNum)

# def FormPair(file):
#     pcap = dpkt.pcap.Reader(open(file,'rb'))
#     db = ParsePcapFile(pcap)
#     Task1(db)

# print("############FINAL############")
def partC_1(flows_grouped):
    for ele in flows_grouped:
        getr = 0
        postr = 0
        con = 0
        req = {}
        response_tuple = []
        for j in range(len(ele)):
            pkt = ele[j]
            i = 0
            if pkt.fin=="1":
                break
            if str(pkt.payload).find('GET')!=-1:
                print("REQUEST")
                getr +=1
                # print(pkt.payload)
                print(str(pkt.payload)[0:str(pkt.payload).find('Connection')])
                # print("TUPLE FOR GET REQUEST\n")
                print("(source: "+str(pkt.srcIp)+", dest: "+str(pkt.destIp)+", seq: "+str(pkt.seqNum)+", ack: "+str(pkt.ackNum)+")")
            elif str(pkt.payload).find('HTTP')!=-1:
                postr+=1
                # req[pkt.seqNum] = pkt
                # print(pkt.payload)
            elif pkt.syn!="1" and pkt.fin!="1" and pkt.srcIp == "34.193.77.105":
                req[pkt.seqNum] = pkt
                response_tuple.append(pkt)
                
                # print("("+str(pkt.srcIp)+","+str(pkt.destIp)+","+str(pkt.seqNum)+","+str(pkt.ackNum)+")")
        print("RESPONSE")
        for p in response_tuple:
            print("(source: "+str(p.srcIp)+", dest: "+str(p.destIp)+", seq: "+str(p.seqNum)+", ack: "+str(p.ackNum)+")")


    # print("GET:",getr)
    # print("POST:",postr)
    # print("NUMBER OF TUPLES",len(req))
    # print("RESPONSE TUPLE",len(response_tuple))
    print("************************************************")
    # break
# print("############FINAL############")

partC_1(flows_grouped)

#FormPair('http_1080 (1).pcap')	
# pcaps = ['http_1080.pcap','tcp_1081.pcap', 'tcp_1082.pcap']
# print("----------------------------------------------------------------------------------")
# for fl in pcaps:			
# 	pcap = dpkt.pcap.Reader(open(fl,'rb'))
# 	db = ParsePcapFile(pcap)
# 	CheckHTTP(db)
# 	print("----------------------------------------------------------------------------------")

print("***********************CONECTION TYPE*************************")

def partC_2(pcap,f1):
    packet_list = []
    for line in pcap:
        timestamp = line[0]
        header = line[1]
        packet = Packet()
        packet.packetparse(timestamp,header)
        # packet.parsehttp(timestamp,header)
        packet_list.append(packet)
    flows_grouped = []
    flows = dict()
    noc = 0
    for ele in packet_list:
        if ele.syn=="1" and ele.ack=="1":
            noc = noc+1
            # This line gives us the flow. For this packet the destination will be the sender of the SYN
            flows[str(ele.destPort)] = str(ele.srcPort)
    for j in flows:
        temp_flow = []
        for pkt in packet_list:
            if pkt.srcPort == j or pkt.destPort==j:
                temp_flow.append(pkt)
        flows_grouped.append(temp_flow)
    if len(flows_grouped)>6:
        return ("HTTP 1.0 for " + f1)
    if len(flows_grouped)==6:
        return ("HTTP 1.1 for " + f1)
    if len(flows_grouped)<6:
        return ("HTTP 2.0 for " + f1)
pcaps = ['http_1080.pcap','tcp_1081.pcap','tcp_1082.pcap']
# print("----------------------------------------------------------------------------------")
for fl in pcaps:			
    pcap = dpkt.pcap.Reader(open(fl,'rb'))
    ans = partC_2(pcap,fl)
    print(ans)
# 	print("----------------------------------------------------------------------------------")




# print("Closed!")