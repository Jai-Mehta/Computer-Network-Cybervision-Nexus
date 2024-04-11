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
	#Reference : http://www.networksorcery.com/enp/protocol/tcp.htm
    def parse(self, timestamp, buf):
        try:
            packetarray = []
            self.length=len(buf)
            
            for character in bytes(buf):
                #print("hii")
                packetarray.append(character)
                
            #print("1")
            self.startipheader = 14
            ipheader=(hex(packetarray[14]))
            pointertcpheader=ipheader[-1]
            starttcp=self.startipheader+int(pointertcpheader, 16)*4
            startdestport=starttcp+2
            self.totallength=hex(packetarray[self.startipheader+2])[2:]+hex(packetarray[self.startipheader+3])[2:]
            self.a=(int(pointertcpheader,16)+int(hex(packetarray[startdestport+10])[2],16))*4
            self.datalen1=int(self.totallength,16)-self.a
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
            
            self.fin = ( tcp.flags & dpkt.tcp.TH_FIN )
            self.seqNum = convertfrombytes(buf, ">I", 38, 4)
            self.ackNum = convertfrombytes(buf, ">I", 42, 4)
            self.wndsize = convertfrombytes(buf, ">H", 48, 2)
            self.size = len(buf)
            self.timestamp = timestamp


            head_len          = int.from_bytes(buf[46:47], byteorder='big')
            
            self.head_len     = 4*(head_len>>4)
            self.payload     = len(buf[34+self.head_len:])
            #print(self.payload)

            self.mss = convertfrombytes(buf, ">H", 56, 2)
        except:
            self.isValid = False
file = open('assignment2.pcap','rb')

pcap = dpkt.pcap.Reader(file)

# print("Open and Reading")
packet_list = []
for line in pcap:
    timestamp = line[0]
    header = line[1]
    packet = Packet()
    packet.parse(timestamp,header)
    packet_list.append(packet)

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
print("FLOWS:")
for i in flows:
    print(i," to/from ",flows[i])
print("\n")
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

def partA_2a(flowsgrouped):
    f = 1
    for ele in flowsgrouped:
        c = 0
        visited = []
        print("FOR FLOW "+str(f))
        for k in range(3,len(ele)):
            p = ele[k]
            if p.syn=="1":
                continue
            else:
                if p.seqNum not in visited:
                    visited.append(p.seqNum)
                    print("################SENDING PACKET####################")
                    print("SEQUENCE NUMBER "+ str(p.seqNum) + "               ACKNOWLEDGEMENT NUMBER " + str(p.ackNum) + "               WINDOW SIZE " + str(int(p.wndsize)*16384))
                    # print(p.datalen1)
                    for t in ele:
                        if int(t.ackNum) == (int(p.seqNum)+int(p.datalen1)):
                            print("################RECEIVING ACK####################")
                            print("SEQUENCE NUMBER "+ str(t.seqNum) + "               ACKNOWLEDGEMENT NUMBER " + str(t.ackNum) + "               WINDOW SIZE " + str(int(t.wndsize)*16384) + "\n")
                            
                            break
                    # print("ACKNOWLEDGEMENT NUMBER", p.ackNum)
                    # print("WINDOW SIZE", p.wndsize)
                    c+=1
                    if c==2:
                        break
                
        f+=1
        print("\n")
partA_2a(flows_grouped)

def partA_2b(transactionlist):
    throughputs = []
    f = 1
    for ele in transactionlist:
        time_stamp = ele[-1].timestamp-ele[0].timestamp
        total_size = 0
        for p in ele:
            total_size = total_size + p.size
        print("FOR FLOW "+str(f))
        # print("THROUGHPUT: "+ str((total_size/time_stamp))+ " Mbps\n")
        print("THROUGHPUT: "+ str((total_size/time_stamp)/1000000)+ " Mbps\n")
        f+=1
        # throughputs.append((total_size/time_stamp)/1000000)
        throughputs.append((total_size/time_stamp))
    return throughputs
throughputs = partA_2b(transactions_list)

# I calculate the loss by finding out the number of times a packet is retransmitted and dividing that total count by the total number of packets sent. Total number o packets sent include the retransmitted packets also
def partA_2c(transactionlist):
    losses = []
    f = 1
    # c = 0
    for ele in transactionlist:
        sent_once = []
        lost = 0
        total_sent = len(ele)
        for p in ele:
            if p.seqNum in sent_once:
                lost+=1
                # if c==2:
                #     print("***************************************",p.payload)
            else:
                if p.payload!=0:
                    sent_once.append(p.seqNum)

        print("FOR FLOW "+str(f))
        print("LOSS RATE: "+ str(lost/total_sent) + "\n" )
        losses.append((lost/total_sent))
        f+=1
        # c+=1
    return losses
losses = partA_2c(transactions_list)

def partA_2d_temp(flowsgrouped,flows):
    rtts = []
    flow_sender = list(flows.keys())
    for l in range(len(flowsgrouped)):
        ele = flowsgrouped[l]
        seq_dict = {}
        ack_dict = {}
        for i in range(len(ele)):
            pkt = ele[i]
            if pkt.srcPort==flow_sender[l]:
                if int(pkt.seqNum) in seq_dict:
                    seq_dict.pop(int(pkt.seqNum))
                else:
                    seq_dict[int(pkt.seqNum)] = [float(pkt.timestamp),(int(pkt.seqNum)+int(pkt.datalen1))]
            if pkt.destPort==flow_sender[l]:
                ack_dict[int(pkt.ackNum)] = float(pkt.timestamp)
        RTT = 0
        tc = 0
        # alpha = 0.125
        for seqnumber in seq_dict:
            #print(seq_dict[seqnumber][1])
            #print(ack_dict[seq_dict[seqnumber][1]])
            keyt = seq_dict[seqnumber][1]
            if keyt in ack_dict:
                # print(ack_dict[keyt])
                # print(seq_dict[seqnumber][0])
                # RTT = ((1-alpha)*RTT) + (alpha*(ack_dict[keyt]-seq_dict[seqnumber][0]))
                RTT = RTT + (ack_dict[keyt]-seq_dict[seqnumber][0])
                tc = tc + 1
        print("FOR FLOW ",str(l+1))
        #print(ack_dict)
        print("AVERAGE RTT " + str(RTT/tc) + "\n")
        rtts.append((RTT/tc))
    return rtts
rtts = partA_2d_temp(flows_grouped,flows)

import math
def theoretical(rtts,losses):
    theoretical_throughputs = []
    MSS = 1460
    for i in range(len(rtts)):
        print("FOR FLOW ",i+1)
        try:
            theoretical_throughputs.append(((math.sqrt(3/2) * MSS)/(rtts[i] * (math.sqrt(losses[i])))))
            print("THEORETICAL THROUGHPUT: ",theoretical_throughputs[i]/1000000,"Mbps\n")
            # print("\n")
        except ZeroDivisionError:
            theoretical_throughputs.append("Infinity")
            print("THEORETICAL THROUGHPUT: ","Infinity Mbps\n")
            # print("\n")
theoretical_throughputs = theoretical(rtts,losses)

# def partB_2(flowsgrouped, flows):
#     flow_sender = list(flows.keys())
#     for l in range(len(flowsgrouped)):
#         ele = flowsgrouped[l]
#         seq_dict = {}
#         ack_dict = {}
#         tri_ack = []
#         # sent_once = []
#         # loss = 0
#         for i in range(len(ele)):
#             pkt = ele[i]
#             if pkt.srcPort==flow_sender[l]:
#                 seq_dict[pkt.seqNum] = seq_dict.get(pkt.seqNum,0) + 1
#                 # if seq_dict[pkt.seqNum]>1:
#                 #     print("Hii")
#             if pkt.destPort==flow_sender[l]:
#                 ack_dict[pkt.ackNum] = ack_dict.get(pkt.ackNum,0) + 1
#                 # if ack_dict[pkt.ackNum]>2:
#                 #     tri_ack.append(int(pkt.ackNum))
#             # if pkt.srcPort == flow_sender[l] and pkt.seqNum in sent_once:
#             #     loss = loss + 1
#             # else:
#             #     sent_once.append(pkt.seqNum)
#         for a in ack_dict:
#             if ack_dict[a]==3:
#                 tri_ack.append(a)
#         total_transmisson = 0
#         for k in seq_dict:
#             total_transmisson = total_transmisson + seq_dict[k]
#         unique_tranmission = len(seq_dict)
#         # total_transmisson = len(tl[l])
#         print("TOTAL TRANSMISSION: ",total_transmisson)
#         print("UNIQUE ", unique_tranmission)
#         # print("LOSS ", loss)
#         triple_ack_transmission = len(tri_ack)
#         # timeout_transmisson = total_transmisson - triple_ack_transmission - unique_tranmission
#         # print("FOR FLOW "+ str(l))
#         # print("TIMEOUT RETRANSMISSIONS: "+ str(timeout_transmisson))
#         print("TRIPLE DUPLICATE ACK RETRANSMISSIONS: " + str(triple_ack_transmission) + "\n")
# partB_2(flows_grouped, flows)





# def partB_1(flowsgrouped,flows):
#     flow_sender = list(flows.keys())
#     for l in range(len(flowsgrouped)):
#         ele = flowsgrouped[l]
#         sent = []
#         cwnd = []
#         for k in range(3,len(ele)):
#             p = ele[k]
#             if p.srcPort == flow_sender[l]:
#                 sent.append(p)
#             if p.destPort == flow_sender[l]:
#                 cwnd.append(int(sent[-1].seqNum) - int(p.ackNum))
#                 if len(cwnd)==10:
#                     break
#         print(cwnd)
# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
# partB_1(flows_grouped,flows)
# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

# def partB_2(flowsgrouped, flows):
#     flow_sender = list(flows.keys())
#     for l in range(len(flowsgrouped)):
#         ele = flowsgrouped[l]
#         seq_dict = {}
#         ack_dict = {}
#         for i in range(len(ele)):
#             pkt = ele[i]
#             if pkt.srcPort==flow_sender[l]:
#                 #ADDED TO REMOVE THE PUSH OUT
#                 if pkt.payload!=0:
#                     seq_dict[pkt.seqNum] = seq_dict.get(pkt.seqNum,0) + 1
#             if pkt.destPort==flow_sender[l]:
#                 ack_dict[pkt.ackNum] = ack_dict.get(pkt.ackNum,0) + 1
#         loss = 0
#         triackcount = 0
#         for seqnumber in seq_dict:
#             if seqnumber in seq_dict:
#                 loss += seq_dict[seqnumber]-1
#             if (seqnumber in ack_dict) and (ack_dict[seqnumber]  >3):
#                 triackcount += seq_dict[seqnumber]-1
#         print("FOR FLOW "+ str(l+1))
#         print("TRIPLE ACK RETRANSMISSION : " + str(triackcount))
#         print("TIMEOUT RETRANSMISSION : " + str(loss-triackcount)+ "\n")
# partB_2(flows_grouped, flows)

file.close()
# print("Closed!")

# tcp.analysis.duplicate_ack && tcp.dstport == 43498
# tcp.analysis.duplicate_ack && tcp.dstport == 43500
# tcp.analysis.duplicate_ack 
# (tcp.srcport == 43498 || tcp.dstport == 43498) && (tcp.analysis.retransmission)
# tcp.analysis.rto