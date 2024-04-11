import requests
#from bs4 import BeautifulSoup
import re
import sys
import dns
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import time
import datetime

# rootservers = []
# #Requesting server page for scraping to get the ip addresses for the root servers
# server_page = requests.get('https://www.iana.org/domains/root/servers') # Getting the resource page for fetching the ipaddresses
# # Parsing content of the page retreived
# htmldata = BeautifulSoup(server_page.content, 'html.parser') 
# # Selecting 2nd column for the table found on the retreived page where td is the table data
# for td in htmldata.select('table tr td:nth-child(2)'):
#     pattern =re.compile('''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''') # Matching regular expressions to retreive the IP Addresses
#     address = pattern.search(td.text.strip())
#     #if ip address successfully retreived, adding it to the list of root servers
#     if address:
#         rootservers.append(address[0])

rootservers=['198.41.0.4','199.9.14.201','192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241','192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30','193.0.14.129','199.7.83.42','202.12.27.33']

def query(domain_name, record_type, server):
    # We extract the do,main name from text to pass in to the main query, it returns an object of type dns.name.Name
    input_name = dns.name.from_text(str(domain_name))
    # We pass the Name object to make_ query function to formulate a query in the format to be sent. It will randomly choose query id and set the flags ot RD. This returns an object of type dns.message.QueryMessage
    query_name = dns.message.make_query(input_name, record_type)
    # dns.message.Message object is passed to the udp query that is to be sent to the server, which returns a response of type dns.message.Message. This message object has fields like Additional, Answer and Authority which further need to be evaluated.
    response = dns.query.udp(query_name, server, timeout=1)
    # Checking the flags of the reponse and storing them in flags variable to be returned
    return response

def mydig(domain_name, record_type, server_list, record_class):
    rootservers=['198.41.0.4','199.9.14.201','192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241','192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30','193.0.14.129','199.7.83.42','202.12.27.33']
    for serv in server_list:
        try:
            response = query(domain_name, record_type, serv)
            if not response:
                print("There is no response from the server:", serv)
            # if serv == '205.251.192.47':
            # print("*****************ORIGINAL RESPONSE******************")
            # print(response)
            # print("*****************ORIGINAL RESPONSE******************")
            # print(server_list)


            # Firstly we check if we have an answer in the response. If not, only then we move further to check the additional and authority section of response.
            while len(response.answer)==0:
                # Here we parse through the addresses returned in the addtional section. We first store them in the list and parse and then start running dig on them with the original domain name
                if len(response.additional)>0:
                    #print(response)
                    parse = []
                    for address in response.additional:
                      if (dns.rdatatype.to_text(address.rdtype) == 'A'):
                        parse.append(address[0].address)
                    ans = mydig(domain_name, record_type, parse, record_class)
                    if ans: return ans

                # Here we check the authority section of the response.
                elif len(response.authority)>0:
                  #print(response)
                  # First we check if the section has a record of type SOA. If yes we take the name of the name server and query it against the original root servers, setting record type as A
                  for ad in response.authority[0]:
                      if dns.rdatatype.to_text(ad.rdtype) == "SOA":
                          # print("SOA!")
                          qname = (str(ad).split(" ")[0])
                          ans = mydig(qname, "A", rootservers, record_class)
                          if ans: return ans
                  ip = []
                  # If the response does not have an SOA record, then we move further to query the domain name of the new name servers found against the root server with the intially entered record type.
                  for i in range(len(response.authority)):
                    ns = response.authority[i][0].to_text()
                    auth_ns = mydig(ns, record_type, rootservers, record_type)
                    if auth_ns:
                      break
                  return auth_ns
            # If the response has an answer it will enter this section.
            if len(response.answer)>0:
                #print("Hii Answer")
                for ans in response.answer:
                    # print(dns.rdatatype.to_text(ans.rdtype))
                    # if the response has answer section and is of the record type A, then the answer is returned
                    if (dns.rdatatype.to_text(ans.rdtype)=="A"):
                        return ans
                    # if the response has an answer of record type NS or MX, then we query that new name against the rootservers to resolve it.
                    elif (dns.rdatatype.to_text(ans.rdtype)=="NS") or (dns.rdatatype.to_text(ans.rdtype)=="MX"):
                        qname = str(response.answer[0]).split(" ")[-1]
                        ans = mydig(qname, record_type, rootservers, record_class)
                        if ans: return ans
                    # If the record returned is of the type CNAME, we need to to further resolve it to get the final answer and then return it if found
                    elif (dns.rdatatype.to_text(ans.rdtype)=="CNAME"):
                        # print(ans)
                        # print("CNAME")
                        canonical_name = (str(ans.to_text()).split(" ")[-1])
                        ans2 = mydig(canonical_name, "A", rootservers, record_class)
                        if ans2:
                            return ans2
                break
        except dns.exception.Timeout:
            print("***********************")
            print("Timeout Error!")
            print("***********************")

# Taking the inputs from the user, using system arguments
if len(sys.argv) < 3:
    print("please provide the domain and record type")
    exit()
domain_name = sys.argv[1]
record_type = sys.argv[2]
record_class = "IN"

# Printing the question section
print("QUESTION SECTION:")
print(domain_name + "        " + record_class + " " + record_type +"\n")

# Recording the time to measure the time to resolve a domain name
t1 = int(round(time.time()*1000))

# Calling the dig function to start resolving the user entered domain name
ans= mydig(domain_name, record_type, rootservers, record_class)
# print(cname)
# if cname=="cname":
#     while cname=="cname":
#       print("##########################")
#       print(str(ans).split(" ")[-1])
#       print("##########################")
#       ans,cname = dig(domain_name, record_type, (str(ans).split(" ")[-1]), record_class)
#       if ans:
#         print(ans)

# Recording the time once the resolution is complete
t2=int(round(time.time()*1000))
#print(ans)
# Printing the answer section
print("ANSWER SECTION:")
if ans:
    for ele in ans:
    # print(ele)
    # a = str(ele).split(" ")
    # print(a)
    # a.pop(0)
    # (a.pop(0))
    # print(domain_name + " " + " ".join(a)+"\n")
        print(domain_name+" " + record_class + " A " + str(ele) )
    print("\n")
    # Printing the query time, the date and time of the resolution and the size of the message received
    print("QUERY TIME: "+ str(t2-t1)+"msec")
    print("WHEN: ", datetime.date.today().strftime("%A"), datetime.date.today().strftime(
                                "%B"), datetime.date.today().strftime(
                                "%d"), datetime.datetime.now(), datetime.date.today().strftime("%Y"))
    print("MSG SIZE rcvd: ", sys.getsizeof(ans))
else:
    print("You are not connected to the internet! or You are hitting the firewall!")
# # Taking the inputs from the user, using system arguments


# RUN FOR TXT FILE OUTPUT

# domain_name = ["www.google.com", "www.cnn.com", "www.facebook.com","google.co.jp"]
# record_type = ["A","NS","MX","A"]
# record_class = "IN"
# # Printing the question section
# f = open("mydig_output.txt", "a")
# print("##############################INPUTS#####################################\n"+"1. www.google.com IN A\n"+"2. www.cnn.com IN NS\n"+"3. facebook.com IN MX\n"+"4. google.co.jp\n",file = f)
# for i in range(0,4):
#   print("******************************* "+ "EXAMPLE FOR RECORD TYPE " + record_type[i] +" *******************************",file= f)
#   print("QUESTION SECTION:",file= f)
#   print(domain_name[i] + "        " + record_class + " " + record_type[i] +"\n",file= f)

#   # Recording the time to measure the time to resolve a domain name
#   t1 = int(round(time.time()*1000))

#   # Calling the dig function to start resolving the user entered domain name
#   ans= mydig(domain_name[i], record_type[i], rootservers, record_class)
#   # print(cname)
#   # if cname=="cname":
#   #     while cname=="cname":
#   #       print("##########################")
#   #       print(str(ans).split(" ")[-1])
#   #       print("##########################")
#   #       ans,cname = dig(domain_name, record_type, (str(ans).split(" ")[-1]), record_class)
#   #       if ans:
#   #         print(ans)

#   # Recording the time once the resolution is complete
#   t2=int(round(time.time()*1000))
#   #print(ans)
#   # Printing the answer section
#   print("ANSWER SECTION:",file= f)
#   for ele in ans:
#     # print(ele)
#     # a = str(ele).split(" ")
#     # print(a)
#     # a.pop(0)
#     # (a.pop(0))
#     # print(domain_name + " " + " ".join(a)+"\n")
#     print(domain_name[i]+ "        " + record_class + " A " + str(ele),file= f)
#   print("\n",file= f)
#   # Printing the query time, the date and time of the resolution and the size of the message received
#   print("QUERY TIME: "+ str(t2-t1)+"msec",file= f)
#   print("WHEN: ", datetime.date.today().strftime("%A"), datetime.date.today().strftime(
#                               "%B"), datetime.date.today().strftime(
#                               "%d"), datetime.datetime.now(), datetime.date.today().strftime("%Y"),file= f)
#   print("MSG SIZE rcvd: ", sys.getsizeof(ans),file= f)
#   print("",file= f)
# f.close()