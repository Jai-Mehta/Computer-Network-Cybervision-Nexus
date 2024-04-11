
import requests
import re
import sys
import dns
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import time
import datetime
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
rootservers=['198.41.0.4','199.9.14.201','192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241','192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30','193.0.14.129','199.7.83.42','202.12.27.33']

if len(sys.argv) < 3:
    print("please provide the domain and record type")
    exit()
d_name = sys.argv[1]
rdtype = sys.argv[2]
if rdtype!="A":
  print("Only A record type will be resolved!")
  exit()
# record_class = "IN"
# dname = "www.verisignlabs.com"
# rdtype = "A"
qname = dns.name.from_text(d_name)
labels = qname.labels
max_iterations = len(labels)
index = 1
validate_root = 0
root_dslist = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5', '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']
def query(domain_name, record_type, server):
    # We extract the do,main name from text to pass in to the main query, it returns an object of type dns.name.Name
    input_name = dns.name.from_text(str(domain_name))
    # We pass the Name object to make_ query function to formulate a query in the format to be sent. It will randomly choose query id and set the flags ot RD. This returns an object of type dns.message.QueryMessage
    query_name = dns.message.make_query(input_name, record_type, want_dnssec=True)
    # dns.message.Message object is passed to the udp query that is to be sent to the server, which returns a response of type dns.message.Message. This message object has fields like Additional, Answer and Authority which further need to be evaluated.
    response = dns.query.udp(query_name, server, timeout=1)
    # Checking the flags of the reponse and storing them in flags variable to be returned
    return response
# Function to retrieve delegation signers and hashing algorithm
def retrieve_delsigner_hash(resp_ans_or_auth):
    hashing = {1:'SHA1',2:'SHA256'}
    for line in resp_ans_or_auth:
      if (line.rdtype == dns.rdatatype.DS):
        ds = line[0]
        hash = hashing[line[0].digest_type]
    return ds,hash
# Function to retrieve the Key Signing Key
def retrieve_kkey(resp_ans_or_auth):
  for line in resp_ans_or_auth:
    ksk = None
    if (line.rdtype == dns.rdatatype.DNSKEY):
      for record in line:
        if record.flags == 257: 
          ksk = record
          return ksk
  return ksk
# Function to retrieve the Key Signing Key
def retrieve_rrset(resp_ans_or_auth):
  for line in resp_ans_or_auth:
    rrset = None
    if (line.rdtype == dns.rdatatype.DNSKEY):
      return line
  return rrset
# Function to retrieve the Zone Signing Key
def retrieve_zskey(resp_ans_or_auth):
  for line in resp_ans_or_auth:
    zsk = None
    if (line.rdtype == dns.rdatatype.DNSKEY):
      for record in line:
        if record.flags == 256: 
          zsk = record
          return zsk
  return zsk
# Dunction to retrieve the RRsig from the response
def retrieve_rrsig(ans):
	if len(ans) == 0:
		return None
	for entry in ans:
		if (entry.rdtype == dns.rdatatype.RRSIG):
			return entry
	return None
# Function for verifying the digests as apart of the final verification after each validation round
def verification(domain_name, current_server, next_server):
  ds = query(domain_name, dns.rdatatype.DS, current_server)
  key = query(domain_name, dns.rdatatype.DNSKEY, next_server)
  if not key.answer:
    print("DNSSEC not supported!")
    return False
  KSK = None
  KSK = retrieve_kkey(key.answer)
  if not KSK:
    print("Key Signing Key not generated!")
    return False
  for ele in ds.answer:
    if ele.rdtype==43: #DS
      delegation_signer = ele
      pass
    
  # if not ds.items:
  #   print("No delegation signers available!")
  #   return False
  if not delegation_signer:
    print("No delegation signers available!")
    return False
  else:
    DS, hash = retrieve_delsigner_hash(ds.answer)
  nextds = dns.dnssec.make_ds(domain_name,KSK, hash)
  if nextds.digest!=DS.digest:
    print("DNSSEC configured, but verification failed!")
    return False
  return True
time_out = 0
def dig_dnssec(name, rdclass, rdtype, nameservers, tflag):
    global root_dslist
    global max_iterations
    global sp
    global time_out
    global index
# we use this variable to check has our root been verified. Once it is verifies we can move further
    global validate_root
    qname = dns.name.from_text(name)
    labels = qname.labels
    for ns in nameservers:
        ns = str(ns)
        try: 
            current_part = None
            if index<max_iterations+1:
              index = index+1
            if index < max_iterations+1:
                current_part = str(qname.split(index)[1])
            if validate_root==0:
              root_q = query('.', dns.rdatatype.DNSKEY, ns)
              if not root_q:
                return 1,None
              RRSIG = retrieve_rrsig(root_q.answer)
              RRSET = retrieve_rrset(root_q.answer)
              print(RRSET.rdtype)
              KSK = retrieve_kkey(root_q.answer)
              hash = dns.dnssec.make_ds('.', KSK, 'sha256')
              for dels in root_dslist:
                if str(dels) == str(hash):
                  print("Root Hashes Match!")
                  try:  
                    dns.dnssec.validate(RRSET, RRSIG, {dns.name.from_text('.'): RRSET})
                  except:
                    print("Root Verification Failed")
                    # For debugging hav ekept this line. if validate function works, not required.
                    getkey = root_q
                    # print(getkey.answer[0].rdtype)
                    # if current_part is not None:
                    #   getkey = query(current_part, 48, ns)
                    #return 1, None
                    #return 1, None
              validate_root = 1
            else:
              if current_part is not None:
                getkey = query(current_part, 48, ns)
            if current_part is not None:
                getrecord = query(qname, rdtype, ns)
                #getkey = query(current_part, 48, ns)
                zsk = None
                if len(getkey.answer) > 0:
                    zsk = retrieve_zskey(getkey.answer)
                    # print(getkey.answer)
                    # print("RRSET",getkey.answer[0].rdtype)
                    # print(getkey.answer[0])
                    # print("RRSIG",getkey.answer[1].rdtype)
                    # print(getkey.answer[1])

                    try:
                        ## Verify the DNS Keys ##
                        #print("Hii:",getkey.answer[1].rdtype)
                        dns.dnssec.validate(getkey.answer[0], getkey.answer[1], {(dns.name.from_text(current_part)):getkey.answer[0]})

                    except:
                      print("1 DNSSEC is configured but failed here")
                      return 1, None
                if len(getrecord.answer) > 0 and len(getkey.answer) > 0:
                    zsk = getkey.answer[0]
                    try:
                        ## Verify the RRsig from answer ##
                        dns.dnssec.validate(getrecord.answer[0], getrecord.answer[1], {(dns.name.from_text(current_part)):getkey.answer[0]})
                    except:
                      print("2 DNSSEC is configured but failed here")
                      return 1, None
                elif len(getrecord.authority) > 0 and len(getkey.answer) > 0:
                    zsk = getkey.answer[0]
                    try:
                        ## Verify the RRsig from authority ##
                        dns.dnssec.validate(getrecord.authority[1], getrecord.authority[2], {(dns.name.from_text(current_part)):getkey.answer[0]})
                    except:
                      print("3 DNSSEC is configured but failed here")
                      return 1, None
                else:
                    print("DNSSEC is not supported")
                    return 1, None
            q = dns.message.make_query(qname, rdtype)
            r = dns.query.tcp(q, ns, timeout=1)
            if len(r.answer) > 0:
                for ans in r.answer:
                    if (ans.rdtype == 1):
                        return 1, r
#Checking if there is a CNAME and resolving it if present.
                for ans in r.answer:
                    if (ans.rdtype == 5):
                        cname = str(ans.items[0].target)
                        done, r = dig_dnssec(cname, rdclass, rdtype, rootservers, 1)
                        if done:
                           return 1, r
            elif len(r.additional) > 0:
                add = []
                for x in r.additional:
                    if x.rdtype == 1:
                        for item in x.items:
#Verifying by comparing the hashed digests 
                            result = verification(r.authority[0].name, ns, item.address)
                            if not result:
                                return 1, None
                            elif result and time_out==1:
                              print("DNSSEC is verified for this website!")
                              return 1, None
                              #print(r.answer)
                            add.append(str(item))
                done, r = dig_dnssec(name, rdclass, rdtype, add, 1)
                if done:
                    return 1, r
            elif len(r.authority) > 0:
                ip = []
                for x in r.authority:
                    for ns in x.items:
                        done, r = dig_dnssec(str(ns), rdclass, "A", rootservers, 1)
                        if done and r is not None:
                            for ans in r.answer:
                                for item in ans.items:
                                    ip.append(str(item))
                done, r = dig_dnssec(name, rdclass, rdtype, ip, 1)
                if done:
                    return 1, r
        except dns.exception.Timeout:
            print ("Timeout\n")
    return None, None
	
done, r = dig_dnssec(d_name, "IN", "A", rootservers, 1)
if r is not None:
    print("DNSSEC is configured and validated here!")
    print(r)

# dns.rdatatype.to_text(48)

# dns.rdatatype.to_text(46)

# dns.rdatatype.to_text(43)

# qname = "www.verisignlabs.com"
# qname = dns.name.from_text(qname)
# print(qname.labels)
# print(len(qname.labels))
# for i in range(1,len(qname.labels)):
#   print(qname.split(i)[1])