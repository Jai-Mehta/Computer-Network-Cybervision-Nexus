websites = ['Google.com','Youtube.com','Facebook.com','Baidu.com','Wikipedia.org','Reddit.com','Yahoo.com','Google.co.in',
            'Qq.com','Taobao.com','Amazon.com','Tmall.com','Twitter.com','Google.co.jp','Instagram.com','Live.com',
            'Vk.com','Sohu.com','Sina.com.cn','Jd.com','Weibo.com','360.cn','Google.de',
            'Google.co.uk','Google.com.br']
import time
import dns.resolver
def timefromlocaldig(websites):
  local_dig = dns.resolver.Resolver(configure=False)
  local_dig.nameservers=['130.245.255.4']
  time_list_local_dig = []
  for domain_name in websites: 
    t = []
    for i in range(10):
      t1 = int(round(time.time()*1000))
      ans= local_dig.resolve(domain_name,'A')
      t2=int(round(time.time()*1000))
      t.append(t2-t1)
    time_list_local_dig.append(sum(t)/len(t))
  return time_list_local_dig
print("LOCAL",timefromlocaldig(websites))
def timefromgoogledig(websites):
  local_google_dig = dns.resolver.Resolver(configure=False)
  local_google_dig.nameservers = ['8.8.8.8','8.8.4.4']
  time_list_google_dig = []
  for domain_name in websites: 
    t = []
    # Recording the time to measure the time to resolve a domain name
    for i in range(10):
      t1 = int(round(time.time()*1000))
      ans= local_google_dig.resolve(domain_name, 'A')
      t2=int(round(time.time()*1000))
      t.append(t2-t1)
    time_list_google_dig.append(sum(t)/len(t))
  return time_list_google_dig
print("GOOGLE",timefromgoogledig(websites))