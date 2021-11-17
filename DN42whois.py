import re
import os
import time
import errno
import asyncio
import tornado
import traceback
from git import Repo
import ipaddress
from tornado.httpclient import HTTPClientError
from urllib.parse import urlparse
class whois():
    def __init__(self, proto, url):
        self.proto = proto
        if proto == "tcp":
            self.whois = tcp_whois(url)
        elif proto == "git":
            self.whois = git_whois(url,"dn42data",600)
        elif proto == "http" or proto == "https":
            if not url.startswith("http"):
                url = proto + "://" + url
            self.whois = http_whois(url)
        else:
            raise Exception("Support tcp or git only")
    async def query(self,query):
        return await self.whois.query(query)

prefixes = {"as-block","as-set","aut-num","dns","inet6num","inetnum","key-cert","mntner","organisation","person","registry","role","route","route6","route-set","schema","tinc-key"}

def remove_prefix(query):
    if "/" in query:
        prefix, body = query.split("/",1)
        if prefix in prefixes:
            query = body
    return query

ngc = """Copy from https://lantian.pub/article/modify-website/serve-dn42-whois-with-nginx.lantian
rewrite "^/([0-9]{1})$" /aut-num/AS424242000$1 last;
rewrite "^/([0-9]{2})$" /aut-num/AS42424200$1 last;
rewrite "^/([0-9]{3})$" /aut-num/AS4242420$1 last;
rewrite "^/([0-9]{4})$" /aut-num/AS424242$1 last;
rewrite "^/([Aa][Ss]|)([0-9]+)$" /aut-num/AS$2 last;
rewrite "^/([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)[/_]([0-9]+)$" /inet_route/$1.$2.$3.$4_$5 last;
rewrite "^/([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$" /inet_route/$1.$2.$3.$4_32 last;
rewrite "^/([0-9a-fA-F:]+)[/_]([0-9]+)$" /inet_route6/$1_$2 last;
rewrite "^/([0-9a-fA-F:]+)$" /inet_route6/$1_128 last;
rewrite "^/([^/]+)-([Dd][Nn]42)$" /person/$1-DN42 last;
rewrite "^/([^/]+)-([Nn][Ee][Oo][Nn][Ee][Tt][Ww][Oo][Rr][Kk])$" /person/$1-NEONETWORK last;
rewrite "^/([^/]+)-([Mm][Nn][Tt])$" /mntner/$1-MNT last;
rewrite "^/([^/]+)-([Ss][Cc][Hh][Ee][Mm][Aa])$" /schema/$1-SCHEMA last;
rewrite "^/([Oo][Rr][Gg])-(.+)$" /organisation/ORG-$2 last;
rewrite "^/([Ss][Ee][Tt])-(.+)-([Tt][Ii][Nn][Cc])$" /tinc-keyset/SET-$2-TINC last;
rewrite "^/([^/]+)-([Tt][Ii][Nn][Cc])$" /tinc-key/$1-TINC last;
rewrite "^/([Rr][Ss])-(.+)$" /route-set/RS-$2 last;
rewrite "^/([Aa][Ss])([0-9]+)-([Aa][Ss])([0-9]+)$" /as-block/$1$2-$3$4 last;
rewrite "^/[Aa][Ss](.+)$" /as-set/AS$1 last;
rewrite "^/[Pp][Gg][Pp][Kk][Ee][Yy][-](.+)$" /key-cert/PGPKEY-$1 last;
rewrite "^/([^/]+)$" /dns/$1 last;"""

def add_prefix(query):
    if "/" in query:
        prefix, body = query.split("/",1)
        if prefix in prefixes:
            return query
    for c in filter(lambda x:"rewrite" in x, ngc.split("\n")):
        matches = re.finditer(r"\"(.*)\" (.*) last", c, re.MULTILINE)
        sub_re, replace_pattern = list(matches)[0].groups()
        sub_re = sub_re[0] + sub_re[2:]
        required_group_num = max( map( lambda x:int(x.groups()[0]), re.finditer(r"\$(\d+)", replace_pattern, re.MULTILINE)))
        sub_match = list( map( lambda x:x.groups(), re.finditer(sub_re, query, re.MULTILINE) ))
        sub_matches = []
        if len(sub_match) == 1:
            sub_matches = sub_match[0]
        if len(sub_matches) >= required_group_num:
            for i in range(required_group_num):
                replace_pattern = replace_pattern.replace("$" + str(i+1),sub_matches[i])
            return replace_pattern[1:]

def proc_data(data_in):
    ret_dict = {}
    for data_in_item in data_in.split("\n"):
        if len(data_in_item) == 0:
            continue
        if data_in_item[0] == "%":
            continue
        if ":" not in data_in_item:
            continue
        key , val = data_in_item.split(":",1)
        val = val.lstrip()
        if key in ret_dict:
            ret_dict[key] += [val]
        else:
            ret_dict[key] = [val]
    return ret_dict

class tcp_whois():
    def __init__(self, url):
        self.host, self.port = url.rsplit(":",1)
        self.port = int(self.port)
    async def query(self,query):
        query = remove_prefix(query)
        return await self.socket_query(query)
    async def socket_query(self,query):
        query = query.strip()
        reader, writer = await asyncio.open_connection(self.host, self.port)
        writer.write(query.encode("utf8"))
        writer.write("\n".encode("utf8"))
        await writer.drain()
        writer.write_eof()
        data = await reader.read()
        writer.close()
        await writer.wait_closed()
        result = data.decode("utf8")
        result_item = result.split("\n")
        result_item = list(filter(lambda l:not l.startswith("%") and ":" in l,result_item))
        if len(result_item) == 0:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
        return "\n".join(result_item)

class git_whois():
    def __init__(self, url, local_git,pull_cooldown):
        os.environ['GIT_SSH_COMMAND'] = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        if not os.path.isdir(local_git):
            self.repo = Repo.clone_from(url, local_git,depth=1,env={'GIT_SSL_NO_VERIFY': '1'},config='http.sslVerify=false')
        else:
            self.repo = Repo(local_git)
            self.repo.remotes.origin.set_url(url)
        self.cooldown = pull_cooldown
        self.pulltime = time.time()
        self.local_git = local_git
        self.repo.remotes.origin.pull()
    async def query(self,query):
        query = query.strip()
        if time.time() - self.pulltime > self.cooldown:
            self.repo.remotes.origin.pull()
            self.pulltime = time.time()
        query = add_prefix(query)
        if query.startswith("inetnum/") or query.startswith("inet6num/") or query.startswith("route/") or query.startswith("route6/") or query.startswith("inet_route/") or query.startswith("inet_route6/"):
            if query.startswith("inetnum/") or query.startswith("route/") or query.startswith("inet_route/"):
                max_length=32
            elif query.startswith("inet6num/") or query.startswith("route6/") or query.startswith("inet_route6/"):
                max_length=128
            prefix,body = query.split("/",1)
            ip,length = ("",0)
            if "_" in body:
                ip,length = body.split("_")
                length = int(length)
            elif "/" in body:
                ip,length = body.split("/")
                length = int(length)
            else:
                ip = body
                length = max_length
            if length > max_length:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
            ret_result = ""
            inet_route_result = {"inet":False,"route":False}
            for i in range(length,-1,-1):
                try:
                    try_net = ipaddress.ip_network(ip + "/" + str(i),strict=False)
                    if prefix not in ("inet_route","inet_route6"):
                        return self.file_query(prefix + "/" + str(try_net.network_address) + "_" + str(i))
                    else:
                        query_body = str(try_net.network_address) + "_" + str(i)
                        if prefix == "inet_route":
                            qi = "inetnum/"
                            qr = "route/"
                        elif prefix == "inet_route6":
                            qi = "inet6num/"
                            qr = "route6/"
                        try:
                            if inet_route_result["inet"] == False:
                                ret_result += self.file_query(qi + query_body)
                                inet_route_result["inet"] = True
                        except FileNotFoundError as e:
                            pass
                        try:
                            if inet_route_result["route"] == False:
                                ret_result += self.file_query(qr + query_body)
                                inet_route_result["route"] = True
                        except FileNotFoundError as e:
                            pass
                        if inet_route_result["inet"] == True and inet_route_result["route"] == True:
                            break
                except FileNotFoundError as e:
                    pass
            if ret_result != "":
                return ret_result
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
        else:
            return self.file_query(query)
    def file_query(self,query):
        path = os.path.join(self.local_git , "data" , query )
        try:
            response = open(path,"rb").read()
            result = response.decode("utf8")
            result_item = result.split("\n")
            result_item = list(filter(lambda l:not l.startswith("%") and ":" in l,result_item))
            return f"% Information related to '{query}':\n" + "\n".join(result_item) + "\n\n"
        except FileNotFoundError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)

            
class http_whois():
    def __init__(self, url):
        if not url.startswith("http"):
            raise Exception('URL not startswith "http"')
        self.url = url
    async def query(self,query):
        query = query.strip()
        query = add_prefix(query)
        if query.startswith("inetnum/") or query.startswith("inet6num/") or query.startswith("route/") or query.startswith("route6/") or query.startswith("inet_route/") or query.startswith("inet_route6/"):
            if query.startswith("inetnum/") or query.startswith("route/") or query.startswith("inet_route/"):
                max_length=32
            elif query.startswith("inet6num/") or query.startswith("route6/") or query.startswith("inet_route6/"):
                max_length=128
            prefix,body = query.split("/",1)
            ip,length = ("",0)
            if "_" in body:
                ip,length = body.split("_")
                length = int(length)
            elif "/" in body:
                ip,length = body.split("/")
                length = int(length)
            else:
                ip = body
                length = max_length
            if length > max_length:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
            ret_result = ""
            inet_route_result = {"inet":False,"route":False}
            http_prequaries = {}
            loop = asyncio.get_event_loop()
            for i in range(length,-1,-1):
                try_net = ipaddress.ip_network(ip + "/" + str(i),strict=False)
                if prefix not in ("inet_route","inet_route6"):
                    qq  = prefix + "/" + str(try_net.network_address) + "_" + str(i)
                    http_prequaries[qq] = loop.create_task(self.http_query(qq))
                else:
                    query_body = str(try_net.network_address) + "_" + str(i)
                    if prefix == "inet_route":
                        qi = "inetnum/"
                        qr = "route/"
                    elif prefix == "inet_route6":
                        qi = "inet6num/"
                        qr = "route6/"
                    http_prequaries[qi + query_body] = loop.create_task(self.http_query(qi + query_body))
                    http_prequaries[qr + query_body] = loop.create_task(self.http_query(qr + query_body))
            for i in range(length,-1,-1):
                try:
                    try_net = ipaddress.ip_network(ip + "/" + str(i),strict=False)
                    if prefix not in ("inet_route","inet_route6"):
                        return self.file_query(prefix + "/" + str(try_net.network_address) + "_" + str(i))
                    else:
                        query_body = str(try_net.network_address) + "_" + str(i)
                        if prefix == "inet_route":
                            qi = "inetnum/"
                            qr = "route/"
                        elif prefix == "inet_route6":
                            qi = "inet6num/"
                            qr = "route6/"
                        try:
                            if inet_route_result["inet"] == False:
                                ret_result += await http_prequaries[qi + query_body]
                                inet_route_result["inet"] = True
                        except FileNotFoundError as e:
                            pass
                        try:
                            if inet_route_result["route"] == False:
                                ret_result += await http_prequaries[qr + query_body]
                                inet_route_result["route"] = True
                        except FileNotFoundError as e:
                            pass
                        if inet_route_result["inet"] == True and inet_route_result["route"] == True:
                            break
                except FileNotFoundError as e:
                    pass
            for k,q in http_prequaries.items():
                q.cancel()
            if ret_result != "":
                return ret_result
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
        else:
            return await self.http_query(query)
    async def http_query(self,query):
        client = tornado.httpclient.AsyncHTTPClient()
        try:
            response_f = client.fetch(self.url + "/" + query)
            response = await response_f
            result = response.body.decode("utf8")
            result_item = result.split("\n")
            result_item = list(filter(lambda l:not l.startswith("%") and ":" in l,result_item))
            return f"% Information related to '{query}':\n" + "\n".join(result_item) + "\n\n"
        except asyncio.CancelledError:
            response_f.cancel()
            client.close()
            return ""
        except HTTPClientError as e:
            if e.code == 404:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
            raise e

def get_whois_hendler(my_whois):
    async def whois_hendler(reader, writer):
        try:
            query = b""
            while True:
                indata = await reader.read(1024)
                query += indata
                if len(indata) == 0: # connection closed
                    writer.close()
                    break
                if b"\n" in indata:
                    try:
                        print("WHOIS query: " + query.decode().strip())
                        outdata = await my_whois.query(query.decode())
                    except Exception as e:
                        traceback.print_exc()
                        outdata = "% Not found"
                    writer.write(outdata.encode())
                    await writer.drain()
                    writer.close()
                    break
        except Exception as e:
            traceback.print_exc()
    return whois_hendler
            
async def whois_server():
    HOST = '0.0.0.0'
    PORT = 43
    print('prepareing for whois...')
    my_whois = git_whois("https://github.com/KusakabeSi/dn42-registry","whoisdata",600)
    #my_whois = http_whois("https://cdn.jsdelivr.net/gh/KusakabeSi/dn42-registry/data")
    
    whois_hendler = get_whois_hendler(my_whois)
    print('server start at: %s:%s' % (HOST, PORT))
    server = await asyncio.start_server(whois_hendler,HOST,PORT)
    print('wait for connection...')
if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(whois_server())
    loop.run_forever()
