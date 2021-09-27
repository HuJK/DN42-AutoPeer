import re
import os
import time
import errno
import asyncio
import tornado
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
        if self.proto == "git":
            return self.whois.query(query)
        else:
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
rewrite "^/([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)$" /inetnum/$1.$2.$3.$4_$5 last;
rewrite "^/([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$" /inetnum/$1.$2.$3.$4_32 last;
rewrite "^/([0-9a-fA-F:]+)/([0-9]+)$" /inet6num/$1_$2 last;
rewrite "^/([0-9a-fA-F:]+)$" /inet6num/$1_128 last;
rewrite "^/([^/]+)-([Dd][Nn]42)$" /person/$1-DN42 last;
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
    def query(self,query):
        query = query.strip()
        if time.time() - self.pulltime > self.cooldown:
            self.repo.remotes.origin.pull()
            self.pulltime = time.time()
        query = add_prefix(query)
        if query.startswith("inetnum/") or query.startswith("inet6num/") or query.startswith("route/") or query.startswith("route6/"):
            if query.startswith("inetnum/") or query.startswith("route/"):
                max_length=32
            elif query.startswith("inet6num/") or query.startswith("route6/"):
                max_length=128
            body,length = query.split("_")
            prefix,ip = body.split("/",1)
            length = int(length)
            if length > max_length:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
            for i in range(length,-1,-1):
                try:
                    try_net = ipaddress.ip_network(ip + "/" + str(i),strict=False)
                    return self.file_query(prefix + "/" + str(try_net.network_address) + "_" + str(i))
                except FileNotFoundError as e:
                    pass
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
            return "\n".join(result_item)
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
        if query.startswith("inetnum/") or query.startswith("inet6num/") or query.startswith("route/") or query.startswith("route6/"):
            if query.startswith("inetnum/") or query.startswith("route/"):
                max_length=32
            elif query.startswith("inet6num/") or query.startswith("route6/"):
                max_length=128
            body,length = query.split("_")
            prefix,ip = body.split("/",1)
            length = int(length)
            if length > max_length:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
            http_quaries = [ asyncio.create_task(self.http_query(prefix + "/" + str(ipaddress.ip_network(ip + "/" + str(i),strict=False).network_address) + "_" + str(i))) for i in range(length,-1,-1)]
            result = ""
            for i in range(0,length+1):
                try:
                    result = await http_quaries[i]
                    for j in range(i+1,length+1):
                        http_quaries[j].cancel()
                    return result
                except FileNotFoundError as e:
                    pass
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
        else:
            return await self.http_query(query)
    async def http_query(self,query):
        client = tornado.httpclient.AsyncHTTPClient()
        try:
            response = await client.fetch(self.url + "/" + query)
            result = response.body.decode("utf8")
            result_item = result.split("\n")
            result_item = list(filter(lambda l:not l.startswith("%") and ":" in l,result_item))
            return "\n".join(result_item)
        except HTTPClientError as e:
            if e.code == 404:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), query)
            raise e
            
            
            

def whois_server():
    import socket
    HOST = '0.0.0.0'
    PORT = 43

    print('prepareing for whois...')
    my_whois = git_whois("https://github.com/KusakabeSi/dn42-registry","whoisdata",600)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    print('server start at: %s:%s' % (HOST, PORT))
    print('wait for connection...')

    while True:
        try:
            conn, addr = s.accept()
            query = b""
            while True:
                indata = conn.recv(1024)
                query += indata
                if len(indata) == 0: # connection closed
                    conn.close()
                    break
                if b"\n" in indata:
                    try:
                        print("WHOIS query: " + query.decode().strip())
                        outdata = my_whois.query(query.decode())
                    except Exception as e:
                        outdata = "% Not found"
                    conn.send(outdata.encode())
                    conn.close()
                    break
        except Exception as e:
            conn.close()
            #raise(e)
            print(e)
        
    server.bind(("127.0.0.1",43))
if __name__ == '__main__':
    whois_server()
