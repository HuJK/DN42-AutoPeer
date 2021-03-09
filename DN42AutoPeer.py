#!/usr/bin/python3
import os
import re
import jwt
import time
import yaml
import json
import asyncio
import random
import string
import socket
import base64
import hashlib
import OpenSSL
import requests
import datetime
import tornado.web
import tornado.gen
import tornado.ioloop
from urllib import parse
import tornado.httpclient
from Crypto.PublicKey import RSA
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from tornado.httpclient import HTTPClientError

my_paramaters = json.loads(open("my_parameters.json").read())
my_config = json.loads(open("my_config.json").read())

if my_config["jwt_secret"] == None:
    my_config["jwt_secret"] = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    open("my_config.json","w").write(json.dumps(my_config,indent=4,ensure_ascii=False))
jwt_secret = my_config["jwt_secret"]

wgconfpath = my_config["wgconfpath"]
bdconfpath = my_config["bdconfpath"]
client_valid_keys = ["peer_plaintext","peer_signature", "peerASN", "hasIPV4", "peerIPV4", "hasIPV6", "peerIPV6", "hasIPV6LL", "peerIPV6LL", "hasHost", "peerHost", "peerWG_Pub_Key", "peerContact", "PeerID"]
dn42_whois_server = my_config["dn42_whois_server"]
dn42repo_base = my_config["dn42repo_base"]
DN42_valid_ipv4s = my_config["DN42_valid_ipv4s"]
DN42_valid_ipv6s = my_config["DN42_valid_ipv6s"]
valid_ipv6_lilos = my_config["valid_ipv6_linklocals"]

method_hint = {"ssh-rsa":"""
<h4>Paste following command to your terminal to get your signature.</h4>
<code>
# copy your ssh private key to ~/.ssh/id_rsa_tosign<br>
cp ~/.ssh/id_rsa ~/.ssh/id_rsa_tosign<br>
# convert the private key from RFC4716 into PEM format<br>
ssh-keygen -p -N "" -m pem -f ~/.ssh/id_rsa_tosign<br>
# sign message with your private key, then convert to base64 form<br>
echo -n "{text2sign}"  | openssl dgst -sign ~/.ssh/id_rsa_tosign | openssl base64<br>
# Delete converted private key<br>
rm ~/.ssh/id_rsa_tosign<br>
# Done. You can copy the signature now<br>
</code>"""}

async def get_signature_html(baseURL,paramaters):
    peerASN = paramaters["peerASN"]
    peerMNT = await get_mntner_from_asn(peerASN)
    methods = await get_auth_method(peerMNT)
    text2sign = jwt.encode({'ASN': peerASN, "exp":datetime.datetime.utcnow() + datetime.timedelta(hours = 1) }, jwt_secret, algorithm='HS256')
    methods_class = {"Supported":{},"Unsupported":{}}
    for m,v in methods:
        if m in method_hint:
            if m not in methods_class["Supported"]:
                methods_class["Supported"][m] = []
            methods_class["Supported"][m] += [v]
        else:
            if m not in methods_class["Unsupported"]:
                methods_class["Unsupported"][m] = []
            methods_class["Unsupported"][m] += [v]
    retstr = f"""<!DOCTYPE html>
<html>
<style type="text/css">
* {{
    font-family: "Lucida Console", "Courier New", monospace;
}}
code {{display: block; /* fixes a strange ie margin bug */font-family: Courier New;font-size: 11pt;overflow:auto;background: #f0f0f0 url(data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAsAAASwCAYAAAAt7rCDAAAABHNCSVQICAgIfAhkiAAAAQJJREFUeJzt0kEKhDAMBdA4zFmbM+W0upqFOhXrDILwsimFR5pfMrXW5jhZr7PwRlxVX8//jNHrGhExjXzdu9c5IiIz+7iqVmB7Hwp4OMa2nhhwN/PRGEMBh3Zjt6KfpzPztxW9MSAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzB8HS+J9kUTvzEDMwAAAABJRU5ErkJggg==) left top repeat-y;border: 10px solid white;padding: 10px 10px 10px 21px;max-height:1000px;line-height: 1.2em;}}
table {{
  table-layout: fixed;
  width: 100%;
}}

table td {{
    word-wrap: break-word;         /* All browsers since IE 5.5+ */
    overflow-wrap: break-word;     /* Renamed property in CSS3 draft spec */
}}
table, th, td {{
  border: 1px solid black;
  border-collapse: collapse;
}}
input[type="text"] {{
  width: 100%;
}}
</style>
<body>

<h2>DN42 Automatic Peering</h2>
"""
    if len(methods_class["Supported"]) == 0:
        retstr += f"""<h3>Sorry, we couldn't find any available authentication method in <a href="{baseURL}/data/mntner/{peerMNT}" target="_blank">your DN42 profile</a>.</h3>"""
        retstr += f"<p>Please contact my to peer manually.</p>"
    else:
        retstr += f"""<h3>Sign our message with your private key registered in <a href="{baseURL}/data/mntner/{peerMNT}" target="_blank">your DN42 profile</a> to get your signature</h3>"""
    if len(methods_class["Supported"]) + len(methods_class["Unsupported"]) == 0:
        retstr += f"""<h3>There are no any "auth" section in yout profile</h3>"""
    retstr += "<h4>Supported auth method: </h4>" if len(list(methods_class["Supported"].keys())) != 0 else ""
    for m,v in methods_class["Supported"].items():
        retstr += f"""<table><tr><td><b>{m}</b></td></tr>"""
        for v_item in v:
            retstr += f"""<tr><td>{v_item}</td></tr>"""
        retstr += "</table>"
        retstr += method_hint[m].format(text2sign = text2sign.decode("utf8"))
    retstr += "<h4>Unupported auth method: </h4>" if len(list(methods_class["Unsupported"].keys())) != 0 else ""
    for m,v in methods_class["Unsupported"].items():
        retstr += f"""<table><tr><td><b>{m}</b></td></tr>"""
        for v_item in v:
            retstr += f"""<tr><td>{v_item}</td></tr>"""
        retstr += "</table>"
    retstr += f"""
<br>
<form action="/action_page.php" method="post">\n"""
    paramaters = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys }
    paramaters["peer_plaintext"] = text2sign.decode("utf8")
    for k,v in paramaters.items():
        if v == None:
            v = ""
        elif v == True:
            v = "on"
        retstr += f'<input type="hidden" name="{k}" value="{v}">\n'
    retstr +="""<input type="submit" name="action" value="OK" />
</form>

</body>
</html>
"""
    return retstr



def get_html(paramaters,peerSuccess=False):
    peer_plaintext = paramaters["peer_plaintext"]
    peer_signature = paramaters["peer_signature"]
    peerASN = paramaters["peerASN"]
    hasIPV4 = paramaters["hasIPV4"]
    peerIPV4 = paramaters["peerIPV4"]
    hasIPV6 = paramaters["hasIPV6"]
    peerIPV6 = paramaters["peerIPV6"]
    hasIPV6LL = paramaters["hasIPV6LL"]
    peerIPV6LL = paramaters["peerIPV6LL"]
    hasHost = paramaters["hasHost"]
    peerHost = paramaters["peerHost"]
    peerWG_Pub_Key = paramaters["peerWG_Pub_Key"]
    peerContact = paramaters["peerContact"]
    PeerID = paramaters["PeerID"]
    myASN = paramaters["myASN"]
    myHost = paramaters["myHost"]
    myIPV4 = paramaters["myIPV4"]
    myIPV6 = paramaters["myIPV6"]
    myIPV6LL = paramaters["myIPV6LL"]
    myWG_Pub_Key = paramaters["myWG_Pub_Key"]
    myContact = paramaters["myContact"]
    return f"""
<!DOCTYPE html>
<html>
<a href="https://github.com/HuJK/dn42-autopeer/" class="github-corner" aria-label="View source on GitHub"><svg width="80" height="80" viewBox="0 0 250 250" style="fill:#64CEAA; color:#fff; position: absolute; top: 0; border: 0; right: 0;" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a><style>.github-corner:hover .octo-arm{{animation:octocat-wave 560ms ease-in-out}}@keyframes octocat-wave{{0%,100%{{transform:rotate(0)}}20%,60%{{transform:rotate(-25deg)}}40%,80%{{transform:rotate(10deg)}}}}@media (max-width:500px){{.github-corner:hover .octo-arm{{animation:none}}.github-corner .octo-arm{{animation:octocat-wave 560ms ease-in-out}}}}</style>
<style type="text/css">
* {{
    font-family: "Lucida Console", "Courier New", monospace;
}}
table {{
  table-layout: auto;
  width: 100%;
}}
input[type="text"] {{
  width: 100%;
}}
textarea {{
  width: 100%;
  height:87px;
}}
</style>
<body>

<h2>DN42 Automatic Peering</h2>
<h3>{"Peer success! " if peerSuccess else "Please fill "}Your Info</h3>

<form action="/action_page.php" method="post">
 <table>
   <tr><td>Your ASN</td><td><input type="text" value="{peerASN if peerASN != None else ""}" name="peerASN" /></td></tr>
   <tr><td></td><td><input type="submit" name="action" value="Get Signature" /></td></tr>
   <tr><td>Plain text to sign</td><td><input type="text" value="{peer_plaintext}" name="peer_plaintext" readonly/></textarea></td></tr>
   <tr><td>Your signature</td><td><textarea name="peer_signature">{peer_signature}</textarea></td></tr>
   <tr><td><input type="checkbox" name="hasIPV4" {"checked" if hasIPV4 else ""}>DN42 IPv4</td><td><input type="text" value="{peerIPV4 if peerIPV4 != None else ""}" name="peerIPV4" /></td></tr>
   <tr><td><input type="checkbox" name="hasIPV6" {"checked" if hasIPV6 else ""}>DN42 IPv6</td><td><input type="text" value="{peerIPV6 if peerIPV6 != None else ""}" name="peerIPV6" /></td></tr>
   <tr><td><input type="checkbox" name="hasIPV6LL" {"checked" if hasIPV6LL else ""}>IPv6 Link local</td><td><input type="text" value="{peerIPV6LL if peerIPV6LL != None else ""}" name="peerIPV6LL" /></td></tr>
   <tr><td>Connectrion Info: </td><td>  </td></tr>
   <tr><td><input type="checkbox" name="hasHost" {"checked" if hasHost else ""}>Your Clearnet Host</td><td><input type="text" value="{peerHost if peerHost != None else ""}" name="peerHost" /></td></tr>
   <tr><td>Your WG Public Key</td><td><input type="text" value="{peerWG_Pub_Key}" name="peerWG_Pub_Key" /></td></tr>
   <tr><td>Your Telegram ID</td><td><input type="text" value="{peerContact}" name="peerContact" /></td></tr>
   <tr><td><input type="submit" name="action" value="Register" /></td><td>Register a new peer to get Peer ID</td></tr>
   <tr><td>Your Peer ID</td><td><input type="text" value="{PeerID if PeerID != None else ""}" name="PeerID" /></td></tr>
   <tr><td><input type="submit" name="action" value="Get Info" /><input type="submit" name="action" value="Delete" /></td><td>Get the info of an existening peer or delete it.</td></tr>
 </table>
</form>


<h3>{"Peer success! " if peerSuccess else "This is "}My Info</h3>


<form method="post">
 <table>
   <tr><td>My ASN</td><td><input type="text" value="{myASN}" readonly /></td></tr>
   <tr><td>DN42 IPv4</td><td><input type="text" value="{myIPV4}" readonly /></td></tr>
   <tr><td>DN42 IPv6</td><td><input type="text" value="{myIPV6}" readonly /></td></tr>
   <tr><td>IPv6 Link local</td><td><input type="text" value="{myIPV6LL}" readonly /></td></tr>
   <tr><td>Connectrion Info: </td><td>  </td></tr>
   <tr><td>My Clearnet Host</td><td><input type="text" value="{myHost}:{PeerID if PeerID != None else "{{Not assign yet, Register first}}"}" readonly /></td></tr>
   <tr><td>My WG Public Key</td><td><input type="text" value="{myWG_Pub_Key}" readonly /></td></tr>
   <tr><td>My Telegram ID</td><td><input type="text" value="{myContact}" readonly /></td></tr>
 </table>
</form>

</body>
</html>
"""

def proc_data(data_in):
    ret_dict = {}
    for data_in_item in filter(None,data_in.split("\n")):
        key , val = data_in_item.split(":",1)
        val = val.lstrip()
        if key in ret_dict:
            ret_dict[key] += [val]
        else:
            ret_dict[key] = [val]
    return ret_dict

async def socket_query(addr,message):
    host,port = addr.rsplit(":",1)
    port = int(port)
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(message.encode("utf8"))
    await writer.drain()
    writer.write_eof()
    data = await reader.read()
    writer.close()
    await writer.wait_closed()
    return data.decode("utf8")

async def whois_query(addr,query):
    result = await socket_query(addr,query + "\r\n")
    result_item = result.split("% Information related to ")[1:]
    result_item = list(map(lambda x:x.split("\n",1)[1],result_item))
    if len(result_item) == 0:
        raise FileNotFoundError(query)
    return result_item

async def get_mntner_from_asn(asn):
    client = tornado.httpclient.AsyncHTTPClient()
    asn_info = (await whois_query(dn42_whois_server, "aut-num/" + asn))[-1]
    return proc_data(asn_info)["mnt-by"][0]

async def get_mntner_info(mntner):
    client = tornado.httpclient.AsyncHTTPClient()
    mntner_info = (await whois_query(dn42_whois_server, "mntner/" + mntner))[-1]
    ret = proc_data(mntner_info)
    if "auth" not in ret:
        ret["auth"] = []
    return ret

async def get_auth_method(mntner):
    authes = (await get_mntner_info(mntner))["auth"]
    ret = []
    for a in authes:
        ainfo = a.split(" ",1)
        if len(ainfo) < 2:
            ainfo += [""] * (2-len(ainfo))
        ret += [ainfo]
    return ret

def verify_signature(plaintext,pub_key,raw_signature,method):
    if method=="ssh-rsa":
        signature_base64 = raw_signature.replace("\n","").replace("\r","")
        signature = base64.b64decode(signature_base64)
        ppp = OpenSSL.crypto.X509()
        pkk = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_PEM, RSA.importKey("ssh-rsa " + pub_key).exportKey())
        ppp.set_pubkey(pkk)
        OpenSSL.crypto.verify(cert=ppp,signature=signature,data = plaintext.encode("utf8"), digest = "sha256")
        return True
    raise NotImplementedError("method not implement")

async def verify_user_signature(peerASN,plaintext,raw_signature):
    sig_info = jwt.decode(plaintext.encode("utf8"),jwt_secret)
    if sig_info["ASN"] != peerASN:
        raise ValueError("JWT verification failed. You are not the mntner of " + sig_info["ASN"])
    supported_method= ["ssh-rsa"]
    mntner = await get_mntner_from_asn(peerASN)
    authes = await get_auth_method(mntner)
    tried = False
    authresult = [{"Your input":{"plaintext":plaintext,"signature":raw_signature}}]
    try:
        for method,pub_key in authes:
            try:
                if verify_signature(plaintext,pub_key,raw_signature,method) == True:
                    return True
            except Exception as e:
                authresult += [{"Method": method , "Result": type(e).__name__ + ": " + str(e), "Content":  pub_key}]
        raise ValueError(yaml.dump(authresult, sort_keys=False))
    catch Exception as e:
        r.__name__ = "SignatureError: " + r.__name__
        raise r

def get_err_page(paramaters,level,error):
    retstr =  f"""<!DOCTYPE html>
<html>
<style type="text/css">
* {{
    font-family: "Lucida Console", "Courier New", monospace;
}}
code {{display: block; /* fixes a strange ie margin bug */font-family: Courier New;font-size: 11pt;overflow:auto;background: #f0f0f0 url(data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAsAAASwCAYAAAAt7rCDAAAABHNCSVQICAgIfAhkiAAAAQJJREFUeJzt0kEKhDAMBdA4zFmbM+W0upqFOhXrDILwsimFR5pfMrXW5jhZr7PwRlxVX8//jNHrGhExjXzdu9c5IiIz+7iqVmB7Hwp4OMa2nhhwN/PRGEMBh3Zjt6KfpzPztxW9MSAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzB8HS+J9kUTvzEDMwAAAABJRU5ErkJggg==) left top repeat-y;border: 10px solid white;padding: 10px 10px 10px 21px;max-height:1000px;line-height: 1.2em;}}
table {{
  table-layout: auto;
  width: 100%;
}}
input[type="text"] {{
  width: 100%;
}}
</style>
<body>

<h2>DN42 Automatic Peering</h2>
<h3>{level}</h3>
{"<h3>" + type(error).__name__ + ":</h3>" if type(error) != str else ""}
<code><pre>{str(error)}</pre></code>
<form action="/action_page.php" method="post">\n"""
    paramaters = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys }
    for k,v in paramaters.items():
        if v == None:
            v = ""
        elif v == True:
            v = "on"
        retstr += f'<input type="hidden" name="{k}" value="{v}">\n'
    retstr +="""<input type="submit" name="action" value="OK" />
</form>

</body>
</html>"""
    return retstr

def check_valid_ip_range(IPclass,IPranges,ip,name):
    sum = 0
    if "/" in ip:
        raise ValueError(ip + " is not a valid IPv4 or IPv6 address")
    if IPclass(ip).num_addresses != 1:
        raise ValueError(ip + " contains more than one IP")
    for iprange in IPranges:
        if IPclass(iprange).supernet_of(IPclass(ip)):
            return True
    raise ValueError(ip + " is not a valid " + name + " address")
    

async def check_reg_paramater(paramaters):
    paramaters["PeerID"] = None
    if (paramaters["hasIPV4"] or paramaters["hasIPV6"] or paramaters["hasIPV6LL"]) == False:
        raise ValueError("You can't peer without any IP.")
    mntner = await get_mntner_from_asn(paramaters["peerASN"])
    if paramaters["hasIPV4"]:
        check_valid_ip_range(IPv4Network,DN42_valid_ipv4s,paramaters["peerIPV4"],"DN42 ip")
        peerIPV4_info = proc_data((await whois_query(dn42_whois_server,paramaters["peerIPV4"]))[-1])
        if peerIPV4_info["mnt-by"][0] != mntner:
            raise PermissionError("IP " + paramaters["peerIPV4"] + " owned by " + peerIPV4_info["mnt-by"][0] + " instead of " + mntner)
    else:
        paramaters["peerIPV4"] = None
    if paramaters["hasIPV6"]:
        check_valid_ip_range(IPv6Network,DN42_valid_ipv6,paramaters["peerIPV6"],"DN42 ipv6")
        peerIPV6_info = proc_data((await whois_query(dn42_whois_server,paramaters["peerIPV6"]))[-1])
        if peerIPV6_info["mnt-by"][0] != mntner:
            raise PermissionError("IP " + paramaters["peerIPV6"] + " owned by " + peerIPV6_info["mnt-by"][0] + " instead of " + mntner)
    else:
        paramaters["peerIPV6"] = None
    if paramaters["hasIPV6LL"]:
        check_valid_ip_range(IPv6Network,valid_ipv6_lilos,paramaters["peerIPV6LL"],"link-local ipv6")
    else:
        paramaters["peerIPV6LL"] = None
    print(paramaters["hasHost"])
    if paramaters["hasHost"]:
        if ":" not in paramaters["peerHost"]:
            raise ValueError("Parse Error, Host must looks like address:port .")
        hostaddr,port = paramaters["peerHost"].rsplit(":",1)
        port = int(port)
        addrinfo = socket.getaddrinfo(hostaddr,port)
    else:
        paramaters["peerHost"] = None
    return paramaters

def newConfig(paramaters):
    peerASN = paramaters["peerASN"][2:]
    peerKey = paramaters["peerWG_Pub_Key"]
    peerName = paramaters["peerContact"]
    myport=None
    peerHost = paramaters["peerHost"]
    peerIPV4 = paramaters["peerIPV4"]
    peerIPV6 = paramaters["peerIPV6"]
    peerIPV6LL = paramaters["peerIPV6LL"]
    
    myIPV4 = paramaters["myIPV4"]
    myIPV6 = paramaters["myIPV6"]
    myIPV6LL = paramaters["myIPV6LL"]
    myhost = paramaters["myHost"]
    myasn = paramaters["myASN"][2:]
    privkey = paramaters["myWG_Pri_Key"]
    publkey = paramaters["myWG_Pub_Key"]
    portlist = list(sorted(map(lambda x:int(x.split("-")[0]),filter(lambda x:x[-4:] == "conf", os.listdir(wgconfpath)))))
    # portlist=[23001, 23002, 23003,23004,23005,23006,23007,23008,23009,23088]
    if myport == None:
        port_range = [eval(my_config["wg_port_search_range"][0])(peerASN) , eval(my_config["wg_port_search_range"][1])(peerASN)]
        for p in range(*port_range):
            if p not in portlist:
                myport = p
                break
    
    if peerIPV6 == None:
        peerIPV6 = peerIPV6LL
    paramaters["PeerID"] = myport
    peerName = re.sub(r"[^A-Za-z0-9_]+", '', peerName)
    peerName = peerName[:10]
    peerName = peerName.replace("-","_")
    wsconf = f"""[Interface]
PrivateKey = {privkey}
ListenPort = {myport}

[Peer]
PublicKey = {peerKey} {chr(10) + "Endpoint = " + peerHost if peerHost != None else ""}
AllowedIPs = 0.0.0.0/0,::/0"""
    
    wssh = f"""#!/bin/bash
ip link add dev dn42-{peerName} type wireguard
wg setconf dn42-{peerName} {myport}-{peerName}.conf
ip link set dn42-{peerName} up
ip addr add {myIPV6LL}/64 dev dn42-{peerName}
"""
    wssh += f"""ip addr add {myIPV4} peer {peerIPV4} dev dn42-{peerName}
""" if peerIPV4 != None else ""
    wssh += f"""ip addr add {myIPV6} peer {peerIPV6} dev dn42-{peerName}
ip route add {peerIPV6}/128 src {myIPV6} dev dn42-{peerName}""" if peerIPV6 != None else ""
    
    birdconf = ""
    birdconf += f"""protocol bgp dn42_{peerName}_v4 from dnpeers {{
    neighbor {peerIPV4} as {peerASN};
    direct;
}};
""" if peerIPV4 != None else ""
    birdconf += f"""protocol bgp dn42_{peerName}_v6 from dnpeers {{
    neighbor {peerIPV6LL} % 'dn42-{peerName}' as {peerASN};
    direct;
}};""" if peerIPV6 != None else ""
    
    paramaters = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys }
    paramaters["peer_signature"] = ""
    paramaters["peer_plaintext"] = ""
    paramaters["peerName"] = peerName
    return {
        f"{wgconfpath}/{myport}-{peerName}.conf": wsconf,
        f"{wgconfpath}/{myport}-{peerName}.sh": wssh,
        f"{wgconfpath}/{myport}.yaml": yaml.dump(paramaters),
        f"{bdconfpath}/{myport}-{peerName}.conf": birdconf,
        "paramaters": paramaters
           }

def saveConfig(new_config):
    for path,content in new_config.items():
        print("================================")
        print(path)
        print(content)
        open(path,"w").write(content)
        if path[-2:] == "sh":
            os.chmod(path, 0o755)
            os.system(path)
        print("================================")
    os.system("birdc configure")
    return None

def deleteConfig(myport,peerName):
    print(f"ip link del dev dn42-{peerName}")
    print(f"rm {wgconfpath}/{myport}-{peerName}.conf")
    print(f"rm {wgconfpath}/{myport}-{peerName}.sh")
    print(f"rm {wgconfpath}/{myport}.yaml")
    print(f"rm {bdconfpath}/{myport}-{peerName}.conf")
    print(f"birdc configure")
    os.system(f"ip link del dev dn42-{peerName}")
    os.remove(f"{wgconfpath}/{myport}-{peerName}.conf")
    os.remove(f"{wgconfpath}/{myport}-{peerName}.sh")
    os.remove(f"{wgconfpath}/{myport}.yaml")
    os.remove(f"{bdconfpath}/{myport}-{peerName}.conf")
    os.system("birdc configure")
    return None

def get_key_default(D,k,d):
    if k in D and D[k] != "":
        return D[k]
    return d

def qsd2d(qsd):
    return {k:v[0] for k,v in qsd.items()}

async def action(paramaters):
    paramaters["action"]           = get_key_default(paramaters,"action","OK")
    paramaters["peer_plaintext"]   = get_key_default(paramaters,"peer_plaintext","")
    paramaters["peer_signature"]   = get_key_default(paramaters,"peer_signature","")
    paramaters["peerASN"]          = get_key_default(paramaters,"peerASN",None)
    paramaters["hasIPV4"]          = get_key_default(paramaters,"hasIPV4",False)
    paramaters["peerIPV4"]         = get_key_default(paramaters,"peerIPV4",None)
    paramaters["hasIPV6"]          = get_key_default(paramaters,"hasIPV6",False)
    paramaters["peerIPV6"]         = get_key_default(paramaters,"peerIPV6",None)
    paramaters["hasIPV6LL"]        = get_key_default(paramaters,"hasIPV6LL",False)
    paramaters["peerIPV6LL"]       = get_key_default(paramaters,"peerIPV6LL",None)
    paramaters["hasHost"]          = get_key_default(paramaters,"hasHost",False)
    paramaters["peerHost"]         = get_key_default(paramaters,"peerHost",None)
    paramaters["peerWG_Pub_Key"]   = get_key_default(paramaters,"peerWG_Pub_Key","")
    paramaters["peerContact"]      = get_key_default(paramaters,"peerContact","")
    paramaters["PeerID"]           = get_key_default(paramaters,"PeerID",None)
    paramaters["hasIPV4"] = True if (paramaters["hasIPV4"] == "on" or paramaters["hasIPV4"] == "True")  else False
    paramaters["hasIPV6"] = True if (paramaters["hasIPV6"] == "on" or paramaters["hasIPV6"] == "True") else False
    paramaters["hasIPV6LL"] = True if (paramaters["hasIPV6LL"] == "on" or paramaters["hasIPV6LL"] == "True") else False
    paramaters["hasHost"] = True if (paramaters["hasHost"] == "on" or paramaters["hasHost"] == "True") else False
    action = paramaters["action"]
    paramaters = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys }
    paramaters = {**paramaters, **my_paramaters} 
    try:
        try:
            if paramaters["PeerID"] != None:
                if int(paramaters["PeerID"]) <= 1024 or int(paramaters["PeerID"]) > 65535:
                    raise ValueError("Invalid PeerID")
        except Exception as e:
            paramaters["PeerID"] = None
            raise e
        if action=="OK":
            if paramaters["peerASN"] == None:
                paramaters["hasIPV4"] = True 
                paramaters["hasIPV6"] = True 
                paramaters["hasIPV6LL"] = True
                paramaters["hasHost"] = True 
            return get_html(paramaters,peerSuccess=False)
        if action == "Get Info":
            peerInfo = yaml.load(open(wgconfpath + "/" + paramaters["PeerID"] + ".yaml").read())
            peerInfo = { valid_key: peerInfo[valid_key] for valid_key in client_valid_keys }
            paramaters = {**paramaters,**peerInfo, **my_paramaters}
            return get_html(paramaters,peerSuccess=True)
        # Check ASN is valid for following action
        if paramaters["peerASN"] == None:
            raise ValueError("peerASN can't be null.")
        if paramaters["peerASN"].startswith("AS"):
            aaa = int(paramaters['peerASN'][2:])
        else:
            aaa = int(paramaters['peerASN'])
        #Actions need ASN
        if action=="Delete":
            await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_signature"])
            peerInfo = yaml.load(open(wgconfpath + "/" + paramaters["PeerID"] + ".yaml").read())
            if peerInfo["peerASN"] != paramaters["peerASN"]:
                raise PermissionError("peerASN not match")
            deleteConfig(peerInfo["PeerID"],peerInfo["peerName"])
            paramaters["PeerID"] = None
            return get_err_page(paramaters,"Success! ","Profile deleted:<br><br>" + yaml.dump(peerInfo,sort_keys=False).replace("\n","<br>"))
        elif action=="Get Signature":
            return await get_signature_html(dn42repo_base,paramaters)
        elif action == "Register":
            await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_signature"])
            paramaters = await check_reg_paramater(paramaters)
            new_config = newConfig(paramaters)
            paramaters = new_config["paramaters"]
            del new_config["paramaters"]
            saveConfig(new_config)
            paramaters = {**paramaters, **my_paramaters}
            return get_html(paramaters,peerSuccess=True)
        return get_err_page(paramaters,"Error",ValueError("Unknow action" + str(action)))
    except Exception as e:
        return get_err_page(paramaters,"Error",e)
    
    

class actionHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(actionHandler, self).__init__(*args, **kwargs)
    def set_default_headers(self, *args, **kwargs):
        # Just for fun, pretend I am a php server
        self.set_header('server','Microsoft-IIS/7.5')
        self.set_header('x-powered-by','PHP/5.4.2')
    async def get(self, *args, **kwargs): 
        paramaters = { k: self.get_argument(k) for k in self.request.arguments }
        ret = await action(paramaters)
        self.write(ret)
    async def post(self, *args, **kwargs): 
        paramaters = { k: self.get_argument(k) for k in self.request.arguments }
        ret = await action(paramaters)
        self.write(ret)
    
if __name__ == '__main__':
    app = tornado.web.Application(handlers=[
        (r'/', actionHandler),
        (r'/action_page.php', actionHandler),
        
    ])
    server = tornado.httpserver.HTTPServer(app, ssl_options=my_config["ssl_options"] )
    server.listen(my_config["listen_port"],my_config["listen_host"])
    tornado.ioloop.IOLoop.current().start()
