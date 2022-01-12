#!/usr/bin/python3
import os
import re
import jwt
import time
import pgpy
import yaml
import json
import shlex
import errno
import shutil
import random
import string
import socket
import base64
import pathlib
import asyncio
import hashlib
import OpenSSL
import textwrap
import requests
import datetime
import ipaddress
import traceback
import tornado.web
import tornado.gen
from git import Repo
import tornado.ioloop
import multiprocessing
from urllib import parse
import tornado.httpclient
from Crypto.PublicKey import RSA
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from subprocess import Popen, PIPE, STDOUT
from tornado.httpclient import HTTPClientError
import DN42whois 
from DN42GIT import DN42GIT 

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--envfile",action='append', help="envfile", type=str)
parser.add_argument("-c", "--config",action='store', help="envfile", type=str)
parser.add_argument("-p", "--parms",action='store', help="envfile", type=str)
args = parser.parse_args()
envs = {}
if args.envfile:
    for efs in args.envfile:
        es = open(efs).read().split("\n")
        for e in es:
            if "=" in e:
                k,v = e.split("=",1)
                os.environ[k] = v
    
confpath = "my_config.yaml"
parmpath = "my_parameters.yaml"
if args.config:
    confpath = args.config
if args.parms:
    parmpath = args.parms
    
print("Starting...")
os.environ['GIT_SSH_COMMAND'] = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

my_paramaters = yaml.load(open(parmpath).read(),Loader=yaml.Loader)
my_config = yaml.load(open(confpath).read(),Loader=yaml.Loader)

if my_config["jwt_secret"] == None:
    my_config["jwt_secret"] = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    # open("confpath","w").write(yaml.dump(my_config))

jwt_secret = my_config["jwt_secret"]

def try_read_env(params,pkey,ekey,ValType=str,default=None):
    if ekey in os.environ:
        if ValType == bool:
            params[pkey] = os.environ[ekey].lower() == "true"
        elif ValType == "json":
            params[pkey] = json.loads( os.environ[ekey] )
        else:
            params[pkey] = ValType(os.environ[ekey])
        print(f"Load {pkey} from env, val: {params[pkey]}")
    if pkey not in params:
        if default == None:
            raise ValueError("default for " + pkey + " are not set")
        params[pkey] = default

use_speed_limit = False
if "WG_SPEED_LIMIT" in os.environ:
    try:
        if int(os.environ["WG_SPEED_LIMIT"]) > 0:
            use_speed_limit = True
    except:
        pass

try_read_env(my_paramaters,"myIPV4",'DN42_IPV4')
try_read_env(my_paramaters,"myIPV6",'DN42_IPV6')
try_read_env(my_paramaters,"myIPV4LL",'DN42_IPV4_LL')
try_read_env(my_paramaters,"myIPV6LL",'DN42_IPV6_LL')
try_read_env(my_paramaters,"myHost",'DN42AP_ENDPOINT')
try_read_env(my_paramaters,"myHostDisplay",'DN42AP_HOST_DISPLAY')
try_read_env(my_paramaters,"myHostHidden",'DN42AP_HOST_HIDDEN',bool,False)
try_read_env(my_paramaters,"myASN",'DN42_E_AS')
try_read_env(my_paramaters,"myContact",'DN42_CONTACT')
try_read_env(my_paramaters,"myWG_Pub_Key",'WG_PUBKEY')
try_read_env(my_paramaters,"allowExtNh",'DN42AP_ALLOW_ENH',bool,False)
try_read_env(my_config,"html_title",'DN42AP_TITLE')
try_read_env(my_config,"git_repo_url",'DN42AP_GIT_REPO_URL')
try_read_env(my_config,"listen_host",'DN42AP_LISTEN_HOST')
try_read_env(my_config,"listen_port",'DN42AP_PORT')
try_read_env(my_config,"myWG_Pri_Key",'WG_PRIVKEY')
try_read_env(my_config,"urlprefix",'DN42AP_URLPREFIX')
try_read_env(my_config,"wgconfpath",'DN42AP_WGCONFPATH')
try_read_env(my_config,"bdconfpath",'DN42AP_BIRDCONFPATH')
try_read_env(my_config,"gitsyncpath",'DN42AP_GIT_SYNC_PATH')
try_read_env(my_config,"admin_mnt",'DN42AP_ADMIN')
try_read_env(my_config,"register_redirect",'DN42AP_REGISTER_REDIRECT')
try_read_env(my_config,"wg_port_search_range",'DN42AP_PORT_RANGE',str)
try_read_env(my_config,"init_device",'DN42AP_INIT_DEVICE',bool)
try_read_env(my_config,"reset_wgconf_interval",'DN42AP_RESET_WGCONF',int,0)

RRstate_repo = DN42GIT(my_config["gitsyncpath"])

use_remote_command = ""
if "DN42AP_REMOTE_COMMAND" in os.environ:
    use_remote_command = os.environ['DN42AP_REMOTE_COMMAND']

def es2none(p):
    if p == "":
        return None
    return p

my_paramaters["myIPV4"] = es2none(my_paramaters["myIPV4"])
my_paramaters["myIPV6"] = es2none(my_paramaters["myIPV6"])
my_paramaters["myIPV6LL"] = es2none(my_paramaters["myIPV6LL"])
my_paramaters["myHost"] = es2none(my_paramaters["myHost"])
my_paramaters["myASN"] = my_paramaters["myASN"] if my_paramaters["myASN"].startswith("AS") else "AS" + my_paramaters["myASN"]


node_name = ""
try:
    node_name = os.environ['NODE_NAME']
except Exception as e:
    pass


wgconfpath = my_config["wgconfpath"]
bdconfpath = my_config["bdconfpath"]

pathlib.Path(wgconfpath + "/peerinfo").mkdir(parents=True, exist_ok=True)

client_valid_keys = ["peer_plaintext","peer_pub_key_pgp","peer_signature", "peerASN","peerName", "hasIPV4", "peerIPV4","hasIPV4LL","peerIPV4LL", "hasIPV6", "peerIPV6", "hasIPV6LL", "peerIPV6LL","MP_BGP","Ext_Nh", "hasHost", "peerHost", "peerWG_Pub_Key","peerWG_PS_Key", "peerContact", "PeerID","myIPV4LL","myIPV6LL","customDevice","customDeviceSetup","myWG_Pri_Key","transitMode","myWG_MTU"]
client_valid_keys_admin_only = ["customDevice","customDeviceSetup","myWG_Pri_Key","peerName"]
dn42repo_base = my_config["dn42repo_base"]
DN42_valid_ipv4s = my_config["DN42_valid_ipv4s"]
DN42_valid_ipv6s = my_config["DN42_valid_ipv6s"]
valid_ipv4_lilos = my_config["valid_ipv4_linklocals"]
valid_ipv6_lilos = my_config["valid_ipv6_linklocals"]
whois = DN42whois.whois(*my_config["dn42_whois_server"])
whois_query = whois.query

method_hint = {"ssh-rsa":"""<h4>Paste following command to your terminal to get your signature.</h4>
<code>
echo -n "{text2sign}" | ssh-keygen -Y sign -n dn42ap -f ~/.ssh/id_rsa
</code>""",
"ssh-ed25519":"""<h4>Paste following command to your terminal to get your signature.</h4>
<code>
echo -n "{text2sign}" | ssh-keygen -Y sign -n dn42ap -f ~/.ssh/id_ed25519
</code>""",
"pgp-fingerprint": """<h4>Paste following command to your terminal to get your PGP public key and signature.</h4>
<code>
# Export PGP public key<br>
gpg --armor --export<br>
<br>
# sign message with your PGP private key<br>
echo -n "{text2sign}" | gpg --clearsign --detach-sign<br>
<br>
# Done. You can copy the signature now<br>
</code>""",
"PGPKEY": """<h4>Paste following command to your terminal to get your PGP public key and signature.</h4>
<code>
# Export PGP public key<br>
gpg --armor --export<br>
<br>
# sign message with your PGP private key<br>
echo -n "{text2sign}" | gpg --clearsign --detach-sign<br>
<br>
# Done. You can copy the signature now<br>
</code>"""
}

async def get_signature_html(baseURL,paramaters):
    peerASN = paramaters["peerASN"]
    peerMNT, peerADM = await get_info_from_asn(peerASN)
    try:
        peerADMname = (await get_person_info(peerADM))["person"][0]
    except Exception as e:
        peerADMname = ""
    methods = await get_auth_method(peerMNT, peerADM)
    text2sign = jwt.encode({'ASN': peerASN, "exp":datetime.datetime.utcnow() + datetime.timedelta(minutes = 30) }, jwt_secret, algorithm='HS256')
    methods_class = {"Supported":{},"Unsupported":{}}
    for m,v in methods:
        if m in method_hint:
            if m not in methods_class["Supported"]:
                methods_class["Supported"][m] = []
            methods_class["Supported"][m] += [v]
            if m in { "PGPKEY" , "pgp-fingerprint" }:
                if paramaters["peer_pub_key_pgp"] == "":
                    paramaters["peer_pub_key_pgp"] = await try_get_pub_key(v)
        else:
            if m not in methods_class["Unsupported"]:
                methods_class["Unsupported"][m] = []
            methods_class["Unsupported"][m] += [v]
    retstr = f"""<!DOCTYPE html>
<html>
    <head>
        <title>{ my_config["html_title"] }</title>
        <a href="{ my_config["git_repo_url"] }" class="github-corner" aria-label="View source on GitHub"><svg width="80" height="80" viewBox="0 0 250 250" style="fill:#64CEAA; color:#fff; position: absolute; top: 0; border: 0; right: 0;" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a><style>.github-corner:hover .octo-arm{{animation:octocat-wave 560ms ease-in-out}}@keyframes octocat-wave{{0%,100%{{transform:rotate(0)}}20%,60%{{transform:rotate(-25deg)}}40%,80%{{transform:rotate(10deg)}}}}@media (max-width:500px){{.github-corner:hover .octo-arm{{animation:none}}.github-corner .octo-arm{{animation:octocat-wave 560ms ease-in-out}}}}</style>
        <style type="text/css">
            code {{display: block; /* fixes a strange ie margin bug */font-family: Courier New;font-size: 11pt;overflow:auto;background: #f0f0f0 url(data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAsAAASwCAYAAAAt7rCDAAAABHNCSVQICAgIfAhkiAAAAQJJREFUeJzt0kEKhDAMBdA4zFmbM+W0upqFOhXrDILwsimFR5pfMrXW5jhZr7PwRlxVX8//jNHrGhExjXzdu9c5IiIz+7iqVmB7Hwp4OMa2nhhwN/PRGEMBh3Zjt6KfpzPztxW9MSAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzB8HS+J9kUTvzEDMwAAAABJRU5ErkJggg==) left top repeat-y;border: 10px solid white;padding: 10px 10px 10px 21px;max-height:1000px;line-height: 1.2em;}}
            table {{
              table-layout: fixed;
              width: 100%;
            }}
            table td {{
                word-wrap: break-word;         /* All browsers since IE 5.5+ */
                overflow-wrap: break-word;     /* Renamed property in CSS3 draft spec */
            }}
            textarea {{
              width: 100%;
              height:87px;
            }}
            input[type="text"] {{
              width: 100%;
            }}
        </style>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" integrity="sha384-B0vP5xmATw1+K9KRQjQERJvTumQW0nPEzvF6L/Z6nronJ3oUOFUFpCjEUQouq2+l" crossorigin="anonymous">
    </head>
<body>
<h2>{ my_config["html_title"] }</h2>
<h3>Dear { peerADMname }:</h3>
"""
    if len(methods_class["Supported"]) == 0:
        retstr += f"""<h4>&nbsp;&nbsp;&nbsp;&nbsp;Sorry, we couldn't find any available authentication method in your <a href="{baseURL}/data/mntner/{peerMNT}" target="_blank">mntner</a> object or <a href="{baseURL}/data/person/{peerADM}" target="_blank"> admin contact</a> in the DN42 registry.</h4><h4>Please <a href="{my_paramaters["myContact"]}" target="_blank">contact me</a> to peer manually.</h4>"""
    else:
        retstr += f"""<h4>&nbsp;&nbsp;&nbsp;&nbsp;Please sign our message with your private key registered in your <a href="{baseURL}/data/mntner/{peerMNT}" target="_blank">mntner object</a> or <a href="{baseURL}/data/person/{peerADM}" target="_blank"> admin contact</a> in the DN42 registry.</h4>"""
    retstr += "<h3><font color='red'><b>Supported</b></font> auth method: </h3>" if len(list(methods_class["Supported"].keys())) != 0 else ""
    for m,v in methods_class["Supported"].items():
        retstr += f"""<table class="table"><tr><td><b>Allowed {m}(s): </b></td></tr>"""
        for v_item in v:
            retstr += f"""<tr><td>{v_item}</td></tr>"""
        retstr += "</table>"
        retstr += method_hint[m].format(text2sign = text2sign)
    retstr += "<h4>Unupported auth method: </h4>" if len(list(methods_class["Unsupported"].keys())) != 0 else ""
    for m,v in methods_class["Unsupported"].items():
        retstr += f"""<table class="table"><tr><td><b>{m}</b></td></tr>"""
        for v_item in v:
            retstr += f"""<tr><td>{v_item}</td></tr>"""
        retstr += "</table>"
    retstr += f"""
<br>
<form action="action_page.php" method="post">\n"""
    paramaters = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys if valid_key in paramaters}
    paramaters["peer_plaintext"] = text2sign
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



async def get_html(paramaters,peerSuccess=False):
    peer_plaintext = paramaters["peer_plaintext"]
    peer_pub_key_pgp = paramaters["peer_pub_key_pgp"]
    peer_signature = paramaters["peer_signature"]
    peerASN = paramaters["peerASN"]
    hasIPV4 = paramaters["hasIPV4"]
    hasIPV4Disabled = ""
    peerIPV4 = paramaters["peerIPV4"]
    hasIPV6 = paramaters["hasIPV6"]
    hasIPV6Disabled = ""
    peerIPV6 = paramaters["peerIPV6"]
    hasIPV6LL = paramaters["hasIPV6LL"]
    hasIPV6LLDisabled = ""
    peerIPV6LL = paramaters["peerIPV6LL"]
    MP_BGP = paramaters["MP_BGP"]
    MP_BGP_Disabled = ""
    Ext_Nh = paramaters["Ext_Nh"]
    Ext_Nh_Disabled = ""
    hasHost = paramaters["hasHost"]
    hasHost_Readonly = ""
    peerHost = paramaters["peerHost"]
    peerWG_Pub_Key = paramaters["peerWG_Pub_Key"]
    peerWG_PS_Key = paramaters["peerWG_PS_Key"]
    peerContact = paramaters["peerContact"]
    PeerID = paramaters["PeerID"]
    myASN = paramaters["myASN"]
    myHost = paramaters["myHost"]
    myIPV4 = paramaters["myIPV4"]
    myIPV6 = paramaters["myIPV6"]
    myIPV6LL = paramaters["myIPV6LL"]
    myWG_Pub_Key = paramaters["myWG_Pub_Key"]
    myContact = paramaters["myContact"]
    if myIPV4 == None:
        myIPV4 = ""
    if myIPV6 == None:
        myIPV6 = ""
    if myIPV6LL == None:
        myIPV6LL = ""
    if myHost == None:
        myHost = ""
    if myIPV4 == "":
        hasIPV4 = False
        hasIPV4Disabled = "disabled"
        peerIPV4 = "Sorry, I don't support IPv4 address."
    if myIPV6 == "":
        hasIPV6 = False
        hasIPV6Disabled = "disabled"
        peerIPV6 = "Sorry, I don't support IPv6 address."
    if myIPV6LL == "":
        hasIPV6LL = False
        hasIPV6LLDisabled = "disabled"
        peerIPV6LL = "Sorry, My interface doesn't support IPv6 link local address."
    if not (myIPV4!="") and (myIPV6!="" or myIPV6LL!=""):
        MP_BGP_Disabled = "disabled"
        Ext_Nh_Disabled = "disabled"
    if myHost == "":
        hasHost = True
        hasHost_Readonly = 'onclick="alert(\\"Sorry, I don\'t have a public IP so that your endpoint can\'t be null.\\");return false;"'
        hasHost_Readonly = 'onclick="alert(\'Sorry, I don\\\'t have a public IP so that your endpoint can\\\'t be null.\');return false;";'
        myHostDisplay = paramaters["myHostDisplay"]
    else:
        if PeerID == None:
            myHostDisplay = "(Register to get the endpoint) :"
        else:
            myHostDisplay = "(Authenticate to show the endpoint) :"
        if my_paramaters["myHostHidden"]:
            if peer_signature != "" and peer_signature != None:
                try:
                    mntner = await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_pub_key_pgp"],peer_signature)
                    myHostDisplay = myHost + " :"
                except Exception as e:
                    paramaters["peer_signature"] = ""
                    raise e
        else:
            myHostDisplay = myHost + " :"
        if PeerID == None:
            myHostDisplay += f" [{my_config['wg_port_search_range']}]"
        else:
            myHostDisplay += str(PeerID)
    return f"""
<!DOCTYPE html>
<html>
    <head>
        <title>{ my_config["html_title"] }</title>
        <a href="{ my_config["git_repo_url"] }" class="github-corner" aria-label="View source on GitHub"><svg width="80" height="80" viewBox="0 0 250 250" style="fill:#64CEAA; color:#fff; position: absolute; top: 0; border: 0; right: 0;" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a><style>.github-corner:hover .octo-arm{{animation:octocat-wave 560ms ease-in-out}}@keyframes octocat-wave{{0%,100%{{transform:rotate(0)}}20%,60%{{transform:rotate(-25deg)}}40%,80%{{transform:rotate(10deg)}}}}@media (max-width:500px){{.github-corner:hover .octo-arm{{animation:none}}.github-corner .octo-arm{{animation:octocat-wave 560ms ease-in-out}}}}</style>
        <style type="text/css">
            code {{display: block; /* fixes a strange ie margin bug */font-family: Courier New;font-size: 11pt;overflow:auto;background: #f0f0f0 url(data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAsAAASwCAYAAAAt7rCDAAAABHNCSVQICAgIfAhkiAAAAQJJREFUeJzt0kEKhDAMBdA4zFmbM+W0upqFOhXrDILwsimFR5pfMrXW5jhZr7PwRlxVX8//jNHrGhExjXzdu9c5IiIz+7iqVmB7Hwp4OMa2nhhwN/PRGEMBh3Zjt6KfpzPztxW9MSAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzB8HS+J9kUTvzEDMwAAAABJRU5ErkJggg==) left top repeat-y;border: 10px solid white;padding: 10px 10px 10px 21px;max-height:1000px;line-height: 1.2em;}}
            html {{
              height: 100%;
              width: 100%;
              display: flex;
              justify-content: center;
            }}
            body {{
              height: 100%;
              width: 100%;
              max-width: 1000px;
            }}
            table {{
              table-layout: fixed;
              width: 100%;
            }}
            table td {{
                word-wrap: break-word;         /* All browsers since IE 5.5+ */
                overflow-wrap: break-word;     /* Renamed property in CSS3 draft spec */
            }}
            textarea {{
              width: 100%;
              height:87px;
            }}
            input[type="text"] {{
              width: 100%;
            }}
        </style>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" integrity="sha384-B0vP5xmATw1+K9KRQjQERJvTumQW0nPEzvF6L/Z6nronJ3oUOFUFpCjEUQouq2+l" crossorigin="anonymous">
    </head>
<body>
<h1>{ my_config["html_title"] }</h1>
<h3>{"Peer success! " if peerSuccess else "Please fill "}Your Info</h3>
<form action="action_page.php" method="post" class="markdown-body">
 <h2>Authentication</h2>
 <table class="table">
   <tr><td>Your ASN</td><td><input type="text" value="{peerASN if peerASN != None else ""}" name="peerASN" style="width:75%" /><input type="submit" name="action" value="Get Signature" /></td></tr>
   <tr><td>Plain text to sign</td><td><input type="text" value="{peer_plaintext}" name="peer_plaintext" readonly/></td></tr>
   <tr><td>Your PGP public key<br>(leave it blank if you don't use it)</td><td><textarea name="peer_pub_key_pgp">{peer_pub_key_pgp}</textarea></td></tr>
   <tr><td>Your signature</td><td><textarea name="peer_signature">{peer_signature}</textarea></td></tr>
 </table>
 <h2>Registration</h2>
 <table class="table">
   <tr><td><input type="checkbox" name="hasIPV4" {"checked" if hasIPV4 else ""} {hasIPV4Disabled}>DN42 IPv4</td><td><input type="text" value="{peerIPV4 if peerIPV4 != None else ""}" name="peerIPV4" {hasIPV4Disabled} /></td></tr>
   <tr><td><input type="checkbox" name="hasIPV6" {"checked" if hasIPV6 else ""} {hasIPV6Disabled}>DN42 IPv6</td><td><input type="text" value="{peerIPV6 if peerIPV6 != None else ""}" name="peerIPV6" {hasIPV6Disabled} /></td></tr>
   <tr><td><input type="checkbox" name="hasIPV6LL" {"checked" if hasIPV6LL else ""} {hasIPV6LLDisabled}>IPv6 Link local</td><td><input type="text" value="{peerIPV6LL if peerIPV6LL != None else ""}" name="peerIPV6LL" {hasIPV6LLDisabled} /></td></tr>
   <tr><td><input type="checkbox" name="MP_BGP" {"checked" if MP_BGP else ""} {MP_BGP_Disabled} >Multiprotocol BGP</td><td></td></tr>
   <tr><td><input type="checkbox" name="Ext_Nh" {"checked" if Ext_Nh else ""} {Ext_Nh_Disabled} >Extended next hop</td><td></td></tr>
   <tr><td>Connectrion Info: </td><td>  </td></tr>
   <tr><td><input type="checkbox" name="hasHost" {"checked" if hasHost else ""} {hasHost_Readonly}>Your Clearnet Endpoint (domain or ip:port)</td><td><input type="text" value="{peerHost if peerHost != None else ""}" name="peerHost" /></td></tr>
   <tr><td>Your Wireguard Public Key</td><td><input type="text" value="{peerWG_Pub_Key}" name="peerWG_Pub_Key" /></td></tr>
   <tr><td>Your Wireguard Pre-Shared Key (Optional)</td><td><input type="text" value="{peerWG_PS_Key}" name="peerWG_PS_Key" /></td></tr>
   <tr><td>Your Telegram ID or e-mail</td><td><input type="text" value="{peerContact}" name="peerContact" /></td></tr>
   <tr><td><input type="submit" name="action" value="Register" /></td><td>Register a new peer to get Peer ID</td></tr>
   </table>
   <h2>Deletion</h2>
   <table  class="table">
   <tr><td>Your Peer ID</td><td><input type="text" value="{PeerID if PeerID != None else ""}" name="PeerID" /></td></tr>
   <tr><td><input type="submit" name="action" value="Check My Info" /><input type="submit" name="action" value="Delete" /></td><td>Get the info of an existening peer or delete it.</td></tr>
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
   <tr><td>My Clearnet Endpoint</td><td><input type="text" value="{myHostDisplay}" readonly /></td></tr>
   <tr><td>My WG Public Key</td><td><input type="text" value="{myWG_Pub_Key}" readonly /></td></tr>
   <tr><td>My Contact</td><td><input type="text" value="{myContact}" readonly /></td></tr>
 </table>
</form>
</body>
</html>
"""

async def get_info_from_asn(asn):
    asn_info = await whois_query("aut-num/" + asn)
    data = DN42whois.proc_data(asn_info)
    return data["mnt-by"][0] , data["admin-c"][0]

async def get_mntner_info(mntner):
    mntner_info = await whois_query("mntner/" + mntner)
    ret = DN42whois.proc_data(mntner_info)
    if "auth" not in ret:
        ret["auth"] = []
    return ret

async def get_person_info(person):
    person_info = (await whois_query("person/" + person))
    ret = DN42whois.proc_data(person_info)
    if "auth" not in ret:
        ret["auth"] = []
    if "pgp-fingerprint" in ret:
        ret["auth"] += ["pgp-fingerprint " + ret["pgp-fingerprint"][0]]
    return ret

async def get_auth_method(mnt,admin):
    authes = []
    if mnt != None:
        authes += (await get_mntner_info(mnt))["auth"]
    if admin != None:
        authes += (await get_person_info(admin))["auth"]
    ret = {}
    for a in authes:
        if a.startswith("PGPKEY"):
            method , pgp_sign8 = a.split("-",1)
            pgp_pubkey_str = await try_get_pub_key(pgp_sign8)
            if pgp_pubkey_str == "":
                continue
            pub = pgpy.PGPKey.from_blob(pgp_pubkey_str.encode("utf8"))[0]
            real_fingerprint = pub.fingerprint.replace(" ","")
            ainfo = method + " " + real_fingerprint
        else:
            ainfo = a
        ret[ainfo] = False
    return list(filter(lambda x:len(x) == 2,[r.split(" ",1) for r,v in ret.items()]))

async def try_get_pub_key(pgpsig):
    if len(pgpsig) < 8:
        return ""
    pgpsig = pgpsig[-8:]
    try:
        result = await whois_query("key-cert/PGPKEY-" + pgpsig)
        result = list(filter(lambda l:l.startswith("certif:"),result.split("\n")))
        result = list(map(lambda x:x.split(":")[1].lstrip(),result))
        result = "\n".join(result)
        return result
    except Exception as e:
        pass
    return ""


def verify_signature_pgp(plaintext,fg,pub_key,raw_signature):
    pub = pgpy.PGPKey.from_blob(pub_key.encode("utf8"))[0]
    fg_in = fg.replace(" ","")
    fg_p = pub.fingerprint.replace(" ","")
    if fg_in != fg_p:
        raise ValueError("fingerprint not match")
    sig = pgpy.PGPSignature.from_blob(raw_signature.encode("utf8"))
    if not pub.verify(plaintext,sig):
        raise ValueError("signature verification failed")
    return True

def verify_signature_pgpn8(plaintext,fg,pub_key,raw_signature):
    pub = pgpy.PGPKey.from_blob(pub_key.encode("utf8"))[0]
    fg_in = fg.replace(" ","")
    fg_p = pub.fingerprint.replace(" ","")
    if fg_in != fg_p:
        raise ValueError("fingerprint not match")
    sig = pgpy.PGPSignature.from_blob(raw_signature.encode("utf8"))
    if not pub.verify(plaintext,sig):
        raise ValueError("signature verification failed")
    return True
  
def verify_signature_ssh_rsa(plaintext,pub_key,raw_signature):
    sess = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    pathlib.Path("ssh").mkdir(parents=True, exist_ok=True)
    sigfile_path = "ssh/tmp" + sess + ".sig"
    pubfile_path = "ssh/tmp" + sess + ".pub"
    open(sigfile_path,"w").write(raw_signature)
    open(pubfile_path,"w").write(sess + " ssh-rsa " + pub_key)
    command = 'ssh-keygen',"-Y","verify","-f",pubfile_path,"-n","dn42ap","-I",sess,"-s",sigfile_path
    p = Popen(command, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    stdout_data = p.communicate(input=plaintext.encode())[0]
    os.remove(sigfile_path)
    os.remove(pubfile_path)
    if stdout_data.startswith(b"Good"):
        return True
    else:
        raise ValueError(stdout_data)

def verify_signature_ssh_ed25519(plaintext,pub_key,raw_signature):
    sess = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    pathlib.Path("ssh").mkdir(parents=True, exist_ok=True)
    sigfile_path = "ssh/tmp" + sess + ".sig"
    pubfile_path = "ssh/tmp" + sess + ".pub"
    open(sigfile_path,"w").write(raw_signature)
    open(pubfile_path,"w").write(sess + " ssh-ed25519 " + pub_key)
    command = 'ssh-keygen',"-Y","verify","-f",pubfile_path,"-n","dn42ap","-I",sess,"-s",sigfile_path
    p = Popen(command, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    stdout_data = p.communicate(input=plaintext.encode())[0]
    os.remove(sigfile_path)
    os.remove(pubfile_path)
    if stdout_data.startswith(b"Good"):
        return True
    else:
        raise ValueError(stdout_data)

def removern(strin):
    if type(strin) == str:
        return strin.replace("\r\n","\n").replace("\r","\n")
    elif type(strin) == bytes:
        return strin.replace(b"\r\n",b"\n").replace(b"\r",b"\n")
    return strin
def verify_signature(plaintext,pub_key,pub_key_pgp,raw_signature,method):
    if method=="pgp-fingerprint":
        return verify_signature_pgp(plaintext,pub_key,pub_key_pgp,raw_signature)
    elif method=="PGPKEY":
        return verify_signature_pgpn8(plaintext,pub_key,pub_key_pgp,raw_signature)
    elif method=="ssh-rsa":
        return verify_signature_ssh_rsa(plaintext,pub_key,raw_signature)
    elif method=="ssh-ed25519":
        return verify_signature_ssh_ed25519(plaintext,pub_key,raw_signature)
    raise NotImplementedError("method not implement")

async def verify_user_signature(peerASN,plaintext,pub_key_pgp,raw_signature):
    try:
        plaintext = removern(plaintext)
        pub_key_pgp = removern(pub_key_pgp)
        raw_signature = removern(raw_signature)
        if plaintext == "" or plaintext == None:
            raise ValueError('Plain text to sign can\'t be null, please click the button "Get Signature" first.')
        raw_signature = raw_signature.replace("\r\n","\n").replace("\r","\n")
        if raw_signature == "" or raw_signature == None:
            raise ValueError('Signature can\'t be null, please click the button "Get Signature" and follow the instruction.')
        sig_info = jwt.decode(plaintext.encode("utf8"),jwt_secret,algorithms=["HS256"])
        if sig_info["ASN"] != peerASN:
            raise ValueError("JWT verification failed. You are not the mntner of " + sig_info["ASN"])
        supported_method= ["ssh-rsa"]
        # verify user signature
        mntner, admin = await get_info_from_asn(peerASN)
        authes = await get_auth_method(mntner, admin)
        tried = False
        authresult = [{"Your input":{"plaintext":plaintext,"signature":raw_signature,"pub_key_pgp":pub_key_pgp}}]
        for method,pub_key in authes:
            try:
                if verify_signature(plaintext,pub_key,pub_key_pgp,raw_signature,method) == True:
                    return mntner
            except Exception as e:
                authresult += [{"Source": "User credential","Method": method , "Result": type(e).__name__ + ": " + str(e), "Content":  pub_key}]
        # verify admin signature
        mntner_admin = my_config["admin_mnt"]
        try:
            authes_admin = await get_auth_method(mntner_admin,None)
            for method,pub_key in authes_admin:
                try:
                    if verify_signature(plaintext,pub_key,pub_key_pgp,raw_signature,method) == True:
                        return mntner_admin
                except Exception as e:
                    authresult += [{"Source": "Admin credential", "Method": method , "Result": type(e).__name__ + ": " + str(e), "Content":  pub_key}]
        except Exception as e:
            pass
        raise ValueError(yaml.dump(authresult, sort_keys=False,default_style='|'))
    except Exception as e:
        class customError(type(e)):
            def init(m):
                super(m)
        customError.__name__ = "SignatureError: " + type(e).__name__
        raise customError(str(e))

def get_err_page(paramaters,title,error,big_title="Server Error", tab_title = None,redirect=None):
    if tab_title == None:
        tab_title = title
    retstr =  f"""
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>{ tab_title }</title>
<style type="text/css">
<!--
body{{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}}
fieldset{{padding:0 15px 10px 15px;}}
h1{{font-size:2.4em;margin:0;color:#FFF;}}
h2{{font-size:1.7em;margin:0;color:#CC0000;}}
h3{{font-size:1.2em;margin:10px 0 0 0;color:#000000;}}
#header{{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}}
#content{{margin:0 0 0 2%;position:relative;}}
.content-container{{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}}
-->
</style>
</head>
<body>
<div id="header"><h1>{big_title}</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>{ title }</h2>
  <h3>{str(error).replace(chr(10),"<br>").replace(" ","&nbsp;")}</h3>
  <h3></h3>
  <form action="action_page.php" method="post">\n"""
    paramaters = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys if valid_key in paramaters}
    for k,v in paramaters.items():
        if v == None:
            v = ""
        elif v == True:
            v = "on"
        retstr += f'<input type="hidden" name="{k}" value="{v}">\n'
    if redirect == None:
        retstr +='<input type="submit" name="action" value="OK" />'
    else:
        retstr += f"""<a href="{redirect}">
   <input type="button" value="OK" />
</a>"""
    retstr +="""
    </form>
 </fieldset></div>
</div>
</body>
</html>
"""
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

def check_wg_key(wgkey):
    wg_keylen = 32
    if len(wgkey) > wg_keylen*2:
        raise ValueError(f"Wireguard key {wgkey} too long")
    base64_valid_chars = set(string.ascii_letters + string.digits + "+/=")
    if not set(wgkey).issubset(base64_valid_chars):
        raise ValueError(f"Wireguard key {wgkey} contains invalid character: {set(filter(lambda x:x not in base64_valid_chars,wgkey))}")
    key_raw = base64.b64decode(wgkey)
    if len(key_raw) != 32:
        raise ValueError(f"Wireguard key {wgkey} are not {wg_keylen} bytes len")

async def check_reg_paramater(paramaters,alliw_exists=False):
    if (paramaters["hasIPV4"] or paramaters["hasIPV4LL"] or paramaters["hasIPV6"] or paramaters["hasIPV6LL"]) == False:
        raise ValueError("You can't peer without any IP.")
    mntner,admin = await get_info_from_asn(paramaters["peerASN"])
    if paramaters["hasIPV4"]:
        check_valid_ip_range(IPv4Network,DN42_valid_ipv4s,paramaters["peerIPV4"],"DN42 ip")
        peerIPV4_info = DN42whois.proc_data((await whois_query(paramaters["peerIPV4"])))
        if paramaters["myIPV4"] == None:
            raise NotImplementedError("Sorry, I don't have IPv4 address.")
        if "origin" not in peerIPV4_info or len(peerIPV4_info["origin"]) == 0:
            originASN = "nobody"
        else:
            originASN = peerIPV4_info["origin"][0]

        origin_check_pass = False
        for origin in peerIPV4_info["origin"]:
            if origin == paramaters["peerASN"]:
                origin_check_pass = True
        if origin_check_pass:
            pass
        elif mntner == peerIPV4_info["mnt-by"][0] and mntner != "DN42-MNT":
            pass
        elif admin == peerIPV4_info["admin-c"][0]:
            pass
        else:
            ipowner = peerIPV4_info["admin-c"][0]
            raise PermissionError("IP " + paramaters["peerIPV4"] + f" owned by {originASN}({ipowner}) instead of {paramaters['peerASN']}({admin})")
            
    else:
        paramaters["peerIPV4"] = None
    if paramaters["hasIPV6"]:
        check_valid_ip_range(IPv6Network,DN42_valid_ipv6s,paramaters["peerIPV6"],"DN42 ipv6")
        peerIPV6_info = DN42whois.proc_data((await whois_query(paramaters["peerIPV6"])))
        if paramaters["myIPV6"] == None:
            raise NotImplementedError("Sorry, I don't have IPv6 address.")
        if "origin" not in peerIPV6_info or len(peerIPV6_info["origin"]) == 0:
            originASN = "nobody"
        else:
            originASN = peerIPV6_info["origin"][0]
            
        origin_check_pass = False
        for origin in peerIPV6_info["origin"]:
            if origin == paramaters["peerASN"]:
                origin_check_pass = True
        if origin_check_pass:
            pass
        elif mntner == peerIPV4_info["mnt-by"][0] and mntner != "DN42-MNT":
            pass
        elif admin == peerIPV4_info["admin-c"][0]:
            pass
        else:
            ipowner = peerIPV4_info["admin-c"][0]
            raise PermissionError("IP " + paramaters["peerIPV4"] + f" owned by {originASN}({ipowner}) instead of {paramaters['peerASN']}({admin})")
    else:
        paramaters["peerIPV6"] = None

    if paramaters["hasIPV4LL"]:
        check_valid_ip_range(IPv4Network,valid_ipv4_lilos,paramaters["peerIPV4LL"],"link-local ipv4")
        if paramaters["myIPV4LL"] == None:
            raise NotImplementedError("Sorry, I don't have IPv4 link-local address.")
        if paramaters["myIPV4LL"] == paramaters["peerIPV4LL"]:
            raise ValueError("Conflict. Your IPv4 link-local address are conflict with my IPv4 link-local address.")
    else:
        paramaters["peerIPV4LL"] = None
    if paramaters["hasIPV6LL"]:
        check_valid_ip_range(IPv6Network,valid_ipv6_lilos,paramaters["peerIPV6LL"],"link-local ipv6")
        if paramaters["myIPV6LL"] == None:
            raise NotImplementedError("Sorry, I don't have IPv6 link-local address.")
        if paramaters["myIPV6LL"] == paramaters["peerIPV6LL"]:
            raise ValueError("Conflict. Your IPv6 link-local address are conflict with my IPv6 link-local address.")
    else:
        paramaters["peerIPV6LL"] = None
    if paramaters["MP_BGP"]:
        if not (paramaters["hasIPV6"] or paramaters["hasIPV6LL"]):
            raise ValueError("Value Error. You need a IPv6 address to use multiprotocol BGP.")
    if paramaters["Ext_Nh"]:
        if not (paramaters["hasIPV6"] or paramaters["hasIPV6LL"]):
            raise ValueError("Value Error. You need a IPv6 address to use extended next hop.")
        if not paramaters["MP_BGP"]:
            raise ValueError("Value Error. You need enable multiprotocol BGP to use extended next hop.")
        if paramaters["allowExtNh"] == False:
            raise NotImplementedError("Sorry, I don't support extended next hop.")

    if paramaters["peerWG_PS_Key"] == "":
        paramaters["peerWG_PS_Key"] == None
    if paramaters["customDevice"] == None:
        if paramaters["hasHost"]:
            if paramaters["peerHost"] == None and (my_paramaters["myHost"] == None):
                raise ValueError("Sorry, I don't have a public IP so that your endpoint can't be null.")
            if paramaters["peerHost"] == None or ":" not in paramaters["peerHost"]:
                raise ValueError("Parse Error, Host must looks like address:port.")
            hostaddr,port = paramaters["peerHost"].rsplit(":",1)
            port = int(port)
            if hostaddr[0] == "[" and hostaddr[-1] == "]":
                hostaddr = hostaddr[1:-1]
            elif ":" in hostaddr:
                 raise ValueError(f"Parse Error, IPv6 Address as endpoint, it should be like [{hostaddr}]:{port}.")
            addrinfo = socket.getaddrinfo(hostaddr,port)
        else:
            paramaters["peerHost"] = None
        peerKey = paramaters["peerWG_Pub_Key"]
        if peerKey == None or len(peerKey) == 0:
            raise ValueError('"Your WG Public Key" can\'t be null.')
        if peerKey == paramaters["myWG_Pub_Key"]:
            raise ValueError('You can\'t use my wireguard public key as your wireguard public key.')
        check_wg_key(peerKey)
        check_wg_key(paramaters["myWG_Pri_Key"])
        
    if alliw_exists == False:
        RRstate_repo.pull()
        conf_dir = wgconfpath + "/peerinfo"
        if os.path.isdir(conf_dir): #Check this node hasn't peer with us before
            for old_conf_file in os.listdir(conf_dir):
                if old_conf_file.endswith(".yaml") and os.path.isfile(f"{conf_dir}/{old_conf_file}"):
                    old_conf = yaml.load(open(f"{conf_dir}/{old_conf_file}").read(),Loader=yaml.SafeLoader)
                    if paramaters["peerIPV4"] != None and old_conf["peerIPV4"] == paramaters["peerIPV4"]:
                        raise FileExistsError(f'This IPv4 address {paramaters["peerIPV4"]} already exisis in "{old_conf_file}", please remove the peering first.')
                    if paramaters["peerIPV6"] != None and old_conf["peerIPV6"] == paramaters["peerIPV6"]:
                        raise FileExistsError(f'This IPv6 address {paramaters["peerIPV6"]} already exisis in "{old_conf_file}", please remove the peering first.')
                    if old_conf["peerHost"] != None and old_conf["peerHost"] == paramaters["peerHost"]:
                        raise FileExistsError(f'This endpoint "{paramaters["peerHost"]}" already exisis in "{old_conf_file}", please remove the peering first.')
    return paramaters

def replace_str(text,replace):
    for k,v in replace.items():
        text = text.replace(k,v)
    return text

def indent2(text,fill):
    if "\n" not in text:
        return text
    tail,body = text.split("\n",1)
    return tail + "\n" + textwrap.indent(body,fill)

def get_peeronly_filter(io,af,peerASN,myASN,noExport=True):
    commadd = ""
    if noExport == True:
        commadd = "bgp_community.add((65535,65281));"
    if io == "i":
        if af == 4:
            return textwrap.dedent(f"""\
                        if is_valid_network() && bgp_path.last = {peerASN} then {{
                            if (roa_check(dn42_roa, net, bgp_path.last) != ROA_VALID) then {{
                                print "[dn42] ROA check failed from ",bgp_path.first , " ifname:", ifname ," for ", net, " ASN:", bgp_path.last;
                                reject;
                            }}
                            {commadd}
                            accept;
                        }}
                        reject;
                    """)
        elif af == 6:
            return textwrap.dedent(f"""\
                        if is_valid_network_v6() && bgp_path.last = {peerASN} then {{
                            if (roa_check(dn42_roa_v6, net, bgp_path.last) != ROA_VALID) then {{
                                print "[dn42] ROA check failed from ",bgp_path.first , " ifname:", ifname ," for ", net, " ASN:", bgp_path.last;
                                reject;
                            }}
                            {commadd}
                            accept;
                        }}
                        reject;
                    """)
    if io == "o":
        if af == 4:
            return textwrap.dedent(f"""\
                        if (bgp_path.last = {myASN} && (roa_check(dn42_roa, net, bgp_path.last) = ROA_VALID)) || (is_self_net() && is_valid_network() && source ~ [RTS_STATIC, RTS_BGP]) then{{
                            if is_valid_network() then{{
                                {commadd}
                                accept;
                            }}
                        }}
                        reject;
                    """)
        elif af == 6:
            return textwrap.dedent(f"""\
                        if (bgp_path.last = {myASN} && (roa_check(dn42_roa_v6, net, bgp_path.last) = ROA_VALID)) || (is_self_net_v6() && is_valid_network_v6() && source ~ [RTS_STATIC, RTS_BGP]) then{{
                            if is_valid_network_v6() then{{
                                {commadd}
                                accept;
                            }}
                        }}
                        reject;
                    """)
def get_transit_filter(io,af,peerASN,myASN,noExport=True):
    commadd = ""
    if noExport == True:
        commadd = "bgp_community.add((65535,65281));"
    if io == "i":
        if af == 4:
            return textwrap.dedent(f"""\
                        {commadd}
                        if is_valid_network() && !is_self_net() then {{
                            if (roa_check(dn42_roa, net, bgp_path.last) != ROA_VALID) then {{
                                print "[dn42] ROA check failed from ",bgp_path.first , " ifname:", ifname ," for ", net, " ASN:", bgp_path.last;
                                reject;
                            }} 
                            {commadd}
                            accept;
                        }}
                        reject;
                    """)
        elif af == 6:
            return textwrap.dedent(f"""\
                        {commadd}
                        if is_valid_network_v6() && !is_self_net_v6() then {{
                            if (roa_check(dn42_roa_v6, net, bgp_path.last) != ROA_VALID) then {{
                                print "[dn42] ROA check failed from ",bgp_path.first , " ifname:", ifname ," for ", net, " ASN ", bgp_path.last;
                                reject;
                            }} 
                            {commadd}
                            accept;
                        }}
                        reject;
                    """)
    if io == "o":
        if af == 4:
            return textwrap.dedent(f"""\
                        {commadd}
                        if is_valid_network() && source ~ [RTS_STATIC, RTS_BGP] then {{
                            accept; 
                        }}
                        reject;
                    """)
        elif af == 6:
            return textwrap.dedent(f"""\
                        {commadd}
                        if is_valid_network_v6() && source ~ [RTS_STATIC, RTS_BGP] then {{
                            accept; 
                        }}
                        reject;
                    """)
def get_ix_filter(io,af,peerASN,myASN,noExport=True):
    if io == "i":
        if af == 4:
            return textwrap.dedent(f"""\
                        if (bgp_path.last = bgp_path.first && (roa_check(dn42_roa, net, bgp_path.last) = ROA_VALID)) then{{
                            if is_valid_network() then{{
                                accept;
                            }}
                        }}
                        reject;
                    """)
        elif af == 6:
            return textwrap.dedent(f"""\
                        if (bgp_path.last = bgp_path.first && (roa_check(dn42_roa_v6, net, bgp_path.last) = ROA_VALID)) then{{
                            if is_valid_network_v6() then{{
                                accept;
                            }}
                        }}
                        reject;
                    """)

def newConfig(paramaters,overwrite=False):
    peerASN = int(paramaters["peerASN"][2:])
    peerKey = paramaters["peerWG_Pub_Key"]
    peerPSK = paramaters["peerWG_PS_Key"]
    peerContact = paramaters["peerContact"]
    peerName = paramaters["peerName"]
    peerID = paramaters["PeerID"]
    peerHost = paramaters["peerHost"]
    peerIPV4 = paramaters["peerIPV4"]
    peerIPV6 = paramaters["peerIPV6"]
    peerIPV4LL = paramaters["peerIPV4LL"]
    peerIPV6LL = paramaters["peerIPV6LL"]
    transitMode =  paramaters["transitMode"]
    MP_BGP = paramaters["MP_BGP"]
    Ext_Nh = paramaters["Ext_Nh"]
    myIPV4 = paramaters["myIPV4"]
    myIPV6 = paramaters["myIPV6"]
    myIPV4LL = paramaters["myIPV4LL"]
    myIPV6LL = paramaters["myIPV6LL"]
    myhost = paramaters["myHost"]
    myasn = paramaters["myASN"][2:]
    privkey = paramaters["myWG_Pri_Key"]
    publkey = paramaters["myWG_Pub_Key"]
    mtu = paramaters["myWG_MTU"]
    customDevice = paramaters["customDevice"]
    customDeviceSetup = paramaters["customDeviceSetup"]
    
    if peerContact == None or len(peerContact) == 0:
        raise ValueError('"Your Telegram ID or e-mail" can\'t be null.')
    
    portlist = list(sorted(map(lambda x:int(x.split(".")[0]),filter(lambda x:x[-4:] == "yaml", os.listdir(wgconfpath + "/peerinfo")))))
    # portlist=[23001, 23002, 23003,23004,23005,23006,23007,23008,23009,23088]
    if peerID == None:
        port_range = eval(my_config["wg_port_search_range"])
        for p in port_range:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
                sock.bind(("0.0.0.0", p))
                sock.close()
            except Exception as e:
                try:
                    sock.close()
                except Exception as e:
                    pass
                print(f"Try peer ID:{p} failed, reason:{e}")
                continue
            if p not in portlist:
                peerID = p
                print("Select peer ID:", peerID)
                break
            print(f"Try peer ID:{p} failed, reason: exists in portlist")
    else:
        peerID = int(peerID)
    if peerID == None:
        raise IndexError("PeerID not available, contact my to peer manually. ")
    if peerID in portlist and overwrite == False:
        raise IndexError("PeerID already exists.")
    paramaters["PeerID"] = peerID
    if peerName == None:
        peerName = str(int(peerID) % 10000).zfill(4) + peerContact
        peerName = peerName.replace("-","_")
        peerName = re.sub(r"[^A-Za-z0-9_]+", '', peerName)
        peerName = peerName[:10]
    
    if customDevice == None:
        if_name = "dn42-" + peerName
    else:
        if_name = customDevice
        
    
    customDeviceSetup = customDeviceSetup.replace( "%if_name" , if_name )
    if peerHost != None:
        customDeviceSetup = customDeviceSetup.replace( "%peer_host" , peerHost )
    
    
    wgconf = textwrap.dedent(f"""\
                                [Interface]
                                PrivateKey = { privkey }
                                ListenPort = { str(peerID) }
                                [Peer]
                                PublicKey = { peerKey }
                                AllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64
                                """)
    if peerHost != None and peerHost != "":
        wgconf += f"Endpoint = { peerHost }\n"
    if peerPSK != None and peerPSK != "":
        wgconf += f"PresharedKey = { peerPSK }\n"
    
    wgsh = textwrap.dedent(f"""\
                                ip link add dev {if_name} type wireguard
                                wg setconf {if_name} {wgconfpath}/{peerName}.conf
                                """)
    setupsh = textwrap.dedent(f"""\
                                ip link set {if_name} up
                                """)
    if int(mtu) > 0:
        setupsh += textwrap.dedent(f"""\
                                ip link set mtu {mtu} dev {if_name}
                                """)
    if use_speed_limit:
        setupsh += f"wondershaper {if_name} $WG_SPEED_LIMIT $WG_SPEED_LIMIT || true\n"
    
    if peerIPV4LL != None:
        myIPV4 = myIPV4LL
        peerIPV4 = peerIPV4LL
    birdPeerV4 = None
    birdMyV4 = myIPV4
    birdPeerV6 = None
    birdMyV6 = None
    if myIPV4 != None:
        if Ext_Nh == True:
            pass # setupsh += f"ip addr add {myIPV4}/32 dev {if_name}\n"
        elif peerIPV4 != None:
            setupsh += f"ip addr add {myIPV4} peer {peerIPV4} dev {if_name}\n"
            if MP_BGP == False:
                birdPeerV4 = peerIPV4
        else:
            pass #setupsh += f"ip addr add {myIPV4}/32 dev {if_name}\n"
    
    if peerIPV6LL != None:
        pass #setupsh += f"ip addr add {myIPV6}/128 dev {if_name}\n"
        setupsh += f"ip addr add {myIPV6LL}/64 dev {if_name}\n"
        birdPeerV6 = peerIPV6LL
        birdMyV6 = myIPV6LL
    elif peerIPV6 != None:
        setupsh += f"ip addr add {myIPV6} peer {peerIPV6} dev {if_name}\n"
        setupsh += f"ip route add {peerIPV6}/128 src {myIPV6} dev {if_name}\n"
        birdPeerV6 = peerIPV6
        birdMyV6 = myIPV6
    
    birdconf = ""
    channel4 = ""
    channel6 = ""
    filter4i = ""
    filter4e = ""
    filter6i = ""
    filter6e = ""

    if Ext_Nh == True:
        channel4 += "extended next hop on;\n"
    if transitMode == "Regular" or transitMode == "Private Peering":
        pass
    elif transitMode == "PeerOnly" or transitMode == "Public Peering":
        filter4i += get_peeronly_filter("i",4,peerASN,myasn,True)
        filter6i += get_peeronly_filter("i",6,peerASN,myasn,True)
        filter4e += get_peeronly_filter("o",4,peerASN,myasn,True)
        filter6e += get_peeronly_filter("o",6,peerASN,myasn,True)
    elif transitMode == "Upstream" or transitMode == "Transit Providers":
        filter4i += get_transit_filter("i",4,peerASN,myasn,True)
        filter6i += get_transit_filter("i",6,peerASN,myasn,True)
        filter4e += get_peeronly_filter("o",4,peerASN,myasn,False)
        filter6e += get_peeronly_filter("o",6,peerASN,myasn,False)
    elif transitMode == "Downstream" or transitMode == "Customer":
        filter4i += get_peeronly_filter("i",4,peerASN,myasn,False)
        filter6i += get_peeronly_filter("i",6,peerASN,myasn,False)
        filter4e += get_transit_filter("o",4,peerASN,myasn,True)
        filter6e += get_transit_filter("o",6,peerASN,myasn,True)
    elif transitMode == "IX":
        filter4i += get_ix_filter("i",4,peerASN,myasn,False)
        filter6i += get_ix_filter("i",6,peerASN,myasn,False)
        filter4e += get_peeronly_filter("o",4,peerASN,myasn,False)
        filter6e += get_peeronly_filter("o",6,peerASN,myasn,False)
    else:
        raise ValueError("Unknow transitMode: " + transitMode)
    #########################
    if filter4i != "":
        channel4 += textwrap.dedent(f"""\
                    import filter{{
                        { indent2(filter4i,"                        ") }
                    }};
                    """)
    if filter4e != "":
        channel4 += textwrap.dedent(f"""\
                    export filter{{
                        { indent2(filter4e,"                        ") }
                    }};
                    """)
    if filter6i != "":
        channel6 += textwrap.dedent(f"""\
                    import filter{{
                        { indent2(filter6i,"                        ") }
                    }};
                    """)
    if filter6e != "":
        channel6 += textwrap.dedent(f"""\
                    export filter{{
                        { indent2(filter6e,"                        ") }
                    }};
                    """)
    if channel4 != "":
        channel4 = textwrap.dedent(f"""\
                    ipv4 {{
                        { indent2(channel4,"                        ") }
                    }};
                    """)
        channel4 = indent2(channel4,"                                            ")
    if channel6 != "":
        channel6 = textwrap.dedent(f"""\
                    ipv6 {{
                        { indent2(channel6,"                        ") }
                    }};
                    """)
        channel6 = indent2(channel6,"                                            ")
        
    if MP_BGP == True:
        if peerIPV6 != None or peerIPV6LL != None:
            birdconf += textwrap.dedent(f"""\
                                        protocol bgp dn42_{peerName}_v6 from dnpeers {{
                                            source address {birdMyV6};
                                            neighbor {birdPeerV6} % '{if_name}' as {peerASN};
                                            {channel4}
                                            {channel6}
                                        }};
                                        """)
    else:
        if birdPeerV4 != None:
            birdconf += textwrap.dedent(f"""\
                                        protocol bgp dn42_{peerName}_v4 from dnpeers {{
                                            source address {birdMyV4};
                                            neighbor {birdPeerV4} % '{if_name}' as {peerASN};
                                            {channel4}
                                            ipv6 {{
                                                import none;
                                                export none;
                                            }};
                                        }};
                                        """)
        if peerIPV6 != None or peerIPV6LL != None:
            birdconf += textwrap.dedent(f"""\
                                        protocol bgp dn42_{peerName}_v6 from dnpeers {{
                                            source address {birdMyV6};
                                            neighbor {birdPeerV6} % '{if_name}' as {peerASN};
                                            ipv4 {{
                                                import none;
                                                export none;
                                            }};
                                            {channel6}
                                        }};
                                        """)

    paramaters["peerName"] = peerName
    paramaters_save = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys if valid_key in paramaters}
    paramaters_save["peer_signature"] = ""
    paramaters_save["peer_plaintext"] = ""
    paramaters_save["peerName"] = peerName
    
    devsh = "\n".join([ "#!/bin/bash" , wgsh , setupsh])
    retconfig = {
        f"{wgconfpath}/{peerName}.conf": wgconf,
        f"{wgconfpath}/peerinfo/{peerID}.yaml": yaml.dump(paramaters_save),
        f"{bdconfpath}/{peerName}.conf": birdconf,
        f"{wgconfpath}/{peerName}.sh": devsh,
    }
    
    if customDevice != None: 
        devsh = "\n".join([ "#!/bin/bash" , customDeviceSetup , setupsh])
        del retconfig[f"{wgconfpath}/{peerName}.conf"]
        retconfig[f"{wgconfpath}/{peerName}.sh"] = devsh

    return {
        "config":retconfig,
        "if_name": if_name,
        "peerName": peerName,
        "paramaters": paramaters,
    }

def saveConfig(new_config):
    RRstate_repo.pull()
    runsh = False
    for path,content in new_config["config"].items():
        print("================================")
        print(path)
        print(content)
        fileparent = pathlib.Path(path).parent.absolute()
        if not os.path.isdir(fileparent):
            os.makedirs(fileparent, mode=0o700 , exist_ok=True)
        with open(path,"w") as conffd:
            conffd.write(content)
            if content.startswith("#!"):
                os.chmod(path, 0o755)
            runsh = True
        print("================================")
    peerName = new_config["peerName"]
    RRstate_repo.push(f'{node_name} peer add {peerName}')
    if runsh:
        print_and_exec(f"{wgconfpath}/{peerName}.sh")
    print_and_exec("birdc configure")
    return None

def initDevice():
    print_and_exec(f"ip link add dn42-dummy type dummy")
    print_and_exec(f"ip link set up dn42-dummy")
    print_and_exec(f'ip addr add { my_paramaters["myIPV4"] } dev dn42-dummy')
    print_and_exec(f'ip addr add { my_paramaters["myIPV6"] } dev dn42-dummy')
    for thesh in filter(lambda x:x[-3:] == ".sh", os.listdir(wgconfpath)):
        print_and_exec(wgconfpath + "/" + thesh)
def syncWG():
    interval = my_config["reset_wgconf_interval"]
    print("Sync WG interval:",interval)
    if interval <= 0:
        return
    conf_dir = wgconfpath + "/peerinfo"
    while True:
        time.sleep(interval)
        if os.path.isdir(conf_dir): #Check this node hasn't peer with us before
            for conf_file in os.listdir(conf_dir):
                if conf_file.endswith(".yaml") and os.path.isfile(f"{conf_dir}/{conf_file}"):
                    conf = yaml.load(open(f"{conf_dir}/{conf_file}").read(),Loader=yaml.SafeLoader)
                    if conf["customDevice"] != None:
                        continue
                    if conf["peerWG_Pub_Key"] == None:
                        continue
                    if conf["peerHost"] == None:
                        continue
                    ifname = "dn42-" + conf["peerName"]
                    peerpubkey = conf["peerWG_Pub_Key"]
                    peerendpoint = conf["peerHost"]
                    print_and_exec(f"wg set {shlex.quote(ifname)} peer {shlex.quote(peerpubkey)} endpoint {shlex.quote(peerendpoint)}")
    
def print_and_exec(command):
    if use_remote_command != "":
        command = f'echo {shlex.quote(command + "; exit")} | nc {use_remote_command}'
    print(command)
    os.system(command)
    time.sleep(1)
                                    
def print_and_rm(file):
    print("rm " + file)
    try:
        os.remove(file)
    except Exception as e:
        print(e)

def print_and_rmrf(tree):
    print("rm -rf " + tree)
    shutil.rmtree(tree)
                                    
def deleteConfig(peerID,peerName,customDevice):
    RRstate_repo.pull()
    print_and_rm(f"{wgconfpath}/{peerName}.conf")
    print_and_rm(f"{wgconfpath}/{peerName}.sh")
    print_and_rm(f"{wgconfpath}/peerinfo/{peerID}.yaml")
    print_and_rm(f"{bdconfpath}/{peerName}.conf")
    RRstate_repo.push(f'{node_name} peer del {peerName}')
    if customDevice == None:
        if_name = "dn42-" + peerName
        print_and_exec(f"ip link del {if_name}")
    print_and_exec("birdc configure")
    return None

def get_key_default(D,k,d,ValType=str):
    if k in D and D[k] != "" and D[k] != None:
        return D[k]
        if ValType == bool:
            params[pkey] = os.environ[ekey].lower() == "true"
        else:
            params[pkey] = ValType(os.environ[ekey])
    return d

def qsd2d(qsd):
    return {k:v[0] for k,v in qsd.items()}

def isFormTrue(inp):
    if inp == "on" or inp == "True" or inp == True:
        return True
    return False

def get_paramaters(paramaters,isAdmin=False):
    action                         = get_key_default(paramaters,"action","OK")
    paramaters = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys if (valid_key in paramaters)  }
    if not isAdmin:
        for k in client_valid_keys_admin_only:
            if k in paramaters:
                del paramaters[k]
    paramaters["peer_plaintext"]   = get_key_default(paramaters,"peer_plaintext","")
    paramaters["peer_pub_key_pgp"] = get_key_default(paramaters,"peer_pub_key_pgp","")
    paramaters["peer_signature"]   = get_key_default(paramaters,"peer_signature","")
    paramaters["peerASN"]          = get_key_default(paramaters,"peerASN",None)
    paramaters["hasIPV4"]          = get_key_default(paramaters,"hasIPV4",False)
    paramaters["peerIPV4"]         = get_key_default(paramaters,"peerIPV4",None)
    paramaters["hasIPV4LL"]        = get_key_default(paramaters,"hasIPV4LL",False)
    paramaters["peerIPV4LL"]       = get_key_default(paramaters,"peerIPV4LL",None)
    paramaters["hasIPV6"]          = get_key_default(paramaters,"hasIPV6",False)
    paramaters["peerIPV6"]         = get_key_default(paramaters,"peerIPV6",None)
    paramaters["hasIPV6LL"]        = get_key_default(paramaters,"hasIPV6LL",False)
    paramaters["peerIPV6LL"]       = get_key_default(paramaters,"peerIPV6LL",None)
    paramaters["myIPV4LL"]         = get_key_default(paramaters,"myIPV4LL",None)
    paramaters["myIPV6LL"]         = get_key_default(paramaters,"myIPV6LL",my_paramaters["myIPV6LL"])
    paramaters["myWG_Pri_Key"]     = get_key_default(paramaters,"myWG_Pri_Key",my_config["myWG_Pri_Key"])
    paramaters["myWG_MTU"]         = get_key_default(paramaters,"myWG_MTU",1280,int)
    paramaters["transitMode"]      = get_key_default(paramaters,"transitMode","Regular")
    paramaters["customDevice"]     = get_key_default(paramaters,"customDevice",None)
    paramaters["customDeviceSetup"]= get_key_default(paramaters,"customDeviceSetup","")
    paramaters["MP_BGP"]           = get_key_default(paramaters,"MP_BGP",False)
    paramaters["Ext_Nh"]           = get_key_default(paramaters,"Ext_Nh",False)
    paramaters["hasHost"]          = get_key_default(paramaters,"hasHost",False)
    paramaters["peerHost"]         = get_key_default(paramaters,"peerHost",None)
    paramaters["peerWG_Pub_Key"]   = get_key_default(paramaters,"peerWG_Pub_Key","")
    paramaters["peerWG_PS_Key"]    = get_key_default(paramaters,"peerWG_PS_Key","")
    paramaters["peerContact"]      = get_key_default(paramaters,"peerContact","")
    paramaters["peerName"]         = get_key_default(paramaters,"peerName",None)
    paramaters["PeerID"]           = get_key_default(paramaters,"PeerID",None)
    paramaters["hasIPV4"] = isFormTrue(paramaters["hasIPV4"])
    paramaters["hasIPV6"] = isFormTrue(paramaters["hasIPV6"])
    paramaters["hasIPV6LL"] = isFormTrue(paramaters["hasIPV6LL"])
    paramaters["MP_BGP"] = isFormTrue(paramaters["MP_BGP"])
    paramaters["Ext_Nh"] = isFormTrue(paramaters["Ext_Nh"])
    paramaters["hasHost"] = isFormTrue(paramaters["hasHost"])

    paramaters = {**my_paramaters,**paramaters} 
    return action , paramaters
    
async def action(paramaters):
    action , paramaters = get_paramaters(paramaters)
    try:
        try:
            if paramaters["PeerID"] != None:
                if int(paramaters["PeerID"]) < 0:
                    raise ValueError("Invalid PeerID")
        except Exception as e:
            filename = paramaters["PeerID"] + ".yaml"
            paramaters["PeerID"] = None
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), filename)
        if action=="OK":
            if paramaters["peerASN"] == None:
                paramaters["hasIPV4"] = True 
                paramaters["hasIPV6"] = True 
                paramaters["hasIPV6LL"] = True
                paramaters["MP_BGP"] = True
                paramaters["Ext_Nh"] = False
                paramaters["hasHost"] = True
            return 200, await get_html(paramaters,peerSuccess=False)
        if action == "Check My Info" or action == "Show":
            if paramaters["PeerID"] == None:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), "")
            try:
                peerInfo = yaml.load(open(wgconfpath + "/peerinfo/" + paramaters["PeerID"] + ".yaml").read(),Loader=yaml.SafeLoader)
            except FileNotFoundError as e:
                e.filename = paramaters["PeerID"] + ".yaml"
                raise e
            peerInfo = { valid_key: peerInfo[valid_key] for valid_key in client_valid_keys if valid_key in peerInfo }
            del peerInfo["peer_signature"]
            del peerInfo["peer_plaintext"]
            if paramaters["peer_pub_key_pgp"] != "" or  paramaters["peer_pub_key_pgp"] != None:
                del  peerInfo["peer_pub_key_pgp"]
            paramaters = {**paramaters,**peerInfo}
            return 200, await get_html(paramaters,peerSuccess=True)
        # Check ASN is valid for following action
        if paramaters["peerASN"] == None:
            raise ValueError("peerASN can't be null.")
        if paramaters["peerASN"].startswith("AS"):
            check_num = int(paramaters['peerASN'][2:])
        else:
            check_num = int(paramaters['peerASN'])
            paramaters["peerASN"] = "AS" + paramaters["peerASN"]
        #Actions need ASN
        if action=="Delete":
            await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_pub_key_pgp"],paramaters["peer_signature"])
            try:
                peerInfo = yaml.load(open(wgconfpath + "/peerinfo/" + paramaters["PeerID"] + ".yaml").read(),Loader=yaml.SafeLoader)
            except FileNotFoundError as e:
                e.filename = paramaters["PeerID"] + ".yaml"
                raise e
            if peerInfo["peerASN"] != paramaters["peerASN"]:
                raise PermissionError("Peer ASN not match")
            deleteConfig(peerInfo["PeerID"],peerInfo["peerName"],peerInfo["customDevice"])
            paramaters["PeerID"] = None
            return 200, get_err_page(paramaters,"Profile deleted:" ,yaml.dump(peerInfo,sort_keys=False).replace("\n","<br>"),big_title="Success!")
        elif action=="Get Signature":
            return 200, await get_signature_html(dn42repo_base,paramaters)
        elif action == "Register":
            mntner = await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_pub_key_pgp"],paramaters["peer_signature"])
            if mntner != my_config["admin_mnt"]:
                paramaters["PeerID"] = None
            paramaters = await check_reg_paramater(paramaters)
            new_config = newConfig(paramaters)
            if mntner == my_config["admin_mnt"]:
                paramaters["peer_pub_key_pgp"] = ""
            paramaters = new_config["paramaters"]
            saveConfig(new_config)
            if paramaters["myHost"] == None:
                myHostDisplay = paramaters["myHostDisplay"]
            else:
                myHostDisplay = paramaters["myHost"] + ":" + str(paramaters["PeerID"])
            myInfo = {
                "My ASN":          paramaters["myASN"],
                "DN42 IPv4":       paramaters["myIPV4"],
                "DN42 IPv6":       paramaters["myIPV6"],
                "IPv6 Link local": paramaters["myIPV6LL"],
                "Endpoint Address":myHostDisplay,
                "My WG Public Key":paramaters["myWG_Pub_Key"],
                "My Contact":  paramaters["myContact"]
            }
            return 200, get_err_page(paramaters, f'Your PeerID is: { paramaters["PeerID"] }<br>My info:',yaml.dump(myInfo, sort_keys=False),big_title="Peer Success!", tab_title = "Success!",redirect=my_config["register_redirect"])
        return 400, get_err_page(paramaters,"400 - Bad Request",ValueError("Unknow action" + str(action)))
    except Exception as e:
        title = type(e).__name__
        errcode = 400
        if type(e) == FileNotFoundError:
            title = "404 - File or directory not found."
            errorcode = 404
            e = "The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.\n    " + str(e.filename)
        #return errcode, get_err_page(paramaters,title,traceback.format_exc())
        print(traceback.format_exc())
        return errcode, get_err_page(paramaters,title,e)

ipv4s = [ipaddress.ip_network(n) for n in requests.get("https://www.cloudflare.com/ips-v4").text.split("\n")]
ipv6s = [ipaddress.ip_network(n) for n in requests.get("https://www.cloudflare.com/ips-v6").text.split("\n")]

def get_ip(r):
    rip = ipaddress.ip_address( r.remote_ip )
    if type(rip) == ipaddress.IPv4Address:
        clist = ipv4s
    else:
        clist = ipv6s
    for c in clist:
        if rip in c:
            return r.headers["CF-Connecting-IP"]
    return r.remote_ip


class actionHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(actionHandler, self).__init__(*args, **kwargs)
    def set_default_headers(self, *args, **kwargs):
        # Just for fun, pretend I am a php server
        self.set_header('server','Microsoft-IIS/7.5')
        self.set_header('x-powered-by','PHP/5.4.2')
    async def get(self, *args, **kwargs): 
        paramaters = { k: self.get_argument(k) for k in self.request.arguments }
        print("GET " + self.request.uri + f' ({get_ip(self.request)}) ' , paramaters)
        code, ret = await action(paramaters)
        self.set_status(code)
        self.write(ret)
    async def post(self, *args, **kwargs): 
        paramaters = { k: self.get_argument(k) for k in self.request.arguments }
        print("POST " + self.request.uri + f' ({get_ip(self.request)}) ' , paramaters)
        code, ret = await action(paramaters)
        self.set_status(code)
        self.write(ret)

nfpage = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
<title>404 - File or directory not found.</title>
<style type="text/css">
<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;} 
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;} 
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;} 
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>404 - File or directory not found.</h2>
  <h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>
 </fieldset></div>
</div>
</body>
</html>
"""

class My404Handler(tornado.web.RequestHandler):
    # Override prepare() instead of get() to cover all possible HTTP methods.
    def prepare(self):
        self.set_status(404)
        self.write(nfpage)
    def post(self, *args, **kwargs):
        pass
    def get(self, *args, **kwargs):
        pass

if __name__ == '__main__':
    if my_config["urlprefix"] == "" or  my_config["urlprefix"] == "/":
        url_prefix = ""
        url_prefix_pre = ""
    elif my_config["urlprefix"][-1] == "/":
        url_prefix = my_config["urlprefix"]
        url_prefix_pre = my_config["urlprefix"][:-1]
    else:
        url_prefix = my_config["urlprefix"] + "/"
        url_prefix_pre = my_config["urlprefix"]
    app = tornado.web.Application(handlers=[
        ('/' + url_prefix, actionHandler),
        ('/' + url_prefix + 'action_page.php', actionHandler),
        ('/' + url_prefix_pre, tornado.web.RedirectHandler, {"url": url_prefix}),
        ('/' + url_prefix_pre, tornado.web.RedirectHandler, {"url": url_prefix}),
        ('/', tornado.web.RedirectHandler, {"url": url_prefix}),
        (r"(.*)", My404Handler),
    ])
    if my_config["init_device"] == True:
        initDevice()
    syncwg = multiprocessing.Process(target=syncWG, args=())
    syncwg.start()
    server = tornado.httpserver.HTTPServer(app, ssl_options=my_config["ssl_options"] )
    server.listen(my_config["listen_port"],my_config["listen_host"])
    print("Done. Start serving http(s) on " + my_config["listen_host"]+ ":" + str(my_config["listen_port"]))
    tornado.ioloop.IOLoop.current().start()
