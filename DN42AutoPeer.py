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
import nacl.public
import tornado.web
import tornado.gen
from git import Repo
import tornado.ioloop
import multiprocessing
from urllib import parse
import tornado.httpclient
import requests.packages.urllib3
from Crypto.PublicKey import RSA
from ipaddress import IPv4Network , IPv6Network , IPv4Interface , IPv6Interface, IPv4Address , IPv6Address
from ipaddress import IPv6Network
from subprocess import Popen, PIPE, STDOUT
from tornado.httpclient import HTTPClientError
import DN42whois 
from DN42GIT import DN42GIT

requests.packages.urllib3.disable_warnings()

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

peerHostDisplayText = "(Peer endpoint hidden, authenticate to show)"

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
    open(confpath,"w").write(yaml.dump(my_config, sort_keys=False))

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
try_read_env(my_paramaters,"myIPV4",'DN42AP_MY_IPV4')
try_read_env(my_paramaters,"myIPV6",'DN42AP_MY_IPV6')
try_read_env(my_paramaters,"myIPV4LL",'DN42AP_MY_IPV4_LL')
try_read_env(my_paramaters,"myIPV6LL",'DN42AP_MY_IPV6_LL')
try_read_env(my_paramaters,"myHost",'DN42AP_ENDPOINT')
try_read_env(my_paramaters,"myHostDisplay",'DN42AP_HOST_DISPLAY')
try_read_env(my_paramaters,"myASN",'DN42_E_AS')
try_read_env(my_paramaters,"myContact",'DN42_CONTACT')
try_read_env(my_paramaters,"allowExtNh",'DN42AP_ALLOW_ENH',bool,False)
try_read_env(my_config,"myHostHidden",'DN42AP_HOST_HIDDEN',bool,False)
try_read_env(my_config,"peerEndpointHidden",'DN42AP_PEER_ENDPOINT_HIDDEN',bool,False)
try_read_env(my_config,"registerAdminOnly",'DN42AP_REGISTER_ADMINONLY',bool,False)
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
try_read_env(my_config,"dn42_whois_server","DN42AP_WHOIS_SERVER","json")
try_read_env(my_config,"dn42repo_base","DN42AP_REPO_BASE",str)
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

client_valid_keys = ["peer_plaintext","peer_pub_key_pgp","peer_signature", "peerASN","peerName", "hasIPV4", "peerIPV4","hasIPV4LL","peerIPV4LL", "hasIPV6", "peerIPV6", "hasIPV6LL", "peerIPV6LL","MP_BGP","Ext_Nh", "hasHost", "peerHost", "peerWG_Pub_Key","peerWG_PS_Key", "peerContact", "PeerID","myIPV4","myIPV6","myIPV4LL","myIPV6LL","customDevice","customDeviceSetup","myWG_Pri_Key","transitMode","myWG_MTU","birdAddConf"]
client_valid_keys_admin_only = ["customDevice","customDeviceSetup","myWG_Pri_Key","peerName","birdAddConf","transitMode","myWG_MTU"]
dn42repo_base = my_config["dn42repo_base"]
DN42_valid_ipv4s = my_config["DN42_valid_ipv4s"]
DN42_valid_ipv6s = my_config["DN42_valid_ipv6s"]
valid_ipv4_lilo = my_config["valid_ipv4_linklocal"]
valid_ipv6_lilo = my_config["valid_ipv6_linklocal"]
wg_allowed_ips = DN42_valid_ipv4s + DN42_valid_ipv6s + [valid_ipv4_lilo , valid_ipv6_lilo ]
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
gpg --armor --export --fingerprint {fingerprint}<br>
<br>
# sign message with your PGP private key<br>
echo -n "{text2sign}" | gpg --clearsign --detach-sign -u {fingerprint}<br>
<br>
# Done. You can copy the signature now<br>
</code>""",
"PGPKEY": """<h4>Paste following command to your terminal to get your PGP public key and signature.</h4>
<code>
# Export PGP public key<br>
gpg --armor --export --fingerprint {fingerprint}<br>
<br>
# sign message with your PGP private key<br>
echo -n "{text2sign}" | gpg --clearsign --detach-sign -u {fingerprint}<br>
<br>
# Done. You can copy the signature now<br>
</code>"""
}

async def get_signature_html(baseURL,paramaters):
    peerASN = paramaters["peerASN"]
    peerMNT, peerADM = await get_info_from_asn(peerASN)
    try:
        peerADMname = (await get_auth_info(["person","role"],peerADM[0]))["display"][0]
    except Exception as e:
        peerADMname = ""
    methods = await get_auth_method(peerMNT, peerADM)
    text2sign = jwt.encode({'ASN': peerASN, "exp":datetime.datetime.utcnow() + datetime.timedelta(minutes = 30) }, jwt_secret, algorithm='HS256')
    methods_class = {"Supported":{},"Unsupported":{}}
    for m,v,mnt in methods:
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
        retstr += f"""<h4>&nbsp;&nbsp;&nbsp;&nbsp;Sorry, we couldn't find any available authentication method in your <a href="{baseURL}mntner/{peerMNT}" target="_blank">mntner</a> object or <a href="{baseURL}person/{peerADM}" target="_blank"> admin contact</a> in the DN42 registry.</h4><h4>Please <a href="{my_paramaters["myContact"]}" target="_blank">contact me</a> to peer manually.</h4>"""
    else:
        retstr += f"""<h4>&nbsp;&nbsp;&nbsp;&nbsp;Please sign our message with your private key registered in your <a href="{baseURL}mntner/{peerMNT}" target="_blank">mntner object</a> or <a href="{baseURL}person/{peerADM}" target="_blank"> admin contact</a> in the DN42 registry.</h4>"""
    retstr += "<h3><font color='red'><b>Supported</b></font> auth method: </h3>" if len(list(methods_class["Supported"].keys())) != 0 else ""
    for m,v in methods_class["Supported"].items():
        retstr += f"""<table class="table"><tr><td><b>Allowed {m}(s): </b></td></tr>"""
        for v_item in v:
            retstr += f"""<tr><td>{v_item}</td></tr>"""
        retstr += "</table>"
        retstr += method_hint[m].format(text2sign = text2sign,fingerprint=v[0])
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
        if k in client_valid_keys_admin_only:
            continue
        if v == None:
            v = ""
        elif v == True:
            v = "on"
        retstr += f'<input type="hidden" name="{k}" value="{v}">\n'
    retstr +="""<input type="submit" translate="no" name="action" value="OK" />
</form>
</body>
</html>
"""
    return retstr

def wgpri2pub(pri):
    try:
        pb = base64.b64decode(pri)
        pp = nacl.public.PrivateKey(pb)
        return base64.b64encode(bytes(pp.public_key)).decode("ascii")
    except Exception as e:
        return "Wireguard Key: " + str(e)

async def get_html(paramaters,action="OK",peerSuccess=False):
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
    hasIPV4LL = paramaters["hasIPV4LL"]
    hasIPV4LLDisabled = ""
    peerIPV4LL = paramaters["peerIPV4LL"]
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
    peerHostDisplay = peerHostDisplayText
    peerWG_Pub_Key = paramaters["peerWG_Pub_Key"]
    peerWG_PS_Key = paramaters["peerWG_PS_Key"]
    peerContact = paramaters["peerContact"]
    PeerID = paramaters["PeerID"]
    myASN = paramaters["myASN"]
    myHost = paramaters["myHost"]
    myIPV4 = paramaters["myIPV4"]
    myIPV6 = paramaters["myIPV6"]
    myIPV4LL = paramaters["myIPV4LL"]
    myIPV6LL = paramaters["myIPV6LL"]
    myWG_Pub_Key = paramaters["myWG_Pub_Key"]
    myContact = paramaters["myContact"]
    if myIPV4 == None:
        myIPV4 = ""
    if myIPV6 == None:
        myIPV6 = ""
    if myIPV4LL == None:
        myIPV4LL = ""
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
    if myIPV4LL == "":
        hasIPV4LL = False
        hasIPV4LLDisabled = "disabled"
        peerIPV4LL = "Sorry, I don't support IPv4 link local address."
    if myIPV6LL == "":
        hasIPV6LL = False
        hasIPV6LLDisabled = "disabled"
        peerIPV6LL = "Sorry, I don't support IPv6 link local address."
    if not (myIPV4!="") and (myIPV6!="" or myIPV6LL!=""):
        MP_BGP_Disabled = "disabled"
        Ext_Nh_Disabled = "disabled"
    if my_config["peerEndpointHidden"] and action == "Show":
        if peer_signature != "" and peer_signature != None:
            try:
                mntner = await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_pub_key_pgp"],peer_signature)
                peerHostDisplay = peerHost
            except Exception as e:
                pass
    else:
        peerHostDisplay = peerHost
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
        if my_config["myHostHidden"]:
            if peer_signature != "" and peer_signature != None:
                try:
                    mntner = await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_pub_key_pgp"],peer_signature)
                    myHostDisplay = myHost + ":"
                except Exception as e:
                    pass
        else:
            myHostDisplay = myHost + ":"
        if PeerID == None:
            myHostDisplay += f" [{my_config['wg_port_search_range']}]"
        else:
            myHostDisplay += str(PeerID)
    edit_btn_disabled = "disabled"
    try:
        peerInfo = yaml.load(open(wgconfpath + "/peerinfo/" + str(paramaters["PeerID"]) + ".yaml").read(),Loader=yaml.SafeLoader)
        edit_btn_disabled = ""
    except FileNotFoundError as e:
        pass
    jsscripts = """
prevVars={
  v4: "hasIPV4",
  v6: "hasIPV6LL",
  nov4: "v4only"
}
function getV4() {
  return document.getElementsByName("hasIPV4")[0].checked || document.getElementsByName("hasIPV4LL")[0].checked
}
function getV6() {
  return document.getElementsByName("hasIPV6")[0].checked || document.getElementsByName("hasIPV6LL")[0].checked
}

function onV4() {
  if (document.getElementsByName("hasIPV4")[0].checked == true){
    document.getElementsByName("hasIPV4LL")[0].checked = false;
    document.getElementsByName("Ext_Nh")[0].checked = false;
    prevVars.v4 = "hasIPV4"
  } else {
    if( (getV4() || getV6()) == false){
        alert("We can't establish BGP session without any IP.")
        document.getElementsByName("hasIPV4")[0].checked = true;
        return false;
    }
    if (prevVars.nov4 == "enh"){
      document.getElementsByName("Ext_Nh")[0].checked = true
    } else {
      document.getElementsByName("MP_BGP")[0].checked = false
    }
  }
}
function onV4LL() {
  if (document.getElementsByName("hasIPV4LL")[0].checked == true){
    document.getElementsByName("hasIPV4")[0].checked = false;
    document.getElementsByName("Ext_Nh")[0].checked = false;
    prevVars.v4 = "hasIPV4LL"
  } else {
    if( (getV4() || getV6()) == false){
        alert("We can't establish BGP session without any IP.")
        document.getElementsByName("hasIPV4LL")[0].checked = true;
        return false;
    }
    if (prevVars.nov4 == "enh"){
      document.getElementsByName("Ext_Nh")[0].checked = true
    } else {
      document.getElementsByName("MP_BGP")[0].checked = false
    }
  }
}
function onV6() {
  if (document.getElementsByName("hasIPV6")[0].checked == true){
    document.getElementsByName("hasIPV6LL")[0].checked = false;
    document.getElementsByName("MP_BGP")[0].disabled = false;
    document.getElementsByName("Ext_Nh")[0].disabled = false;
    prevVars.v6 = "hasIPV6"
  } else {
    if( (getV4() || getV6()) == false){
        alert("We can't establish BGP session without any IP.")
        document.getElementsByName("hasIPV6")[0].checked = true;
        return false;
    }
    if (getV6() == false){
      document.getElementsByName("MP_BGP")[0].checked = false;
      document.getElementsByName("Ext_Nh")[0].checked = false
      document.getElementsByName("MP_BGP")[0].disabled = true;
      document.getElementsByName("Ext_Nh")[0].disabled = true;
      prevVars.nov4 = "v4only"
    }
  }
}
function onV6LL() {
  if (document.getElementsByName("hasIPV6LL")[0].checked == true){
    document.getElementsByName("hasIPV6")[0].checked = false;
    document.getElementsByName("MP_BGP")[0].disabled = false;
    document.getElementsByName("Ext_Nh")[0].disabled = false;
    prevVars.v6 = "hasIPV6LL"
  } else {
    if( (getV4() || getV6()) == false){
        alert("We can't establish BGP session without any IP.")
        document.getElementsByName("hasIPV6LL")[0].checked = true;
        return false;
    }
    if (getV6() == false){
      document.getElementsByName("MP_BGP")[0].checked = false;
      document.getElementsByName("Ext_Nh")[0].checked = false
      document.getElementsByName("MP_BGP")[0].disabled = true;
      document.getElementsByName("Ext_Nh")[0].disabled = true;
      prevVars.nov4 = "v4only"
    }
  }
}
function onMPBGP() {
  if (document.getElementsByName("MP_BGP")[0].checked == true){
    document.getElementsByName(prevVars.v4)[0].checked = true;
  }
  if (document.getElementsByName("MP_BGP")[0].checked == false){
    document.getElementsByName("Ext_Nh")[0].checked = false;
    prevVars.nov4 = "v4only"
  }
}
function onENH() {
  if (document.getElementsByName("Ext_Nh")[0].checked == true){
    document.getElementsByName("hasIPV4")[0].checked = false;
    document.getElementsByName("hasIPV4LL")[0].checked = false;
    document.getElementsByName("MP_BGP")[0].checked = true;
    prevVars.nov4 = "enh"
  } else {
    document.getElementsByName(prevVars.v4)[0].checked = true;
  }
}
"""
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
<script>
{jsscripts}
</script>
<form action="action_page.php" method="post" class="markdown-body">
 <h2>Authentication</h2>
 <table class="table">
   <tr><td>Your ASN</td><td><input type="text" value="{peerASN if peerASN != None else ""}" name="peerASN" /></td></tr>
   <tr><td>Plain text to sign</td><td><input type="text" value="{peer_plaintext}" name="peer_plaintext" readonly/></td></tr>
   <tr><td>Your PGP public key<br>(leave it blank if you don't use it)</td><td><textarea name="peer_pub_key_pgp">{peer_pub_key_pgp}</textarea></td></tr>
   <tr><td>Your signature</td><td><textarea name="peer_signature">{peer_signature}</textarea></td></tr>
   <tr><td>Fill your ASN, Click the button, Follow the instruction</td><td><input type="submit" translate="no" name="action" value="Get Signature" /></td></tr>
 </table>
 <h2>Registration</h2>
 <table class="table">
   <tr><td><h5>BGP Session Info:</h5></td><td>  </td></tr>
   <tr><td><input type="checkbox" name="hasIPV4" onclick="onV4()" {"checked" if hasIPV4 else ""} {hasIPV4Disabled}>DN42 IPv4</td><td><input type="text" value="{peerIPV4 if peerIPV4 != None else ""}" name="peerIPV4" {hasIPV4Disabled} /></td></tr>
   <tr><td><input type="checkbox" name="hasIPV4LL" onclick="onV4LL()" {"checked" if hasIPV4LL else ""} {hasIPV4LLDisabled}>IPv4 Link local</td><td><input type="text" value="{peerIPV4LL if peerIPV4LL != None else ""}" name="peerIPV4LL" {hasIPV4LLDisabled} /></td></tr>
   <tr><td><input type="checkbox" name="hasIPV6" onclick="onV6()" {"checked" if hasIPV6 else ""} {hasIPV6Disabled}>DN42 IPv6</td><td><input type="text" value="{peerIPV6 if peerIPV6 != None else ""}" name="peerIPV6" {hasIPV6Disabled} /></td></tr>
   <tr><td><input type="checkbox" name="hasIPV6LL" onclick="onV6LL()" {"checked" if hasIPV6LL else ""} {hasIPV6LLDisabled}>IPv6 Link local</td><td><input type="text" value="{peerIPV6LL if peerIPV6LL != None else ""}" name="peerIPV6LL" {hasIPV6LLDisabled} /></td></tr>
   <tr><td><input type="checkbox" name="MP_BGP" onclick="onMPBGP()" {"checked" if MP_BGP else ""} {MP_BGP_Disabled} >Multiprotocol BGP</td><td></td></tr>
   <tr><td><input type="checkbox" name="Ext_Nh" onclick="onENH()" {"checked" if Ext_Nh else ""} {Ext_Nh_Disabled} >Extended next hop</td><td></td></tr>
   <tr><td><h5>Wireguard Connection Info:</h5></td><td>  </td></tr>
   <tr><td><input type="checkbox" name="hasHost" {"checked" if hasHost else ""} {hasHost_Readonly}>Your Clearnet Endpoint (domain or ip:port)</td><td><input type="text" value="{peerHostDisplay if peerHost != None else ""}" name="peerHost" /></td></tr>
   <tr><td>Your Wireguard Public Key</td><td><input type="text" value="{peerWG_Pub_Key}" name="peerWG_Pub_Key" /></td></tr>
   <tr><td>Your Wireguard Pre-Shared Key (Optional)</td><td><input type="text" value="{peerWG_PS_Key}" name="peerWG_PS_Key" /></td></tr>
   <tr><td>Your Telegram ID or e-mail</td><td><input type="text" value="{peerContact}" name="peerContact" /></td></tr>
   <tr><td>Register a new peer and get the peer ID</td><td><input type="submit" translate="no" name="action" value="Register" /></td></tr>
   </table>
   <h2>Management</h2>
   <table  class="table">
   <tr><td>Your Peer ID</td><td><input type="text" value="{PeerID if PeerID != None else ""}" name="PeerID" /></td></tr>
   <tr><td></td><td><input type="submit" translate="no" name="action" value="Show" /><input type="submit" translate="no" name="action" value="Update" {edit_btn_disabled}/><input type="submit" translate="no" name="action" value="Delete" {edit_btn_disabled} /></td></tr>
 </table>
<h3>{"Peer success! " if peerSuccess else "This is "}My Info</h3>
 <table>
   <tr><td>My ASN</td><td><input type="text" value="{myASN}" readonly /></td></tr>
   <tr><td>DN42 IPv4</td><td><input type="text" name="myIPV4" value="{myIPV4}" /></td></tr>
   <tr><td>DN42 IPv6</td><td><input type="text" name="myIPV6" value="{myIPV6}" /></td></tr>
   <tr><td>IPv4 Link local</td><td><input type="text" name="myIPV4LL" value="{myIPV4LL}" {hasIPV4LLDisabled} /></td></tr>
   <tr><td>IPv6 Link local</td><td><input type="text" name="myIPV6LL" value="{myIPV6LL}" {hasIPV6LLDisabled} /></td></tr>
   <tr><td>Connectrion Info: </td><td>  </td></tr>
   <tr><td>My Clearnet Endpoint</td><td><input type="text" value="{myHostDisplay}" readonly /></td></tr>
   <tr><td>My WG Public Key</td><td><input type="text" value="{myWG_Pub_Key}" readonly /></td></tr>
   <tr><td>My Contact</td><td><input type="text" value="{myContact}" readonly /></td></tr>
 </table>
</form>
</body>
</html>
"""

remove_empty_line = lambda s: "\n".join(filter(lambda x:len(x)>0, s.replace("\r\n","\n").replace("\r","\n").split("\n")))
async def get_info_from_asn(asn):
    asn_info = await whois_query("aut-num/" + asn)
    data = DN42whois.proc_data(asn_info)
    mnts = get_key_default(data,"mnt-by",[])
    adms = get_key_default(data,"admin-c",[])
    return mnts , adms

async def get_auth_info(categories,name):
    for category in categories:
        try:
            auth_info = await whois_query(category + "/" + name)
        except FileNotFoundError as e:
            continue
        ret = DN42whois.proc_data(auth_info)
        if "auth" not in ret:
            ret["auth"] = []
        if "pgp-fingerprint" in ret:
            ret["auth"] += ["pgp-fingerprint " + ret["pgp-fingerprint"][0]]
        
        if "person" in ret and len(ret["person"]) > 0:
            ret["display"] = [ret["person"][0]]
        elif "role" in ret and  len(ret["role"]) > 0:
            ret["display"] = [ret["role"][0]]
        else:
            ret["display"] = ["[Error: Name not found]"]
        return ret
    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), categories + "/" + name)

async def get_auth_method(mnts,admins): # return [[method,auth_key,mnter]]
    authes = []
    for mnt in mnts:
        try:
            authes += [[a,mnt] for a in (await get_auth_info(["mntner"],mnt))["auth"]]
        except FileNotFoundError as e:
            pass
    for admin in admins:
        try:
            authes += [[a,admin] for a in (await get_auth_info(["person","role"],admin))["auth"]]
        except FileNotFoundError as e:
            pass
    auth_dict = {}
    for auth in authes:
        a,mnt = auth
        if a.startswith("PGPKEY"):
            method , pgp_sign8 = a.split("-",1)
            pgp_pubkey_str = await try_get_pub_key(pgp_sign8)
            if pgp_pubkey_str == "":
                continue
            try:
                pub = pgpy.PGPKey.from_blob(remove_empty_line(pgp_pubkey_str).encode("utf8"))[0]
                real_fingerprint = pub.fingerprint.replace(" ","")
                ainfo = method + " " + real_fingerprint
            except Exception as e:
                ainfo = method + "_Error " + str(e).replace(" ","_")
        else:
            ainfo = a
        auth_dict[ainfo] = mnt
    ret = []
    for r,v in auth_dict.items():
        if len(r.split(" ",1)) == 2:
            m,a = r.split(" ",1)
            ret += [[m,a,v]]
    return ret

async def try_get_pub_key(pgpsig):
    if len(pgpsig) < 8:
        return ""
    pgpsig = pgpsig[-8:]
    try:
        result = await whois_query("key-cert/PGPKEY-" + pgpsig)
        result = list(filter(lambda l:l.startswith("certif:"),result.split("\n")))
        result = list(map(lambda x:x.split(":")[1].lstrip(),result))
        result = "\n".join(result)
        return remove_empty_line(result)
    except Exception as e:
        pass
    return ""


def verify_signature_pgp(plaintext,fg,pub_key,raw_signature):
    pub = pgpy.PGPKey.from_blob(remove_empty_line(pub_key).encode("utf8"))[0]
    fg_in = fg.replace(" ","").upper()
    fg_p = pub.fingerprint.replace(" ","")
    if fg_in != fg_p:
        raise ValueError("fingerprint not match")
    sig = pgpy.PGPSignature.from_blob(remove_empty_line(raw_signature).encode("utf8"))
    if not pub.verify(plaintext,sig):
        raise ValueError("signature verification failed")
    return True

def verify_signature_pgpn8(plaintext,fg,pub_key,raw_signature):
    pub = pgpy.PGPKey.from_blob(remove_empty_line(pub_key).encode("utf8"))[0]
    fg_in = fg.replace(" ","")
    fg_p = pub.fingerprint.replace(" ","")
    if fg_in != fg_p:
        raise ValueError("fingerprint not match")
    sig = pgpy.PGPSignature.from_blob(remove_empty_line(raw_signature).encode("utf8"))
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
        for method,pub_key,mnt in authes:
            try:
                if verify_signature(plaintext,pub_key,pub_key_pgp,raw_signature,method) == True:
                    return mnt
            except Exception as e:
                authresult += [{"Source": "User credential","Method": method , "Result": type(e).__name__ + ": " + str(e), "Content":  pub_key}]
        # verify admin signature
        mntner_admin = [my_config["admin_mnt"]]
        try:
            authes_admin = await get_auth_method(mntner_admin,[])
            for method,pub_key,mnt in authes_admin:
                try:
                    if verify_signature(plaintext,pub_key,pub_key_pgp,raw_signature,method) == True:
                        return mnt
                except Exception as e:
                    authresult += [{"Source": "Admin credential", "Method": method , "Result": type(e).__name__ + ": " + str(e), "Content":  pub_key}]
        except Exception as e:
            pass
        raise ValueError(yaml.dump(authresult, sort_keys=False,default_style='|'))
    except Exception as e:
        class AuthenticationError(type(e)):
            def init(m):
                super(m)
        AuthenticationError.__name__ = "AuthenticationError: " + type(e).__name__
        raise AuthenticationError(str(e))

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
        if k in client_valid_keys_admin_only:
            continue
        if v == None:
            v = ""
        elif v == True:
            v = "on"
        retstr += f'<input type="hidden" name="{k}" value="{v}">\n'
    if redirect == None:
        retstr +='<input type="submit" translate="no" name="action" value="OK" />'
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

def check_valid_ip_range(af,IPranges,ip,name,only_ip = True):
    if af == "IPv4":
        IPNet = IPv4Network
        IPInt = IPv4Interface
    elif af == "IPv6":
        IPNet = IPv6Network
        IPInt = IPv6Interface
    else:
        raise ValueError("Unknown af:",af)
    if only_ip:
        if "/" in ip:
            raise ValueError(ip + " is not a valid IPv4 or IPv6 address")
        if IPNet(ip).num_addresses != 1:
            raise ValueError(ip + " contains more than one IP")
    for iprange in IPranges:
        if IPNet(iprange,strict=False).supernet_of(IPInt(ip).network):
            return True
    raise ValueError(ip + " are not in " + name + " range: " + str(IPranges))

async def check_asn_ip(admin,mntner,asn,af,ip,only_ip=True):
    if af == "IPv4":
        IPNet = IPv4Network
        IPInt = IPv4Interface
        allowed = DN42_valid_ipv4s
        descr = "DN42 IPv4"
    elif af == "IPv6":
        IPNet = IPv6Network
        IPInt = IPv6Interface
        allowed = DN42_valid_ipv6s
        descr = "DN42 IPv6"
    else:
        raise ValueError("Unknown af:",af)
    check_valid_ip_range(af,IPranges=allowed,ip=ip,name=descr,only_ip=only_ip)
    peerIP_info = DN42whois.proc_data((await whois_query(ip)))
    if "origin" not in peerIP_info or len(peerIP_info["origin"]) == 0:
        originASN = "nobody"
    else:
        originASN = peerIP_info["origin"][0]
    origin_check_pass = False
    if asn in peerIP_info["origin"]:
        return True
    elif mntner in peerIP_info["mnt-by"] and mntner != "DN42-MNT":
        return True
    elif admin in peerIP_info["admin-c"]:
        return True
    else:
        ipowner = peerIP_info["admin-c"][0] if len(peerIP_info["admin-c"]) > 0 else None
        raise PermissionError("IP " + ip + f" owned by {originASN}({ipowner}) instead of {asn}({admin})")

async def check_reg_paramater(paramaters,skip_check=None,git_pull=True,allow_invalid_as=False,allowed_custom_myip=[]):
    if (paramaters["hasIPV4"] or paramaters["hasIPV4LL"] or paramaters["hasIPV6"] or paramaters["hasIPV6LL"]) == False:
        raise ValueError("You can't peer without any IP.")
    if paramaters["peerASN"] == "AS" + paramaters["myASN"]:
        raise ValueError("You can't peer with my ASN.")
    try:
        mntner,admin = await get_info_from_asn(paramaters["peerASN"])
    except FileNotFoundError as e:
        if allow_invalid_as:
            mntner,admin = [["DN42-MNT"],["BURBLE-DN42"]]
        else:
            raise e
    ######################### hasIPV4
    if paramaters["hasIPV4"]:
        if paramaters["myIPV4"] == None:
            raise NotImplementedError("Sorry, I don't have IPv4 address.")
        await check_asn_ip(admin,mntner,paramaters['peerASN'],"IPv4",paramaters["peerIPV4"],only_ip=True)
        if paramaters["myIPV4"] == my_paramaters["myIPV4"] or paramaters["myIPV4"] in allowed_custom_myip:
            pass
        else:
            if "/" not in paramaters["myIPV4"]:
                await check_asn_ip(admin,mntner,paramaters['peerASN'],"IPv4",paramaters["myIPV4"],only_ip=True)
            else:
                await check_asn_ip(admin,mntner,paramaters['peerASN'],"IPv4",paramaters["myIPV4"],only_ip=False)
                check_valid_ip_range("IPv4",[paramaters["myIPV4"]],paramaters["peerIPV4"],"allocated IPv4 to me")
    else:
        paramaters["peerIPV4"] = None
    ######################### hasIPV6
    if paramaters["hasIPV6"]:
        if paramaters["myIPV6"] == None:
            raise NotImplementedError("Sorry, I don't have IPv6 address.")
        await check_asn_ip(admin,mntner,paramaters['peerASN'],"IPv6",paramaters["peerIPV6"],only_ip=True)
        if paramaters["myIPV6"] == my_paramaters["myIPV6"] or paramaters["myIPV6"] in allowed_custom_myip:
            pass
        else:
            if "/" not in paramaters["myIPV6"]:
                await check_asn_ip(admin,mntner,paramaters['peerASN'],"IPv6",paramaters["myIPV6"],only_ip=True)
            else:
                await check_asn_ip(admin,mntner,paramaters['peerASN'],"IPv6",paramaters["myIPV6"],only_ip=False)
                check_valid_ip_range("IPv6",[paramaters["myIPV6"]],paramaters["peerIPV6"],"allocated IPv6 to me")
    else:
        paramaters["peerIPV6"] = None
    ######################### hasIPV4LL
    if paramaters["hasIPV4LL"]:
        if paramaters["myIPV4LL"] == None:
            raise NotImplementedError("Sorry, I don't have IPv4 link-local address.")
        check_valid_ip_range("IPv4",[valid_ipv4_lilo],paramaters["peerIPV4LL"],"link-local ipv4")
        check_valid_ip_range("IPv4",[valid_ipv4_lilo],paramaters["myIPV4LL"].split("/")[0],"link-local ipv4")
        paramaters["myIPV4LL"] = paramaters["myIPV4LL"].split("/")[0] + "/" + valid_ipv4_lilo.split("/")[1]
    else:
        paramaters["peerIPV4LL"] = None
    ######################### hasIPV6LL
    if paramaters["hasIPV6LL"]:
        if paramaters["myIPV6LL"] == None:
            raise NotImplementedError("Sorry, I don't have IPv6 link-local address.")
        check_valid_ip_range("IPv6",[valid_ipv6_lilo],paramaters["peerIPV6LL"],"link-local ipv6")
        check_valid_ip_range("IPv6",[valid_ipv6_lilo],paramaters["myIPV6LL"].split("/")[0],"link-local ipv6")
        paramaters["myIPV6LL"] = paramaters["myIPV6LL"].split("/")[0] + "/" + valid_ipv6_lilo.split("/")[1]
    else:
        paramaters["peerIPV6LL"] = None
    if paramaters["MP_BGP"]:
        if not (paramaters["hasIPV6"] or paramaters["hasIPV6LL"]):
            raise ValueError("Value Error. You need a IPv6 address to use multiprotocol BGP.")
        if not paramaters["Ext_Nh"]:
            if not (paramaters["hasIPV4"] or paramaters["hasIPV4LL"]):
                raise ValueError("Value Error. You need a IPv4 address to enable multiprotocol BGP unless you support extended next hop.")
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
    else:
        paramaters["peerWG_Pub_Key"] = ""
        paramaters["myWG_Pub_Key"] = ""
    if git_pull:
        RRstate_repo.pull()
    conf_dir = wgconfpath + "/peerinfo"
    if os.path.isdir(conf_dir): #Check this node hasn't peer with us before
        for old_conf_file in os.listdir(conf_dir):
            if old_conf_file.endswith(".yaml") and os.path.isfile(f"{conf_dir}/{old_conf_file}"):
                if skip_check != None and old_conf_file[:-5] == str(skip_check):
                    continue
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
    birdAddConf = paramaters["birdAddConf"]
    mtu = paramaters["myWG_MTU"]
    customDevice = paramaters["customDevice"]
    customDeviceSetup = paramaters["customDeviceSetup"]
    successdisplay = { "My ASN":  paramaters["myASN"]}
    peerV4use = None
    myV4use = None
    myV4useIP = None
    if peerIPV4LL != None:
        peerV4use = peerIPV4LL
        myV4use = myIPV4LL
        myV4useIP = myIPV4LL.split("/")[0] if myIPV4LL != None else None
        successdisplay["IPv4 Link local"] = myV4useIP
        if IPv4Address(peerV4use) == IPv4Address(myV4useIP):
            raise ValueError("Your tunnel IPv6 link local address are conflicted with mine: " + str(IPv4Address(peerV4use)))
    elif peerIPV4 != None:
        peerV4use = peerIPV4
        myV4use = myIPV4
        myV4useIP = myIPV4.split("/")[0] if myIPV4 != None else None
        successdisplay["DN42 IPv4"] = myV4useIP
        if IPv4Address(peerV4use) == IPv4Address(myV4useIP):
            raise ValueError("Your tunnel IPv4 address are conflicted with mine: " + str(IPv4Address(peerV4use)))
    peerV6use =None
    myV6use = None
    myV6useIP =None
    if peerIPV6LL != None:
        peerV6use = peerIPV6LL
        myV6use = myIPV6LL
        myV6useIP = myIPV6LL.split("/")[0] if myIPV6LL != None else None
        successdisplay["IPv6 Link local"] = myV6useIP
        if IPv6Address(peerV6use) == IPv6Address(myV6useIP):
            raise ValueError("Your tunnel IPv6 link local address are conflicted with mine: " + str(IPv6Address(peerV6use)))
    elif peerIPV6 != None:
        peerV6use = peerIPV6
        myV6use = myIPV6
        myV6useIP = myIPV6.split("/")[0] if myIPV6 != None else None
        successdisplay["DN42 IPv6"] = myV6useIP
        if IPv6Address(peerV6use) == IPv6Address(myV6useIP):
            raise ValueError("Your tunnel IPv6 address are conflicted with mine: " + str(IPv6Address(peerV6use)))
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
                                AllowedIPs = {  ", ".join( wg_allowed_ips ) }
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
    
    birdPeerV4 = peerV4use
    birdMyV4 = myV4useIP
    birdPeerV6 = peerV6use
    birdMyV6 = myV6useIP
    if peerV4use != None:
        if peerV6use != None and MP_BGP == True and Ext_Nh == True:
            birdPeerV4 = None
            birdMyV4 = None
        if Ext_Nh == False:
            if "/" in myV4use:
                setupsh += f"ip addr add {myV4use} dev {if_name} scope link\n"
            else:
                setupsh += f"ip addr add {myV4useIP} peer {peerIPV4} dev {if_name} scope link\n"
    
    if peerV6use != None:
        if "/" in myV6use:
            setupsh += f"ip addr add {myV6use} dev {if_name} scope link\n"
        else:
            setupsh += f"ip addr add {myV6useIP} peer {peerV6use} dev {if_name}\n"
            setupsh += f"ip route add {peerV6use}/128 src {myV6useIP} dev {if_name}\n"
    
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
    if "chan4" in birdAddConf:
        channel4 += "\n".join(birdAddConf["chan4"]) + "\n"
    if "chan6" in birdAddConf:
        channel6 += "\n".join(birdAddConf["chan6"]) + "\n"
    if "filter4i" in birdAddConf:
        filter4i += "\n".join(birdAddConf["filter4i"]) + "\n"
    if "filter6i" in birdAddConf:
        filter4e += "\n".join(birdAddConf["filter6i"]) + "\n"
    if "filter4e" in birdAddConf:
        filter6i += "\n".join(birdAddConf["filter4e"]) + "\n"
    if "filter6e" in birdAddConf:
        filter6e += "\n".join(birdAddConf["filter6e"]) + "\n"
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
        if birdPeerV6 != None:
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
        if birdPeerV6 != None:
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
        "paramaters_save": paramaters_save,
        "successdisplay": successdisplay,
    }

def initDevice():
    print_and_exec(f"ip link add dn42-dummy type dummy")
    print_and_exec(f"ip link set up dn42-dummy")
    print_and_exec(f'ip addr add { my_paramaters["myIPV4"] } dev dn42-dummy')
    print_and_exec(f'ip addr add { my_paramaters["myIPV6"] } dev dn42-dummy')
    for thesh in filter(lambda x:x[-3:] == ".sh", sorted(os.listdir(wgconfpath))):
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
            for conf_file in sorted(os.listdir(conf_dir)):
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

def saveConfig(new_config,sync=True):
    if sync:
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
    if sync:
        RRstate_repo.push(f'{node_name} peer add {peerName}')
    if runsh:
        print_and_exec(f"{wgconfpath}/{peerName}.sh")
    print_and_exec("birdc configure")
    return None

def deleteConfig(peerID,peerName,deleteDevice=True,sync=True):
    if sync:
        RRstate_repo.pull()
    print_and_rm(f"{wgconfpath}/{peerName}.conf")
    print_and_rm(f"{wgconfpath}/{peerName}.sh")
    print_and_rm(f"{wgconfpath}/peerinfo/{peerID}.yaml")
    print_and_rm(f"{bdconfpath}/{peerName}.conf")
    if sync:
        RRstate_repo.push(f'{node_name} peer del {peerName}')
    if deleteDevice:
        if_name = "dn42-" + peerName
        print_and_exec(f"ip link del {if_name}")
    print_and_exec("birdc configure")
    return None

def updateConfig(peerID,peerName,new_config,deleteDevice=True,sync=True):
    if sync:
        RRstate_repo.pull()
    deleteConfig(peerID,peerName,deleteDevice=deleteDevice,sync=False)
    saveConfig(new_config,sync=False)
    if sync:
        RRstate_repo.push(f'{node_name} peer update {peerName}')

def get_key_default(Dictn,key,default):
    if key in Dictn and Dictn[key] != "" and Dictn[key] != None:
        ValType = type(default)
        if ValType == bool and type(Dictn[key]) == str:
            return Dictn[key].lower() == "true" or Dictn[key].lower() == "on"
        if (ValType == dict or ValType == list) and type(Dictn[key]) == str:
            return json.loads(type(Dictn[key]))
        elif default != None:
            return ValType(Dictn[key])
        else:
            return Dictn[key]
    return default

def qsd2d(qsd):
    return {k:v[0] for k,v in qsd.items()}

def isFormTrue(inp):
    if inp == "on" or inp == "True" or inp == True:
        return True
    return False

def try_get_param(peerID,key,default=""):
    try:
        peerInfo = yaml.load(open(wgconfpath + "/peerinfo/" + str(peerID) + ".yaml").read(),Loader=yaml.SafeLoader)
    except FileNotFoundError as e:
        return default
    if key in peerInfo:
        return peerInfo[key]
    return default

def get_paramaters(paramaters,default_params=my_paramaters,isAdmin=False):
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
    paramaters["myIPV4"]           = get_key_default(paramaters,"myIPV4",default_params["myIPV4"]) if default_params["myIPV4"] != "" else ""
    paramaters["myIPV6"]           = get_key_default(paramaters,"myIPV6",default_params["myIPV6"]) if default_params["myIPV6"] != "" else ""
    paramaters["myIPV4LL"]         = get_key_default(paramaters,"myIPV4LL",default_params["myIPV4LL"]) if default_params["myIPV4LL"] != "" else ""
    paramaters["myIPV6LL"]         = get_key_default(paramaters,"myIPV6LL",default_params["myIPV6LL"]) if default_params["myIPV6LL"] != "" else ""
    paramaters["myWG_Pri_Key"]     = get_key_default(paramaters,"myWG_Pri_Key",my_config["myWG_Pri_Key"])
    paramaters["myWG_MTU"]         = get_key_default(paramaters,"myWG_MTU",1280)
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
    paramaters["birdAddConf"]      = get_key_default(paramaters,"birdAddConf",{})
    
    paramaters["myWG_Pub_Key"]     = wgpri2pub(paramaters["myWG_Pri_Key"])
    #print(yaml.safe_dump(paramaters))
    paramaters = {**default_params,**paramaters}
    return action , paramaters

def remove_sensitive(paramaters):
    ret = {}
    for k,v in paramaters.items():
        if k in client_valid_keys_admin_only:
            continue
        ret[k] = v
    return ret

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
                paramaters["hasIPV6LL"] = True
                paramaters["MP_BGP"] = True
                paramaters["Ext_Nh"] = False
                paramaters["hasHost"] = True
            else:
                try:
                    peerInfo = yaml.load(open(wgconfpath + "/peerinfo/" + paramaters["PeerID"] + ".yaml").read(),Loader=yaml.SafeLoader)
                    _, peerInfo = get_paramaters(peerInfo,isAdmin=True)
                    paramaters["myWG_Pub_Key"] = peerInfo["myWG_Pub_Key"]
                except Exception as e:
                    pass
            return 200, await get_html(paramaters,action=action,peerSuccess=False)
        if action == "Show":
            if paramaters["PeerID"] == None:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), "")
            try:
                peerInfo = yaml.load(open(wgconfpath + "/peerinfo/" + paramaters["PeerID"] + ".yaml").read(),Loader=yaml.SafeLoader)
            except FileNotFoundError as e:
                e.filename = paramaters["PeerID"] + ".yaml"
                raise e
            peerInfo = { valid_key: peerInfo[valid_key] for valid_key in client_valid_keys if valid_key in peerInfo }
            _, peerInfo = get_paramaters(peerInfo,isAdmin=True)
            if bool(paramaters["peer_plaintext"]):
                del peerInfo["peer_plaintext"]
            if bool(paramaters["peer_pub_key_pgp"]):
                del peerInfo["peer_pub_key_pgp"]
            if bool(paramaters["peer_signature"]):
                del peerInfo["peer_signature"]
            paramaters = {**paramaters,**peerInfo}
            return 200, await get_html(paramaters,action=action,peerSuccess=True)
        # Check ASN is valid for following action
        if paramaters["peerASN"] == None:
            raise ValueError("peerASN can't be null.")
        if paramaters["peerASN"].startswith("AS"):
            check_num = int(paramaters['peerASN'][2:])
        else:
            check_num = int(paramaters['peerASN'])
            paramaters["peerASN"] = "AS" + paramaters["peerASN"]
        #Actions need ASN
        if action=="Delete" or action=="Update":
            mntner = await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_pub_key_pgp"],paramaters["peer_signature"])
            if paramaters["peerHost"] == peerHostDisplayText:
                paramaters["peerHost"] = try_get_param(paramaters["PeerID"],"peerHost","")
            try:
                peerInfo = yaml.load(open(wgconfpath + "/peerinfo/" + paramaters["PeerID"] + ".yaml").read(),Loader=yaml.SafeLoader)
            except FileNotFoundError as e:
                e.filename = paramaters["PeerID"] + ".yaml"
                raise e
            if peerInfo["peerASN"] != paramaters["peerASN"]:
                raise PermissionError("Peer ASN not match")
            if action=="Delete":
                deleteConfig(peerInfo["PeerID"],peerInfo["peerName"],deleteDevice=peerInfo["customDevice"]==None)
                paramaters["PeerID"] = None
                return 200, get_err_page(paramaters,"Profile deleted:" ,yaml.dump(remove_sensitive(peerInfo),sort_keys=False).replace("\n","<br>"),big_title="Success!")
            elif action=="Update":
                del paramaters["myWG_Pri_Key"]
                del paramaters["myWG_Pub_Key"]
                _, peerInfo = get_paramaters(peerInfo,isAdmin=True)
                paramaters_in = { valid_key: paramaters[valid_key] for valid_key in client_valid_keys if (valid_key in paramaters)  }
                for k in client_valid_keys_admin_only:
                    if k in paramaters_in:
                        del paramaters_in[k]
                paramaters = {**peerInfo,**paramaters_in}
                paramaters = await check_reg_paramater(paramaters,skip_check=paramaters["PeerID"])
                new_config = newConfig(paramaters,overwrite=True)
                if mntner == my_config["admin_mnt"]:
                    paramaters["peer_pub_key_pgp"] = ""
                updateConfig(peerInfo["PeerID"],peerInfo["peerName"],new_config,deleteDevice=peerInfo["customDevice"]==None,sync=True)
                return 200, get_err_page(paramaters,"Profile updated:" ,yaml.dump(remove_sensitive(new_config["paramaters_save"]),sort_keys=False).replace("\n","<br>"),big_title="Success!")
        elif action=="Get Signature":
            return 200, await get_signature_html(dn42repo_base,paramaters)
        elif action == "Register":
            mntner = await verify_user_signature(paramaters["peerASN"],paramaters["peer_plaintext"],paramaters["peer_pub_key_pgp"],paramaters["peer_signature"])
            if mntner not in my_config["admin_mnt"]:
                paramaters["PeerID"] = None
                if my_config["registerAdminOnly"]:
                    raise PermissionError("Guest registration is not enabled at this node, please contact admin.")
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
            myInfo = { **new_config["successdisplay"] ,
                "Endpoint Address":myHostDisplay,
                "My WG Public Key":paramaters["myWG_Pub_Key"],
                "My Contact":  paramaters["myContact"]
            }
            return 200, get_err_page(paramaters, f'Your PeerID is: { paramaters["PeerID"] }<br>My info:',yaml.dump(remove_sensitive(myInfo), sort_keys=False),big_title="Peer Success!", tab_title = "Success!",redirect=my_config["register_redirect"])
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

ipv4s = [ipaddress.ip_network("0.0.0.0/0")]
ipv6s = [ipaddress.ip_network("::/0")]

    
def get_ip(r):
    rip = ipaddress.ip_address( r.remote_ip )
    if type(rip) == ipaddress.IPv4Address:
        clist = ipv4s
    else:
        clist = ipv6s
    for c in clist:
        if rip in c and "CF-Connecting-IP" in r.headers:
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
    try:
        ipv4s = [ipaddress.ip_network(n) for n in requests.get("https://www.cloudflare.com/ips-v4", verify=False, timeout=3).text.split("\n")]
        ipv6s = [ipaddress.ip_network(n) for n in requests.get("https://www.cloudflare.com/ips-v6", verify=False, timeout=3).text.split("\n")]
    except Exception as e:
        print(traceback.format_exc())
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
