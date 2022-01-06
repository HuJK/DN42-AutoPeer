#!/usr/bin/python3
import os
import yaml
import time
import asyncio
import pathlib
from distutils.dir_util import copy_tree
import DN42AutoPeer

conf_dir = DN42AutoPeer.wgconfpath + "/peerinfo"

bkfdr = os.path.expanduser(f"~/dn42ap_{str(int(time.time()))}")

backup = input(f"This script will clear all old files in {DN42AutoPeer.wgconfpath} and {DN42AutoPeer.bdconfpath}, backup it into {bkfdr} ? (Y/N)")

if backup == "y" or backup == "Y":
    print(bkfdr)
    print(os.path.basename(DN42AutoPeer.wgconfpath))
    print(os.path.basename(DN42AutoPeer.bdconfpath))
    os.mkdir(bkfdr)
    os.mkdir(os.path.join(bkfdr, os.path.basename(DN42AutoPeer.wgconfpath)))
    os.mkdir(os.path.join(bkfdr, os.path.basename(DN42AutoPeer.bdconfpath)))
    
    copy_tree(DN42AutoPeer.wgconfpath, os.path.join(bkfdr, os.path.basename(DN42AutoPeer.wgconfpath)))
    copy_tree(DN42AutoPeer.bdconfpath, os.path.join(bkfdr, os.path.basename(DN42AutoPeer.bdconfpath)))

def saveConfig(new_config):
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
        print("================================")

for f in os.listdir(DN42AutoPeer.bdconfpath):
    if f.endswith(".conf"):
        os.remove(os.path.join(DN42AutoPeer.bdconfpath,f))

for f in os.listdir(DN42AutoPeer.wgconfpath):
    if f.endswith(".conf") or f.endswith(".sh") :
        os.remove(os.path.join(DN42AutoPeer.wgconfpath,f))
        
async def main():    
    for old_conf_file in os.listdir(conf_dir):
        if old_conf_file.endswith(".yaml") and os.path.isfile(f"{conf_dir}/{old_conf_file}"):
            old_conf = yaml.load(open(f"{conf_dir}/{old_conf_file}").read(),Loader=yaml.SafeLoader)
            action , paramaters = DN42AutoPeer.get_paramaters(old_conf,isAdmin=True)
            paramaters = await DN42AutoPeer.check_reg_paramater(paramaters,alliw_exists=True)
            try:
                new_config = DN42AutoPeer.newConfig(paramaters,overwrite=True)
            except Exception as e:
                print(old_conf_file)
                raise e
            saveConfig(new_config)
            
loop = asyncio.get_event_loop()
coroutine = main()
loop.run_until_complete(coroutine)