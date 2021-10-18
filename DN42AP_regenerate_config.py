#!/usr/bin/python3
import os
import yaml
import time
import pathlib
import DN42AutoPeer
from distutils.dir_util import copy_tree


conf_dir = DN42AutoPeer.wgconfpath + "/peerinfo"

bkfdr = f"/tmp/dn42ap_{str(int(time.time()))}"

backup = input(f"This scripy will overwrite files in {DN42AutoPeer.wgconfpath} and {DN42AutoPeer.bdconfpath}, backup it into {bkfdr} ? (Y/N)")

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


for old_conf_file in os.listdir(conf_dir):
    if old_conf_file.endswith(".yaml") and os.path.isfile(f"{conf_dir}/{old_conf_file}"):
        old_conf = yaml.load(open(f"{conf_dir}/{old_conf_file}").read(),Loader=yaml.SafeLoader)
        paramaters = {}
        action , paramaters = DN42AutoPeer.get_paramaters(paramaters)
        paramaters = {**paramaters,**old_conf} 
        new_config = DN42AutoPeer.newConfig(paramaters,overwrite=True)
        saveConfig(new_config)