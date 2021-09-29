#!/bin/bash
. /.denv
if [[ "$VPP" == 1 ]]; then
  echo "vpp enabled, start wg___WG_NAME__"
  if /etc/vpp/checkvpponline.sh ; then
    true
  else
    exec sleep 3
  fi
  export WGGO_RECONF_PATH="__WG_CONF_PATH__"
  export WGGO_RECONF_INTERVAL=600
  /etc/wggo-vpp_template/start.sh
  vppctl delete interface memif memif__PEER_ID__/__PEER_ID__
  vppctl delete memif socket id __PEER_ID__
  exec wireguard-go-vpp -f "__WG_NAME__"
else
  echo "vpp not enabled, wg___WG_NAME__ down"
  sv down wg___WG_NAME__
  exec sleep infinity
fi
