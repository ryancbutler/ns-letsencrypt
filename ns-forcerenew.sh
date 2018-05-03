#!/bin/bash
export counter_file=$(mktemp "/root/ns-letsencrypt/.counter.XXXXXX")
export connect_file=$(mktemp "/root/ns-letsencrypt/.connect.XXXXXX")
printf '%s\n' "0" >"$connect_file"

#Force renewal
/root/ns-letsencrypt/dehydrated/dehydrated -c -f /root/ns-letsencrypt/config.sh -x -k /root/ns-letsencrypt/ns-hook.sh

#Cleanup unused certs
/root/ns-letsencrypt/dehydrated/dehydrated -gc -f /root/ns-letsencrypt/config.sh
