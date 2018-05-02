#!/bin/bash
export counter_file=$(mktemp "/root/ns-letsencrypt/.counter.XXXXXX")

#Force renewal
/root/ns-letsencrypt/dehydrated/dehydrated -c -f /root/ns-letsencrypt/config.sh -x -k /root/ns-letsencrypt/ns-hook.sh

#Normal usage
#/root/ns-letsencrypt/dehydrated/dehydrated -c -f /root/ns-letsencrypt/config.sh -k /root/ns-letsencrypt/ns-hook.sh
#Cleanup unused certs
/root/ns-letsencrypt/dehydrated/dehydrated -gc -f /root/ns-letsencrypt/config.sh
