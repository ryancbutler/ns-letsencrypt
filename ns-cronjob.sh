#!/bin/bash

#Force renewal
#/root/ns-letsencrypt/letsencrypt.sh/letsencrypt.sh -c -f /root/ns-letsencrypt/config.sh -x -k /root/ns-letsencrypt/ns-hook.sh

#Normal usage
/root/ns-letsencrypt/letsencrypt.sh/letsencrypt.sh -c -f /root/ns-letsencrypt/config.sh -k /root/ns-letsencrypt/ns-hook.sh
#Cleanup unused certs
/root/ns-letsencrypt/letsencrypt.sh/letsencrypt.sh -gc -f /root/ns-letsencrypt/config.sh
