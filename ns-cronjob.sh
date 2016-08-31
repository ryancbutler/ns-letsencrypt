#!/bin/bash

#use this line to force renewal. USE WITH CAUTION /root/ns-letsencrypt/letsencrypt.sh/letsencrypt.sh -c -f /root/ns-letsencrypt/config.sh -x -k /root/ns-letsencrypt/ns-hook.sh
/root/ns-letsencrypt/letsencrypt.sh/letsencrypt.sh -c -f /root/ns-letsencrypt/config.sh -k /root/ns-letsencrypt/ns-hook.sh
/root/ns-letsencrypt/letsencrypt.sh/letsencrypt.sh -gc -f /root/ns-letsencrypt/config.sh
