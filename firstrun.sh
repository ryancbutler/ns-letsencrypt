export counter_file=$(mktemp "$HOME/.counter.XXXXXX")
/root/ns-letsencrypt/dehydrated/dehydrated -c -f /root/ns-letsencrypt/config.sh -x -k /root/ns-letsencrypt/ns-firstrunhook.sh
