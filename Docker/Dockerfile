FROM python:latest
RUN pip install ndg-httpsclient pyasn1 requests --upgrade && \
apt-get update && \
apt-get install curl -y --no-install-recommends && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* && \
cd /root && \
git clone --recursive https://github.com/ryancbutler/ns-letsencrypt


