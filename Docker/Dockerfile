FROM python:latest
WORKDIR /root
RUN pip install ndg-httpsclient pyasn1 requests --upgrade && \
apt-get update && \
apt-get install curl -y --no-install-recommends && \
apt-get clean && \
cd /root && \
git clone --recursive https://github.com/ryancbutler/ns-letsencrypt && \
rm -rf /var/lib/apt/lists/*