FROM python:latest
WORKDIR /root
RUN pip install ndg-httpsclient pyasn1 requests --upgrade && \
apt-get update && \
apt-get install curl -y --no-install-recommends && \
apt-get clean && \
rm -rf /var/lib/apt/lists/*