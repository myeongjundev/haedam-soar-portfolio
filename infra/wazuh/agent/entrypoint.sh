#!/bin/sh
set -eu
cp /opt/haedam-s7/agent.conf /var/ossec/etc/ossec.conf
cp /run/secrets/authd.pass /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/ossec.conf /var/ossec/etc/authd.pass
chmod 640 /var/ossec/etc/ossec.conf /var/ossec/etc/authd.pass
mkdir -p /opt/haedam-s7/state /var/log/haedam-s7
# Baseline creation is explicit; restarting must never bless a changed file.
/var/ossec/bin/wazuh-control start
trap '/var/ossec/bin/wazuh-control stop; exit 0' TERM INT
while :; do sleep 5 & wait $!; done
