FROM ubuntu:22.04 AS agent
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && WAZUH_MANAGER=wazuh.manager apt-get install -y --no-install-recommends wazuh-agent=4.9.0-1 \
    && rm -rf /var/lib/apt/lists/*
COPY lab/s7/restore/s7_restore.py /opt/haedam-s7/bin/s7_restore.py
COPY lab/s7/restore/s7-restore-ar /var/ossec/active-response/bin/s7-restore-ar
COPY infra/wazuh/agent/ossec.conf /opt/haedam-s7/agent.conf
COPY infra/wazuh/agent/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /opt/haedam-s7/bin/s7_restore.py \
    && chmod 750 /var/ossec/active-response/bin/s7-restore-ar \
    && chown root:wazuh /var/ossec/active-response/bin/s7-restore-ar
ENV S7_WEB_ROOT=/var/www/haedam S7_STATE_DIR=/opt/haedam-s7/state
ENTRYPOINT ["/entrypoint.sh"]

FROM agent AS automatic
COPY infra/wazuh/agent/s7_guard.py /var/ossec/active-response/bin/s7-guarded
RUN find /var/ossec/active-response/bin -maxdepth 1 -type f ! -name s7-guarded -delete \
    && chmod 750 /var/ossec/active-response/bin/s7-guarded \
    && chown root:wazuh /var/ossec/active-response/bin/s7-guarded
