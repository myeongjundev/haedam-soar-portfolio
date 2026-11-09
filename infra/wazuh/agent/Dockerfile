FROM ubuntu:22.04 AS agent
ARG DEBIAN_FRONTEND=noninteractive
ARG S7_RESTORE_PROGRAM=/opt/haedam-s7/bin/s7_restore.py
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && WAZUH_MANAGER=wazuh.manager apt-get install -y --no-install-recommends wazuh-agent=4.9.0-1 \
    && rm -rf /var/lib/apt/lists/*
COPY lab/s7/restore/s7_restore.py ${S7_RESTORE_PROGRAM}
COPY lab/s7/restore/s7-restore-ar /var/ossec/active-response/bin/s7-restore-ar
COPY infra/wazuh/agent/ossec.conf /opt/haedam-s7/agent.conf
COPY infra/wazuh/agent/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh "$S7_RESTORE_PROGRAM" \
    && chmod 750 /var/ossec/active-response/bin/s7-restore-ar \
    && chown root:wazuh /var/ossec/active-response/bin/s7-restore-ar
ENV S7_WEB_ROOT=/var/www/haedam S7_STATE_DIR=/opt/haedam-s7/state S7_LOG=/var/log/haedam-s7/s7-restore.log
ENTRYPOINT ["/entrypoint.sh"]

FROM agent AS automatic
ARG S7_AR_COMMAND
COPY infra/wazuh/agent/s7_guard.py /var/ossec/active-response/bin/${S7_AR_COMMAND}
RUN test -n "$S7_AR_COMMAND" \
    && find /var/ossec/active-response/bin -maxdepth 1 -type f ! -name "$S7_AR_COMMAND" -delete \
    && chmod 750 "/var/ossec/active-response/bin/$S7_AR_COMMAND" \
    && chown root:wazuh "/var/ossec/active-response/bin/$S7_AR_COMMAND"
