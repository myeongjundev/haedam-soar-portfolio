"""Owned S12 lab only: bounded resource contention, never fabricated health responses."""
import json
import os
from pathlib import Path
from threading import BoundedSemaphore
import time
from flask import g,request
from haedam_portal import create_app as portal_app
from haedam_portal.common import fail,ok

def create_app():
    if os.environ.get('HAEDAM_S12_LAB')!='1':raise RuntimeError('isolated_s12_lab_required')
    from s12_settings import validate
    s=validate(json.loads(Path(os.environ['S12_SETTINGS_FILE']).read_text()))
    control=Path(os.environ['S12_WORKLOAD_FILE']);semaphore=BoundedSemaphore(s['workload']['resource_slots'])
    app=portal_app()
    def armed():
        try:
            value=json.loads(control.read_text());now=time.time()
            return set(value)=={'enabled','armed_at','expires_at'} and value['enabled'] is True and 0<=now-value['armed_at']<=s['workload']['maximum_armed_seconds'] and now<value['expires_at']<=value['armed_at']+s['workload']['maximum_armed_seconds']
        except (OSError,ValueError,TypeError,KeyError):return False
    # Registered after the real portal's IP/auth checks: blocked input never owns a slot.
    @app.before_request
    def lab_resource():
        if request.path.startswith('/api/v1/response/') or not armed():return
        if not semaphore.acquire(timeout=s['request_timeout_seconds']):fail(503,'LAB_RESOURCE_BUSY','Bounded lab resource busy.')
        g.s12_slot=True
    @app.teardown_request
    def release_slot(_error):
        if g.pop('s12_slot',False):semaphore.release()
    @app.get(s['paths']['work'])
    def work():
        if request.remote_addr!=s['addresses']['attacker']:fail(403,'LAB_SCOPE','Owned input client required.')
        if armed():time.sleep(s['workload']['work_ms']/1000)
        return ok({'lab':'S12','workload':'bounded_resource_wait','armed':armed()})
    return app
