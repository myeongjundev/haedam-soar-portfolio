#!/usr/bin/env python3
"""S8·S10 Graylog 이벤트 정의 JSON 점검 (B myeongjundev).

A의 lab/s1s4/graylog/check.py 판정 함수(1분 실행 재현·조건식·첫 발동 지연)를 그대로 불러
S8·S10 쿼리 matcher만 더한다. 두 JSON에서 창·실행 주기·묶기·조건식을 읽어 경계 입력을 판정한다.

오프라인 판정 재생이지 Graylog 실측이 아니다. 쿼리 문법이 Graylog 이벤트 정의에서
실제로 발동하는지는 D 반입 뒤 확인한다(README).

사용: python check.py   (실패하면 AssertionError)
"""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("s1s4_check", HERE.parent.parent / "s1s4" / "graylog" / "check.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

SCAN, FAIL, OK, PF = "web-scan", "login-bruteforce", "login-success", "pfsense-block"


def portal(e):
    return e["source"] == "haedam-portal" and ((e["rule"] == SCAN and e.get("status") == 404)
                                                   or (e["rule"] == FAIL and e.get("status") == 401))


def pf(e):
    return e["rule"] == PF and "pf_noise" not in e and "pf_scope" not in e


# 쿼리 문자열은 파싱하지 않고 고정값과 대조한다. 쿼리를 바꾸면 여기 matcher도 같이 고친다.
base.QUERIES.update({
    "s8-scan-then-login.json": (
        '(source:haedam-portal AND rule:"web-scan" AND status:404) OR (source:haedam-portal AND rule:"login-bruteforce" AND status:401)',
        portal),
    "s10-three-layer.json": (
        '(rule:"pfsense-block" AND NOT _exists_:pf_noise AND NOT _exists_:pf_scope)'
        ' OR (source:haedam-portal AND rule:"web-scan" AND status:404) OR (source:haedam-portal AND rule:"login-bruteforce" AND status:401)',
        lambda e: pf(e) or portal(e)),
})


def ev(rules, span_min, start=0, ip="203.0.113.22", **extra):
    """rule 목록을 span_min 분에 고르게 배치. pfSense 신호는 source가 pfSense. 시각은 실행 경계와 어긋나게 +7초."""
    n = len(rules)
    step = span_min * 60 / (n - 1) if n > 1 else 0
    return [{"t": start + 7 + round(i * step), "rule": r, "src_ip": ip, "status": 404 if r == SCAN else 401 if r == FAIL else 200,
             "source": "pfsense" if r == PF else "haedam-portal", **extra} for i, r in enumerate(rules)]


BEFORE_01 = ev([SCAN, FAIL, PF], 0)  # S10-before-01(10/26): .22의 404·401·ICMP 차단 각 1건, 약 1초 안

S8_CASES = [  # (이름, 이벤트, 발동 기대)
    ("스캔 1 + 실패 1 (S8-before-01 입력)", ev([SCAN, FAIL], 0, ip="203.0.113.21"), True),
    ("스캔 20 + 실패 9 / 14분", ev([SCAN] * 20 + [FAIL] * 9, 14), True),
    ("순서 반대: 실패 5 뒤 스캔 10", ev([FAIL] * 5 + [SCAN] * 10, 10), True),
    ("스캔만 30 (일부만)", ev([SCAN] * 30, 10), False),
    ("실패만 9 (일부만, S1 영역)", ev([FAIL] * 9, 10), False),
    ("스캔 뒤 16분에 실패 (창 밖)", ev([SCAN], 0) + ev([FAIL], 0, 16 * 60), False),
    ("스캔 .22 + 실패 .23 (혼합)", ev([SCAN] * 10, 5) + ev([FAIL] * 5, 5, ip="203.0.113.23"), False),
    ("스캔 + 로그인 성공 (주소 오타 뒤 정상 로그인)", ev([SCAN, OK], 1), False),
    ("다른 source 스캔 + 실패 (zz-d-local)", ev([SCAN, FAIL], 1, source="zz-d-local"), False),
    ("알려진 오탐: 없는 주소 1 + 비밀번호 오타 1", ev([SCAN, FAIL], 3, ip="203.0.113.150"), True),
]

S10_CASES = [
    ("S10-before-01 입력 재생: 스캔·실패·PF 차단 각 1", BEFORE_01, True),
    ("PF 차단 3 + 스캔 10 + 실패 5 / 12분", ev([PF] * 3 + [SCAN] * 10 + [FAIL] * 5, 12), True),
    ("S8 앱 차단 뒤 10분에 PF 차단 (연쇄)", ev([SCAN] * 5 + [FAIL] * 3, 2) + ev([PF], 0, 600), True),
    ("스캔 + 실패만 (S8까지만)", ev([SCAN] * 10 + [FAIL] * 5, 10), False),
    ("PF 차단 + 스캔만", ev([PF] * 3 + [SCAN] * 10, 10), False),
    ("스캔 + 실패 + 로그인 성공 (PF 없음, 3종)", ev([SCAN, FAIL, OK], 5), False),
    ("PF 차단이 마지막 포털 신호 16분 뒤 (창 밖)", ev([SCAN, FAIL], 1) + ev([PF], 0, 17 * 60), False),
    ("PF 차단 .22 + 포털 .23 (혼합)", ev([PF] * 3, 2) + ev([SCAN, FAIL], 2, ip="203.0.113.23"), False),
    ("브로드캐스트 PF 차단 (pf_noise)", ev([PF], 0, pf_noise="broadcast_multicast") + ev([SCAN, FAIL], 2), False),
    ("팀 VPN PF 차단 (pf_scope)",
     ev([PF], 0, ip="192.0.2.2", pf_scope="team-vpn") + ev([SCAN, FAIL], 2, ip="192.0.2.2"), False),
    ("포털 신호가 다른 source (zz-d-local)", ev([PF], 0) + ev([SCAN, FAIL], 2, source="zz-d-local"), False),
]


def main():
    failures = []
    for name, cases, n_streams in (("s8-scan-then-login.json", S8_CASES, 1), ("s10-three-layer.json", S10_CASES, 2)):
        defn = json.loads((HERE / name).read_text(encoding="utf-8")) | {"_file": name}
        cfg = defn["config"]
        assert cfg["group_by"] == defn["key_spec"] == ["src_ip"], name
        assert defn["notification_settings"]["grace_period_ms"] == cfg["search_within_ms"], name
        assert len(cfg["streams"]) == n_streams, name
        print(f"## {name}  (창 {cfg['search_within_ms'] // 60000}분, 실행 {cfg['execute_every_ms'] // 1000}초)")
        for case, events, expect in cases:
            fired = base.run(defn, events)
            got = bool(fired)
            note = ""
            if fired:
                lag = fired[0][0] - base.first_true_time(defn, events)
                note = f" · 첫 발동 지연 {lag}초 · 발동 실행 {len(fired)}회"
            mark = "ok " if got == expect else "FAIL"
            if got != expect:
                failures.append(f"{name}: {case}")
            print(f"- [{mark}] {case}: 기대 {'발동' if expect else '미발동'} / 결과 {'발동' if got else '미발동'}{note}")
        print()
    s8 = json.loads((HERE / "s8-scan-then-login.json").read_text(encoding="utf-8")) | {"_file": "s8-scan-then-login.json"}
    print(f"참고: S10-before-01 입력은 S8도 발동 {bool(base.run(s8, BEFORE_01))} → 같은 실행 주기에 두 정의가 함께 알림을 보낸다")
    assert not failures, failures
    print("check ok")


if __name__ == "__main__":
    main()
