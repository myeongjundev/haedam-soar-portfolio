#!/usr/bin/env python3
"""S1·S4 Graylog 이벤트 정의 JSON 점검 (A whiteclover0542).

두 JSON에서 창·실행 주기·묶기·조건식을 직접 읽고, Graylog처럼 execute_every마다
(t - search_within, t] 구간을 묶기 키별로 집계해 경계 입력의 발동 여부를 확인한다.
sweep.py(이벤트마다 연속 창)와 달리 1분 간격 실행을 재현해 첫 발동 지연과 반복 발동 수를 낸다.

오프라인 판정 재생이지 Graylog 실측이 아니다. JSON 형식이 Graylog 6.1에 그대로
들어가는지는 D 반입 때 확인한다.

사용: python check.py   (실패하면 AssertionError)
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
F, S = "login-bruteforce", "login-success"

# 쿼리 문자열은 파싱하지 않고 고정값과 대조한다. 쿼리를 바꾸면 여기 matcher도 같이 고친다.
QUERIES = {
    "s1-login-bruteforce.json": (
        'source:haedam-portal AND rule:"login-bruteforce" AND status:401',
        lambda e: e["source"] == "haedam-portal" and e["rule"] == F and e["status"] == 401),
    "s4-fail-then-success.json": (
        'source:haedam-portal AND ((rule:"login-bruteforce" AND status:401) OR (rule:"login-success" AND status:200))',
        lambda e: e["source"] == "haedam-portal" and ((e["rule"] == F and e["status"] == 401)
                                                     or (e["rule"] == S and e["status"] == 200))),
}


def evaluate(expr, values):
    kind = expr["expr"]
    if kind == "number":
        return expr["value"]
    if kind == "number-ref":
        return values[expr["ref"]]
    left, right = evaluate(expr["left"], values), evaluate(expr["right"], values)
    return {">": left > right, ">=": left >= right, "&&": left and right}[kind]


def series_values(series, events):
    out = {}
    for s in series:
        if s["type"] == "count":
            out[s["id"]] = len(events)
        elif s["type"] == "card":
            out[s["id"]] = len({e[s["field"]] for e in events})
    return out


def run(defn, events):
    """실행 시각마다 발동한 묶기 키 목록 [(t, key), ...]."""
    cfg = defn["config"]
    query, match = QUERIES[defn["_file"]]
    assert cfg["query"] == query, f'{defn["_file"]} 쿼리가 바뀜: matcher도 고칠 것'
    window, every = cfg["search_within_ms"] // 1000, cfg["execute_every_ms"] // 1000
    hits = [e for e in events if match(e)]
    fired = []
    last = max((e["t"] for e in events), default=0) + window
    for t in range(every, last + every, every):
        groups = {}
        for e in hits:
            if t - window < e["t"] <= t:
                groups.setdefault(tuple(e[k] for k in cfg["group_by"]), []).append(e)
        for key, evs in groups.items():
            if evaluate(cfg["conditions"]["expression"], series_values(cfg["series"], evs)):
                fired.append((t, key))
    return fired


def ev(kinds, span_min, start=0, user="zz_a1", ip="203.0.113.11", source="haedam-portal"):
    """(rule, status) 목록을 span_min 분에 고르게 배치. 시각은 1분 실행 경계와 어긋나게 +7초."""
    n = len(kinds)
    step = span_min * 60 / (n - 1) if n > 1 else 0
    return [{"t": start + 7 + round(i * step), "rule": r, "status": st, "username": user, "src_ip": ip,
             "source": source} for i, (r, st) in enumerate(kinds)]


FAIL, OK, LIMITED = (F, 401), (S, 200), (F, 429)

S1_CASES = [  # (이름, 이벤트, 발동 기대)
    ("실패 9/24분", ev([FAIL] * 9, 24), True),
    ("실패 8/24분 (경계 아래)", ev([FAIL] * 8, 24), False),
    ("실패 8 + 429 3 (429 제외)", ev([FAIL] * 8 + [LIMITED] * 3, 24), False),
    ("실패 9/31분 (창 밖)", ev([FAIL] * 9, 31), False),
    ("실패 9 = 출발지 .11 5 + .12 4", ev([FAIL] * 5, 10) + ev([FAIL] * 4, 10, 60, ip="203.0.113.12"), False),
    ("실패 9 = 계정 2개 5 + 4", ev([FAIL] * 5, 10) + ev([FAIL] * 4, 10, 60, user="zz_a2"), False),
    ("다른 source 실패 9 (zz-d-local)", ev([FAIL] * 9, 24, source="zz-d-local"), False),
]

S4_CASES = [
    ("실패 5 + 성공 1/8분", ev([FAIL] * 5 + [OK], 8), True),
    ("실패 4 + 성공 1/8분 (경계 아래)", ev([FAIL] * 4 + [OK], 8), False),
    ("실패만 6", ev([FAIL] * 6, 8), False),
    ("순서 반대: 성공 1 + 실패 5", ev([OK] + [FAIL] * 5, 8), True),
    ("실패 5 (.11) + 성공 1 (.12)", ev([FAIL] * 5, 8) + ev([OK], 0, 500, ip="203.0.113.12"), False),
    ("실패 5 + 성공 1/11분 (창 밖)", ev([FAIL] * 5 + [OK], 11), False),
    ("실패 4 + 429 3 + 성공 1", ev([FAIL] * 4 + [LIMITED] * 3 + [OK], 8), False),
    ("F1 실패 1 + 성공 5 (알려진 오탐)", ev([FAIL] + [OK] * 5, 8), True),
]


def first_true_time(defn, events):
    """연속 창 기준으로 조건이 처음 성립한 이벤트 시각(첫 발동 지연 계산용)."""
    cfg = defn["config"]
    match = QUERIES[defn["_file"]][1]
    window = cfg["search_within_ms"] // 1000
    hits = sorted((e for e in events if match(e)), key=lambda e: e["t"])
    for end in hits:
        evs = [e for e in hits if end["t"] - window < e["t"] <= end["t"]
               and all(e[k] == end[k] for k in cfg["group_by"])]
        if evaluate(cfg["conditions"]["expression"], series_values(cfg["series"], evs)):
            return end["t"]
    return None


def main():
    failures = []
    for name, cases in (("s1-login-bruteforce.json", S1_CASES), ("s4-fail-then-success.json", S4_CASES)):
        defn = json.loads((HERE / name).read_text(encoding="utf-8")) | {"_file": name}
        cfg = defn["config"]
        assert cfg["group_by"] == defn["key_spec"] == ["username", "src_ip"], name
        assert defn["notification_settings"]["grace_period_ms"] == cfg["search_within_ms"], name
        print(f"## {name}  (창 {cfg['search_within_ms'] // 60000}분, 실행 {cfg['execute_every_ms'] // 1000}초)")
        for case, events, expect in cases:
            fired = run(defn, events)
            got = bool(fired)
            note = ""
            if fired:
                lag = fired[0][0] - first_true_time(defn, events)
                note = f" · 첫 발동 지연 {lag}초 · 발동 실행 {len(fired)}회"
            mark = "ok " if got == expect else "FAIL"
            if got != expect:
                failures.append(f"{name}: {case}")
            print(f"- [{mark}] {case}: 기대 {'발동' if expect else '미발동'} / 결과 {'발동' if got else '미발동'}{note}")
        print()
    assert not failures, failures
    print("check ok")


if __name__ == "__main__":
    main()
