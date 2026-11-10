import ipaddress
import re
from functools import wraps

from flask import g, jsonify, request
from werkzeug.exceptions import HTTPException


def normalize_ip(value):
    address = ipaddress.ip_address(value)
    return str(address.ipv4_mapped or address) if address.version == 6 else str(address)


# Same rule as details.file_key in contracts/portal-event.schema.json: web-root relative, "/" separated,
# no "."/".." or empty segments, no drive prefix, control characters, "?", "#" or "\".
FILE_KEY = re.compile(r"^(?![\s\S]*[\u0000-\u001f\u007f])(?![A-Za-z]:)(?![\s\S]*(?:^|/)\.{1,2}(?:/|$))(?:[^/?#\\]+/)*[^/?#\\]+$")


def file_key(path):
    # S7 joins Wazuh FIM paths on this key, so a file whose key breaks the rule is never served.
    return path if len(path) <= 200 and FILE_KEY.search(path) else None


def client_ip():
    # No proxy sits in front of the portal: only the connection address counts, never X-Forwarded-For.
    # Login limits, events, IP blocking and the response API all read the source from here.
    try:
        return normalize_ip(request.remote_addr or "")
    except ValueError:
        return "0.0.0.0"


class ApiError(HTTPException):
    def __init__(self, status, code, message, fields=None):
        super().__init__(description=message)
        self.code = status
        self.error_code = code
        self.fields = fields or {}


def fail(status, code, message, fields=None):
    raise ApiError(status, code, message, fields)


def ok(data, status=200):
    return jsonify(success=True, data=data), status


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        fail(400, "VALIDATION_ERROR", "JSON 객체를 입력해 주세요.")
    return data


def text(data, key, minimum, maximum, strip=True):
    subjects = {
        "title": "제목은", "content": "민원 내용은", "reply": "처리 결과 답변은",
        "username": "아이디는", "display_name": "표시 이름은", "password": "비밀번호는",
        "current_password": "현재 비밀번호는", "new_password": "새 비밀번호는", "department": "부서는",
    }
    subject = subjects.get(key, "입력값은")
    value = data.get(key)
    if not isinstance(value, str):
        message = f"{subject} 문자로 입력해 주세요."
        fail(400, "VALIDATION_ERROR", message, {key: message})
    value = value.strip() if strip else value
    if not minimum <= len(value) <= maximum:
        message = f"{subject} {minimum}~{maximum}자로 입력해 주세요."
        fail(400, "VALIDATION_ERROR", message, {key: message})
    return value


def require(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if g.user is None:
                fail(401, "AUTH_REQUIRED", "로그인이 필요합니다. 다시 로그인해 주세요.")
            if roles and g.user.role not in roles:
                fail(403, "FORBIDDEN", "이 작업을 수행할 권한이 없습니다.")
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def pagination():
    try:
        page = int(request.args.get("page", 1))
        size = int(request.args.get("page_size", 10))
    except (ValueError, TypeError):
        fail(400, "VALIDATION_ERROR", "페이지 값이 올바르지 않습니다.")
    if page < 1 or not 1 <= size <= 50:
        fail(400, "VALIDATION_ERROR", "페이지 범위를 확인해 주세요.")
    return page, size
