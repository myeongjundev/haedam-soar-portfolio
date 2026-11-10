// Security dashboard: 10-second list refresh, row links, copy buttons, close form (design 6).
(function () {
  "use strict";

  var REFRESH_MS = 10000;
  var CLOSE_MESSAGES = {
    INVALID_TRANSITION: "효과 확인·원복 상태만 닫을 수 있습니다.",
    NOT_FOUND: "티켓이 저장소에 없습니다.",
    FORBIDDEN: "대시보드 화면에서 보낸 요청이 아니라서 거부됐습니다. 페이지를 새로 고친 뒤 다시 시도하세요.",
    VALIDATION_ERROR: "닫는 이유를 1~200자로 적어 주세요."
  };

  function clock() {
    return new Date().toLocaleTimeString("en-GB",{ timeZone: "Asia/Seoul", hour12: false });
  }

  function storage(key, value) {
    try {
      if (value === undefined) return window.localStorage.getItem(key);
      window.localStorage.setItem(key, value);
    } catch (e) { /* private window or blocked storage: keep the default */ }
    return null;
  }

  // List page ---------------------------------------------------------------
  function setupList() {
    var area = document.getElementById("list-area");
    if (!area) return;
    var warning = document.getElementById("refresh-warning");
    warning.setAttribute("role", "alert");
    var failedAt = document.getElementById("failed-at");
    var toggle = document.getElementById("auto-refresh");
    var refreshButton = document.getElementById("refresh-now");
    var timer = null;
    var refreshing = false;

    area.addEventListener("click", function (event) {
      var row = event.target.closest("tr[data-href]");
      if (row && !event.target.closest("a")) window.location.href = row.getAttribute("data-href");
    });

    area.addEventListener("change", function (event) {
      var form = event.target.closest("#filters");
      if (form) form.requestSubmit();
    });

    function fail() {
      // Keep the last list on screen and warn above it (6-3).
      failedAt.textContent = clock();
      warning.hidden = false;
    }

    function refresh(manual) {
      // Do not discard a keyboard user's focused ticket link during polling.
      if (refreshing || (!manual && (document.hidden || area.contains(document.activeElement)))) return;
      refreshing = true;
      refreshButton.disabled = true;
      refreshButton.setAttribute("aria-busy", "true");
      var controller = new AbortController();
      var timeout = window.setTimeout(function () { controller.abort(); }, 8000);
      var query = area.getAttribute("data-query");
      fetch("/_list".replace("/_list", area.getAttribute("data-fragment") || "/_list") + (query ? "?" + query : ""), { cache: "no-store", signal: controller.signal })
        .then(function (response) {
          if (!response.ok) throw new Error("HTTP " + response.status);
          return response.text();
        })
        .then(function (html) {
          area.innerHTML = html;
          warning.hidden = true;
        })
        .catch(fail)
        .finally(function () {
          window.clearTimeout(timeout);
          refreshing = false;
          refreshButton.disabled = false;
          refreshButton.removeAttribute("aria-busy");
        });
    }

    function apply() {
      if (timer) window.clearInterval(timer);
      timer = toggle.checked ? window.setInterval(function () { refresh(false); }, REFRESH_MS) : null;
      storage("dashboard-auto-refresh", toggle.checked ? "on" : "off");
    }

    if (storage("dashboard-auto-refresh") === "off") toggle.checked = false;
    toggle.addEventListener("change", apply);
    refreshButton.addEventListener("click", function () { refresh(true); });
    apply();
  }

  // Detail page -------------------------------------------------------------
  function copyText(text, button) {
    function done(ok) {
      var label = button.textContent;
      button.textContent = ok ? "복사됨" : "복사 실패 — 직접 선택하세요";
      window.setTimeout(function () { button.textContent = label; }, 1500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      return;
    }
    var box = document.createElement("textarea");
    box.value = text;
    document.body.appendChild(box);
    box.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(box);
    done(ok);
  }

  function setupDetail() {
    document.querySelectorAll("button.copy").forEach(function (button) {
      button.addEventListener("click", function () { copyText(button.getAttribute("data-copy"), button); });
    });

    var form = document.getElementById("close-form");
    if (!form) return;
    var message = document.getElementById("close-msg");
    var token = document.querySelector('meta[name="dashboard-token"]').getAttribute("content");

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var button = form.querySelector("button");
      button.disabled = true;
      fetch(form.getAttribute("data-url"), {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Dashboard-Token": token },
        body: JSON.stringify({ note: document.getElementById("close-note").value })
      })
        .then(function (response) { return response.json(); })
        .then(function (body) {
          if (body.ok) {
            message.textContent = "티켓을 닫았습니다.";
            message.hidden = false;
            window.setTimeout(function () { window.location.reload(); }, 800);
            return;
          }
          var code = body.error && body.error.code;
          message.textContent = "닫지 못했습니다: " + (CLOSE_MESSAGES[code] || "") +
            " (" + code + ": " + (body.error && body.error.message) + ")";
          message.hidden = false;
          button.disabled = false;
        })
        .catch(function () {
          message.textContent = "닫지 못했습니다: 저장소에 연결할 수 없습니다.";
          message.hidden = false;
          button.disabled = false;
        });
    });
  }

  setupList();
  setupDetail();
})();
