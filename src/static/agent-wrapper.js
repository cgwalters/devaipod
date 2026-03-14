// Agent iframe wrapper logic.
//
// This script runs in the top-level wrapper page (not inside the iframe).
// Pod-specific data is passed via a <script id="pod-data" type="application/json">
// tag in the HTML, avoiding any need for template interpolation in JS.
//
// TODO: This wrapper page should be migrated into the SolidJS app
// (opencode-ui/) as a proper component, replacing this raw JS + the
// inline HTML/CSS in web.rs. That would give us type safety, proper
// templating, and access to the existing component library. See
// docs/todo/integration-web.md for context.

(function () {
  "use strict";

  // -- Read pod-specific data from the HTML -----------------------------------
  const dataEl = document.getElementById("pod-data");
  if (!dataEl) {
    console.error("agent-wrapper.js: missing #pod-data element");
    return;
  }
  const podData = JSON.parse(dataEl.textContent);
  const podName = podData.urlName;       // URL-safe short name (for API calls)
  const currentPod = podData.fullName;   // Full pod name with devaipod- prefix (for matching API)

  // -- Done button ------------------------------------------------------------
  const btn = document.getElementById("done-btn");
  let isDone = false;

  async function fetchStatus() {
    try {
      const r = await fetch("/api/devaipod/pods/" + podName + "/completion-status", { credentials: "include" });
      if (r.ok) {
        const d = await r.json();
        isDone = d.status === "done";
        updateBtn();
      }
    } catch (e) {
      btn.textContent = "Status unavailable";
    }
  }

  function updateBtn() {
    if (isDone) {
      btn.textContent = "Marked Done";
      btn.classList.add("done");
      btn.title = "Click to mark as incomplete";
    } else {
      btn.textContent = "Mark as Done";
      btn.classList.remove("done");
      btn.title = "Click to mark this pod as done";
    }
  }

  async function toggleDone() {
    const newStatus = isDone ? "active" : "done";
    const wasDone = isDone;
    btn.textContent = "Updating...";
    try {
      const r = await fetch("/api/devaipod/pods/" + podName + "/completion-status", {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (r.ok) {
        const d = await r.json();
        isDone = d.status === "done";
      } else {
        isDone = wasDone;
      }
    } catch (e) {
      isDone = wasDone;
    }
    updateBtn();
  }

  btn.addEventListener("click", toggleDone);
  fetchStatus();

  // -- Pod switcher -----------------------------------------------------------
  const trigger = document.getElementById("pod-trigger");
  const dropdown = document.getElementById("pod-dropdown");
  const prevBtn = document.getElementById("prev-pod");
  const nextBtn = document.getElementById("next-pod");
  let pods = [];
  let currentIdx = -1;

  async function openDropdown() {
    await fetchPodList();
    dropdown.classList.add("open");
  }

  trigger.addEventListener("click", function (e) {
    e.stopPropagation();
    if (dropdown.classList.contains("open")) {
      dropdown.classList.remove("open");
    } else {
      openDropdown();
    }
  });
  document.addEventListener("click", function () {
    dropdown.classList.remove("open");
  });
  dropdown.addEventListener("click", function (e) {
    e.stopPropagation();
  });

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function navigateToPod(name) {
    var short = name.replace(/^devaipod-/, "");
    window.location.href = "/_devaipod/agent/" + encodeURIComponent(short) + "/";
  }

  prevBtn.addEventListener("click", async function () {
    await fetchPodList();
    if (currentIdx > 0) navigateToPod(pods[currentIdx - 1].name);
  });
  nextBtn.addEventListener("click", async function () {
    await fetchPodList();
    if (currentIdx >= 0 && currentIdx < pods.length - 1) navigateToPod(pods[currentIdx + 1].name);
  });

  function dotClass(pod) {
    if (pod.completion === "done") return "done";
    if (pod.activity === "Working") return "working";
    if (pod.activity === "Idle") return "idle";
    if (pod.status.toLowerCase() === "running") return "running";
    return "stopped";
  }

  function statusLabel(pod) {
    if (pod.completion === "done") return "Done";
    if (pod.activity === "Working") return pod.tool ? "\u2192 " + pod.tool : "Working";
    if (pod.activity === "Idle") return "Idle";
    if (pod.status.toLowerCase() === "running") return "Running";
    return "Stopped";
  }

  function renderDropdown() {
    if (pods.length === 0) {
      dropdown.innerHTML =
        '<div style="padding:12px;text-align:center;font-size:12px;opacity:0.5;font-family:Inter,system-ui,sans-serif;color:#e8e2e2">No pods</div>';
      return;
    }
    var html = "";
    for (var i = 0; i < pods.length; i++) {
      var p = pods[i];
      var short = esc(p.name.replace("devaipod-", ""));
      var isCurrent = p.name === currentPod;
      html +=
        '<button class="pod-item' +
        (isCurrent ? " current" : "") +
        '" data-idx="' +
        i +
        '">' +
        '<span class="dot ' +
        dotClass(p) +
        '"></span>' +
        '<span class="pod-name">' +
        short +
        "</span>" +
        '<span class="pod-status">' +
        esc(statusLabel(p)) +
        "</span>" +
        "</button>";
    }
    dropdown.innerHTML = html;
    dropdown.querySelectorAll(".pod-item").forEach(function (el) {
      el.addEventListener("click", function () {
        var idx = parseInt(el.dataset.idx);
        if (pods[idx] && pods[idx].name !== currentPod) navigateToPod(pods[idx].name);
      });
    });
  }

  function updateArrows() {
    prevBtn.disabled = currentIdx <= 0;
    nextBtn.disabled = currentIdx < 0 || currentIdx >= pods.length - 1;
  }

  async function fetchPodList() {
    try {
      var r = await fetch("/api/devaipod/pods", { credentials: "include" });
      if (!r.ok) return;
      var data = await r.json();
      pods = data
        .filter(function (p) {
          return p.status.toLowerCase() === "running";
        })
        .map(function (p) {
          return {
            name: p.name,
            status: p.status,
            activity: p.agent_status ? p.agent_status.activity : "Unknown",
            tool: p.agent_status ? p.agent_status.current_tool : null,
            completion: p.agent_status ? p.agent_status.completion_status : null,
          };
        });
      currentIdx = pods.findIndex(function (p) {
        return p.name === currentPod;
      });
      renderDropdown();
      updateArrows();
    } catch (e) {
      console.error("fetchPodList failed:", e);
    }
  }

  // Initial fetch + periodic refresh
  fetchPodList();
  setInterval(fetchPodList, 15000);

  // -- Session title ----------------------------------------------------------
  async function fetchTitle() {
    try {
      var r = await fetch("/api/devaipod/pods/" + podName + "/agent-status", { credentials: "include" });
      if (r.ok) {
        var d = await r.json();
        if (d.title) {
          trigger.textContent = d.title;
          document.title = d.title + " - devaipod";
        }
      }
    } catch (e) {
      // Title fetch is best-effort
    }
  }
  fetchTitle();
})();
