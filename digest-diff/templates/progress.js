(() => {
  "use strict";
  const panel = document.getElementById("scan-status");
  if (!panel) return;
  const message = document.getElementById("status-message");
  const title = panel.querySelector("h2");
  const progress = document.getElementById("scan-progress");
  const retry = document.getElementById("retry-scan");
  const report = document.getElementById("report");
  const params = new URLSearchParams(window.location.search);
  const query = new URLSearchParams({old: params.get("old"), new: params.get("new")});
  const jobsURL = `/jobs?${query}`;
  const fragmentURL = `/diff?${query}&fragment=1`;
  const stages = {
    inventory_old: "Reading packages from the original image…",
    inventory_new: "Reading packages from the updated image…",
    database: "Updating the vulnerability database…",
    vulnerabilities_old: "Checking vulnerabilities in the original image…",
    vulnerabilities_new: "Checking vulnerabilities in the updated image…"
  };
  let packagesShown = false;
  let failures = 0;
  let timer;
  let active = true;

  async function request(url, method = "GET") {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(url, {method, cache: "no-store", signal: controller.signal});
      const body = await response.text();
      return {status: response.status, ok: response.ok, body};
    } finally {
      clearTimeout(timeout);
    }
  }
  function fail(text) {
    active = false;
    title.textContent = "Comparison interrupted";
    message.textContent = text;
    progress.hidden = true;
    retry.hidden = false;
    panel.dataset.failed = "true";
    report.setAttribute("aria-busy", "false");
  }
  async function showReport(complete) {
    const response = await request(fragmentURL);
    if (response.status !== 200 && response.status !== 202) throw new Error("Report unavailable");
    // The final report can expire or disappear during a server restart. Never mark
    // a partial response as complete; the next poll recovers the job instead.
    if (complete && response.status !== 200) return false;
    const html = response.body;
    if (!html.trim()) return false;
    report.innerHTML = html; // Same-origin HTML escaped by Go's html/template.
    packagesShown = true;
    return true;
  }
  async function submit() {
    const response = await request(jobsURL, "POST");
    if (response.status === 503) {
      fail("The scan queue is full. Please retry shortly.");
      return false;
    }
    if (!response.ok) throw new Error("Could not submit comparison");
    return true;
  }
  async function poll() {
    if (!active) return;
    try {
      const response = await request(jobsURL);
      if (response.status === 404) {
        if (!await submit()) return;
      } else {
        if (!response.ok) throw new Error("Could not check progress");
        const job = JSON.parse(response.body);
        if (job.state === "completed") {
          if (await showReport(true)) {
            active = false;
            title.textContent = "Comparison complete";
            message.textContent = "Package and vulnerability results are ready.";
            progress.hidden = true;
            report.setAttribute("aria-busy", "false");
            return;
          }
        } else {
          if (job.packages_ready && !packagesShown) await showReport(false);
          if (job.state === "failed") {
            fail(job.error || "The scan failed. Please retry.");
            return;
          }
          if (job.state === "stale" || job.state === "not_scanned") {
            if (!await submit()) return;
          }
          title.textContent = packagesShown ? "Checking vulnerabilities" : "Comparing images";
          message.textContent = job.state === "queued"
            ? "Queued — waiting for another comparison to finish…"
            : (stages[job.stage] || "Scanning images… The first scan can take a few minutes.");
        }
      }
      failures = 0;
    } catch (_) {
      failures += 1;
      message.textContent = "Connection interrupted. Reconnecting…";
      if (failures >= 3) {
        fail("Could not reach the service. Retry to reconnect.");
        return;
      }
    }
    if (active) timer = setTimeout(poll, 2000 * Math.max(1, failures));
  }
  retry.addEventListener("click", async () => {
    clearTimeout(timer);
    retry.hidden = true;
    progress.hidden = false;
    panel.dataset.failed = "false";
    report.setAttribute("aria-busy", "true");
    title.textContent = "Retrying comparison";
    message.textContent = "Submitting the scan…";
    failures = 0;
    packagesShown = false;
    active = true;
    try {
      if (await submit()) await poll();
    } catch (_) {
      fail("Could not reach the service. Retry to reconnect.");
    }
  });
  window.addEventListener("pagehide", () => { active = false; clearTimeout(timer); });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted && retry.hidden) { active = true; poll(); }
  });
  poll();
})();
