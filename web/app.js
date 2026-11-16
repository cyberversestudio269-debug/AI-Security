(function () {
  "use strict";

  const notice = document.getElementById("notice");
  const authPanel = document.getElementById("auth-panel");
  const appPanel = document.getElementById("app-panel");
  const logoutButton = document.getElementById("logout");
  const deleteAccountButton = document.getElementById("delete-account");

  function showNotice(message, isError) {
    notice.textContent = message || "";
    notice.className = "notice" + (message ? (isError ? " error" : " success") : "");
  }

  async function request(path, options) {
    const config = options || {};
    const headers = Object.assign({}, config.headers || {});
    if (config.body) headers["Content-Type"] = "application/json";
    const response = await fetch(path, Object.assign({}, config, {
      headers: headers,
      credentials: "same-origin"
    }));
    if (response.status === 204) return null;
    const contentType = response.headers.get("content-type") || "";
    const data = contentType.indexOf("application/json") >= 0
      ? await response.json()
      : await response.text();
    if (!response.ok) {
      const message = data && data.detail ? data.detail : "Request failed (" + response.status + ").";
      throw new Error(message);
    }
    return data;
  }

  function setSignedIn(signedIn) {
    authPanel.classList.toggle("hidden", signedIn);
    appPanel.classList.toggle("hidden", !signedIn);
    logoutButton.classList.toggle("hidden", !signedIn);
    deleteAccountButton.classList.toggle("hidden", !signedIn);
    if (signedIn) {
      Promise.all([loadTargets(), loadScans()]).catch(function (error) {
        showNotice(error.message, true);
      });
    }
  }

  document.getElementById("auth-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    const mode = event.submitter ? event.submitter.dataset.auth : "login";
    const payload = {
      email: document.getElementById("email").value,
      password: document.getElementById("password").value
    };
    try {
      await request("/api/auth/" + mode, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      document.getElementById("password").value = "";
      setSignedIn(true);
      showNotice("Signed in.", false);
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  logoutButton.addEventListener("click", async function () {
    try {
      await request("/api/auth/logout", { method: "POST" });
    } catch (error) {
      showNotice(error.message, true);
    }
    setSignedIn(false);
  });

  deleteAccountButton.addEventListener("click", async function () {
    const confirmed = window.confirm(
      "Permanently delete your account, targets, scans, and reports? This cannot be undone."
    );
    if (!confirmed) return;
    try {
      await request("/api/me", { method: "DELETE" });
      setSignedIn(false);
      showNotice(
        "Your account and scan records were deleted. Backup copies may remain until their retention period expires.",
        false
      );
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  async function loadTargets() {
    const targets = await request("/api/targets");
    const list = document.getElementById("targets");
    const select = document.getElementById("target-select");
    list.replaceChildren();
    select.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Select a verified target";
    select.appendChild(placeholder);

    targets.forEach(function (target) {
      const card = document.createElement("article");
      card.className = "card";
      const title = document.createElement("h3");
      title.textContent = target.url;
      const status = document.createElement("p");
      status.textContent = target.verified ? "Verified" : "Ownership not verified";
      card.append(title, status);
      if (!target.verified) {
        ["dns", "file"].forEach(function (method) {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "button secondary";
          button.textContent = "Verify with " + method.toUpperCase();
          button.addEventListener("click", function () {
            verifyTarget(target.id, method);
          });
          card.appendChild(button);
        });
      } else {
        const option = document.createElement("option");
        option.value = String(target.id);
        option.textContent = target.url;
        select.appendChild(option);
      }
      list.appendChild(card);
    });
  }

  async function verifyTarget(targetId, method) {
    try {
      await request("/api/targets/" + targetId + "/verify", {
        method: "POST",
        body: JSON.stringify({ method: method })
      });
      await loadTargets();
      showNotice("Target ownership verified.", false);
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  document.getElementById("target-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    const challenge = document.getElementById("challenge");
    try {
      const target = await request("/api/targets", {
        method: "POST",
        body: JSON.stringify({
          url: document.getElementById("target-url").value,
          model: document.getElementById("target-model").value
        })
      });
      challenge.classList.remove("hidden");
      challenge.textContent = [
        "Target added. Add one of these ownership proofs, then click Verify:",
        "",
        "DNS TXT record",
        "Name: " + target.dns_record.name,
        "Value: " + target.dns_record.value,
        "",
        "OR hosted file",
        "Path: " + target.file_path,
        "Contents: " + target.file_contents
      ].join("\n");
      document.getElementById("target-form").reset();
      document.getElementById("target-model").value = "default";
      await loadTargets();
      showNotice("Target added. The verification token is shown above only once.", false);
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  function questionnaire() {
    return {
      uses_personal_data: document.getElementById("uses-personal-data").checked,
      has_human_review: document.getElementById("has-human-review").checked,
      has_role_based_access: document.getElementById("has-role-based-access").checked,
      has_retention_policy: document.getElementById("has-retention-policy").checked,
      discloses_ai_use: document.getElementById("discloses-ai-use").checked
    };
  }

  function scanPayload(demo) {
    return {
      target_id: demo ? null : Number(document.getElementById("target-select").value),
      demo: demo,
      authorized: demo || document.getElementById("authorized").checked,
      target_api_key: demo ? null : (document.getElementById("target-key").value || null),
      company_name: document.getElementById("company-name").value || "Client",
      questionnaire: questionnaire()
    };
  }

  document.getElementById("scan-form").addEventListener("submit", function (event) {
    event.preventDefault();
    startScan(false);
  });

  document.getElementById("demo-scan").addEventListener("click", function () {
    startScan(true);
  });

  async function startScan(demo) {
    const button = document.getElementById(demo ? "demo-scan" : "live-scan");
    button.disabled = true;
    try {
      if (!demo && !document.getElementById("target-select").value) {
        throw new Error("Choose a verified target.");
      }
      const scan = await request("/api/scans", {
        method: "POST",
        body: JSON.stringify(scanPayload(demo))
      });
      document.getElementById("target-key").value = "";
      showNotice("Scan " + scan.id + " queued.", false);
      await loadScans();
      pollScan(scan.id, 0);
    } catch (error) {
      showNotice(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function loadScans() {
    const scans = await request("/api/scans");
    const list = document.getElementById("scan-list");
    list.replaceChildren();
    scans.forEach(function (scan) {
      const card = document.createElement("article");
      card.className = "card";
      const title = document.createElement("h3");
      title.textContent = "Scan " + scan.id + " — " + scan.company_name;
      const state = document.createElement("p");
      state.className = "status";
      state.textContent = scan.status;
      card.append(title, state);
      if (scan.summary) {
        const score = document.createElement("p");
        score.textContent = "Risk score: " + scan.summary.risk_score + "/100 (" + scan.summary.risk_level + ")";
        card.appendChild(score);
      }
      if (scan.status === "completed") {
        const report = document.createElement("button");
        report.type = "button";
        report.className = "button secondary";
        report.textContent = "Download PDF";
        report.addEventListener("click", function () {
          downloadReport(scan.id);
        });
        const details = document.createElement("button");
        details.type = "button";
        details.className = "button secondary";
        details.textContent = "View findings";
        details.addEventListener("click", function () {
          loadScanDetails(scan.id);
        });
        card.append(report, details);
      }
      list.appendChild(card);
    });
  }

  async function pollScan(scanId, attempt) {
    try {
      const scan = await request("/api/scans/" + scanId);
      if (scan.status === "completed") {
        await loadScans();
        await loadScanDetails(scanId);
        showNotice("Scan " + scanId + " completed.", false);
        return;
      }
      if (scan.status === "failed") {
        await loadScans();
        showNotice(scan.error || "Scan failed.", true);
        return;
      }
      if (attempt < 180) {
        window.setTimeout(function () { pollScan(scanId, attempt + 1); }, 1500);
      } else {
        showNotice("Scan is still running. Refresh the scan list shortly.", false);
      }
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  async function loadScanDetails(scanId) {
    try {
      const scan = await request("/api/scans/" + scanId);
      const area = document.getElementById("scan-detail");
      area.replaceChildren();
      if (!scan.result) return;

      const summary = scan.result.summary;
      const metrics = document.createElement("div");
      metrics.className = "result-grid";
      [
        ["Risk score", summary.risk_score + "/100"],
        ["Risk level", summary.risk_level],
        ["Failed", summary.failed],
        ["Needs review", summary.needs_review],
        ["Errors", summary.errors]
      ].forEach(function (pair) {
        const metric = document.createElement("div");
        metric.className = "metric";
        const label = document.createElement("span");
        label.textContent = pair[0];
        const value = document.createElement("strong");
        value.textContent = String(pair[1]);
        metric.append(label, value);
        metrics.appendChild(metric);
      });
      area.appendChild(metrics);

      scan.result.results.forEach(function (finding) {
        const card = document.createElement("article");
        card.className = "card";
        const title = document.createElement("h3");
        title.textContent = finding.result + " — " + finding.id + ": " + finding.name;
        const tags = document.createElement("p");
        tags.textContent = finding.owasp + " | " + finding.atlas + " | " + finding.severity;
        card.append(title, tags);
        if (finding.runs && finding.runs.length) {
          const reply = document.createElement("p");
          reply.textContent = "Example reply: " + finding.runs[0].reply;
          card.appendChild(reply);
        }
        area.appendChild(card);
      });
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  async function downloadReport(scanId) {
    try {
      const response = await fetch("/api/scans/" + scanId + "/report.pdf", {
        credentials: "same-origin"
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || "Could not download report.");
      }
      const blob = await response.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "scan-" + scanId + ".pdf";
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  async function restoreSession() {
    try {
      await request("/api/me");
      setSignedIn(true);
    } catch (error) {
      setSignedIn(false);
    }
  }

  restoreSession();
}());
