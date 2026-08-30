"use strict";

const MAX_ALERTS = 50;
const POLL_INTERVAL_MS = 3000;

const apiStatus = document.querySelector("#api-status");
const alertCount = document.querySelector("#alert-count");
const alertState = document.querySelector("#alert-state");
const alertList = document.querySelector("#alert-list");
const replayForm = document.querySelector("#replay-form");
const fixtureSelect = document.querySelector("#fixture-select");
const replayButton = document.querySelector("#run-replay");
const operationStatus = document.querySelector("#operation-status");

let replaying = false;
let pollTimer = null;

function setApiStatus(kind, label) {
  apiStatus.className = `status-badge status-${kind}`;
  apiStatus.lastElementChild.textContent = label;
}

function setOperationStatus(message, kind = "") {
  operationStatus.className = kind ? `operation-status is-${kind}` : "operation-status";
  operationStatus.textContent = message;
}

function humanizeKey(key) {
  return key.replaceAll("_", " ");
}

function formatValue(value) {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => (typeof item === "object" ? JSON.stringify(item) : String(item)))
      .join(", ");
  }
  if (typeof value === "object") {
    return Object.entries(value)
      .map(([key, item]) => `${humanizeKey(key)}: ${formatValue(item)}`)
      .join(" · ");
  }
  return String(value);
}

function appendPrimaryItem(container, label, value) {
  const item = document.createElement("div");
  item.className = "alert-primary-item";

  const itemLabel = document.createElement("span");
  itemLabel.className = "alert-primary-label";
  itemLabel.textContent = label;

  const itemValue = document.createElement("span");
  itemValue.className = "alert-primary-value";
  itemValue.textContent = value;

  item.append(itemLabel, itemValue);
  container.append(item);
}

function contextualTarget(alert) {
  if (alert.threat_class === "DGA") {
    return `query ${alert.evidence.query_name}`;
  }
  if (alert.threat_class === "SYN_FLOOD") {
    return `${alert.evidence.target.ip}:${alert.evidence.target.port}`;
  }
  const samples = alert.evidence.destination_samples;
  if (samples.length === 0) {
    return "No destination sample";
  }
  return samples.map((sample) => `${sample.ip}:${sample.port}`).join(", ");
}

function detectorIdentity(alert) {
  const base = `${alert.detector.name} v${alert.detector.version}`;
  return alert.evidence.model_version ? `${base} · ${alert.evidence.model_version}` : base;
}

function createAlertCard(alert) {
  const card = document.createElement("article");
  card.className = "alert-card";

  const header = document.createElement("header");
  header.className = "alert-card-header";
  const headingGroup = document.createElement("div");
  const titleRow = document.createElement("div");
  titleRow.className = "alert-title-row";

  const title = document.createElement("h3");
  title.className = "threat-class";
  title.textContent = alert.threat_class;

  const severity = document.createElement("span");
  severity.className = "severity-badge";
  severity.dataset.severity = alert.severity;
  severity.textContent = alert.severity;

  const timestamp = document.createElement("p");
  timestamp.className = "timestamp";
  timestamp.textContent = alert.timestamp;

  const confidence = document.createElement("div");
  confidence.className = "confidence";
  confidence.textContent = Number(alert.confidence).toFixed(4);
  const confidenceLabel = document.createElement("small");
  confidenceLabel.textContent = "confidence";
  confidence.append(confidenceLabel);

  titleRow.append(title, severity);
  headingGroup.append(titleRow, timestamp);
  header.append(headingGroup, confidence);

  const primary = document.createElement("div");
  primary.className = "alert-primary-grid";
  appendPrimaryItem(primary, "Source", alert.source.ip);
  appendPrimaryItem(primary, "Target / query", contextualTarget(alert));
  appendPrimaryItem(primary, "Detector / model", detectorIdentity(alert));
  appendPrimaryItem(primary, "Flow ID", alert.flow_id);
  appendPrimaryItem(primary, "Protocol", alert.protocol.toUpperCase());
  appendPrimaryItem(
    primary,
    "Observation window",
    `${alert.window.start} → ${alert.window.end} (${alert.window.configured_seconds}s)`,
  );

  const evidenceSection = document.createElement("section");
  evidenceSection.className = "evidence-section";
  const evidenceTitle = document.createElement("h4");
  evidenceTitle.textContent = "Measured alert evidence";
  const evidenceGrid = document.createElement("div");
  evidenceGrid.className = "evidence-grid";

  for (const [key, value] of Object.entries(alert.evidence)) {
    const evidenceItem = document.createElement("div");
    evidenceItem.className = "evidence-item";
    const label = document.createElement("span");
    label.className = "evidence-label";
    label.textContent = humanizeKey(key);
    const measuredValue = document.createElement("span");
    measuredValue.className = "evidence-value";
    measuredValue.textContent = formatValue(value);
    evidenceItem.append(label, measuredValue);
    evidenceGrid.append(evidenceItem);
  }

  evidenceSection.append(evidenceTitle, evidenceGrid);
  card.append(header, primary, evidenceSection);
  return card;
}

function renderAlerts(payload) {
  const alerts = payload.alerts.slice(0, MAX_ALERTS);
  alertCount.textContent = `${alerts.length} shown · ${payload.stored_count} stored · capacity ${payload.capacity}`;
  alertList.replaceChildren(...alerts.map(createAlertCard));

  if (alerts.length === 0) {
    alertState.hidden = false;
    alertState.className = "alert-state";
    alertState.textContent = "No stored alerts. Run an alert fixture, or confirm a benign fixture produces none.";
    alertList.hidden = true;
    return;
  }

  alertState.hidden = true;
  alertList.hidden = false;
}

function schedulePoll() {
  if (!replaying) {
    pollTimer = window.setTimeout(refreshAlerts, POLL_INTERVAL_MS);
  }
}

async function refreshAlerts() {
  if (replaying) {
    return;
  }
  window.clearTimeout(pollTimer);
  pollTimer = null;

  try {
    const response = await fetch(`/api/alerts?limit=${MAX_ALERTS}`, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error("alerts_unavailable");
    }
    renderAlerts(await response.json());
    setApiStatus("ready", "Local API ready");
  } catch (_error) {
    alertState.hidden = false;
    alertList.hidden = true;
    alertState.className = "alert-state is-failure";
    alertState.textContent = "Could not load local alerts. Confirm the loopback dashboard server is running.";
    setApiStatus("failure", "API unavailable");
  } finally {
    schedulePoll();
  }
}

async function runReplay(event) {
  event.preventDefault();
  if (replaying) {
    return;
  }

  replaying = true;
  window.clearTimeout(pollTimer);
  pollTimer = null;
  fixtureSelect.disabled = true;
  replayButton.disabled = true;
  const fixtureId = fixtureSelect.value;
  setOperationStatus(`Running approved fixture: ${fixtureId}…`);
  setApiStatus("loading", "Replay running");

  try {
    const response = await fetch(`/api/replays/${encodeURIComponent(fixtureId)}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "X-SIH26145-Action": "run-approved-fixture",
      },
    });
    if (!response.ok) {
      throw new Error("replay_failed");
    }
    const result = await response.json();
    setOperationStatus(
      `${result.fixture_id}: ${result.events_processed} events processed, ${result.alerts_emitted} alerts emitted, ${result.stored_count} stored.`,
      "success",
    );
  } catch (_error) {
    setOperationStatus("Replay failed safely. Check the local server terminal and fixture availability.", "failure");
  } finally {
    replaying = false;
    fixtureSelect.disabled = false;
    replayButton.disabled = false;
    await refreshAlerts();
  }
}

replayForm.addEventListener("submit", runReplay);
refreshAlerts();
