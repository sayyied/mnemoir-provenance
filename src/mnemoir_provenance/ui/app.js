(() => {
  "use strict";
  const routes = {
    home: ["ATTENTION BRIEF / 01", "What needs judgment now", "Exceptional conditions lead. Routine posture stays quiet."],
    recall: ["RECALL DOSSIER / 02", "A supported answer, with its record", "Evidence and attribution form one reading sequence. Coverage remains context."],
    memory: ["CURATION RECORD / 03", "Memory under review", "Sourced proposals, immutable versions, consequential decisions, and receipts."],
    council: ["COORDINATION RECORD / 04", "Council and bounded autonomy", "Objectives, evidence, policy decisions, lifecycle state, and receipts."],
    system: ["SYSTEM POSTURE / 05", "Local authority and source health", "Exceptions first; routine implementation detail remains available on demand."]
  };
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const content = $("#content"), state = $("#state"), announcer = $("#announcer");
  const drawer = $("#drawer"), drawerContent = $("#drawer-content"), confirmDialog = $("#confirm-dialog");
  let token = "", currentRoute = "home", pendingConfirmation = null, returnFocus = null, lastRecallQuery = "Council memory";

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key === "open" && value) node.open = true;
      else if (key.startsWith("data-")) node.setAttribute(key, value);
      else if (value !== false && value !== null && value !== undefined) node.setAttribute(key, value === true ? "" : value);
    });
    children.flat().filter((child) => child !== null && child !== undefined).forEach((child) => node.append(child.nodeType ? child : document.createTextNode(String(child))));
    return node;
  }
  function display(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "boolean") return value ? "Yes" : "No";
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  }
  const exceptional = new Set(["error", "failed", "unavailable", "unauthorized", "missing", "degraded", "blocked", "attention", "pending", "paused", "approval_required", "proposed", "edited", "rejected", "veto"]);
  function statusLabel(value, force = "") {
    const status = String(value || "unavailable").toLowerCase().replaceAll(" ", "_");
    const className = force || (exceptional.has(status) ? "exceptional" : "quiet");
    return el("span", { class: `status ${status} ${className}`, text: status.replaceAll("_", " ") });
  }
  function formatTime(value) {
    if (!value) return "Observation time unavailable";
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC";
  }
  function freshness(result) {
    if (typeof result.freshness_seconds === "number") {
      if (result.freshness_seconds < 3600) return "fresh within the hour";
      return `freshness window ${Math.round(result.freshness_seconds / 3600)}h`;
    }
    return result.source_health === "healthy" ? "source healthy at query time" : `source ${display(result.source_health)}`;
  }
  function routeButton(label, route, primary = false) {
    const button = el("button", { type: "button", class: primary ? "primary-action" : "", text: label });
    button.addEventListener("click", () => { location.hash = route; });
    return button;
  }
  function actionButton(label, action, payload, confirmation = false) {
    const button = el("button", { type: "button", text: label, "data-ui-action": action });
    button.addEventListener("click", () => confirmation ? confirmAction(action, { ...payload }, button) : mutate(action, { ...payload }, button));
    return button;
  }
  function detailButton(label, kind, id) {
    const button = el("button", { type: "button", text: label });
    button.addEventListener("click", () => openDetail(kind, id, button));
    return button;
  }
  function identifierNode(value) {
    const code = el("code", { class: "identifier" }), parts = String(value || "record").split("_");
    parts.forEach((part, index) => {
      if (index < parts.length - 1) {
        code.append(document.createTextNode(`${part}_`), el("wbr"));
        return;
      }
      (part.match(/.{1,8}/g) || [part]).forEach((chunk, chunkIndex, chunks) => {
        code.append(document.createTextNode(chunk));
        if (chunkIndex < chunks.length - 1) code.append(el("wbr"));
      });
    });
    return code;
  }
  function pointerNode(value) {
    const code = el("code", { class: "pointer-token" });
    String(value || "unavailable").split(/(:\/\/|[\/#?_&=])/).filter(Boolean).forEach((part) => {
      if (/^(:\/\/|[\/#?_&=])$/.test(part)) code.append(document.createTextNode(part), el("wbr"));
      else code.append(el("span", { class: "pointer-segment", text: part }));
    });
    return code;
  }
  function emptyState(title, copy, action = null) {
    const block = el("div", { class: "empty" }, el("strong", { text: title }), document.createTextNode(copy));
    if (action) block.append(el("div", { class: "actions" }, action));
    return block;
  }

  function recordTable(rows) {
    if (!Array.isArray(rows) || !rows.length) return emptyState("No records", "No canonical records are present in this section.");
    const keys = [...new Set(rows.flatMap((row) => row && typeof row === "object" ? Object.keys(row) : []))].slice(0, 8);
    if (!keys.length) return emptyState("No structured records", "The canonical response contained no displayable fields.");
    const table = el("table", { class: "data-table" }), head = el("tr");
    keys.forEach((key) => head.append(el("th", { scope: "col", text: key.replaceAll("_", " ") })));
    table.append(el("thead", {}, head));
    const body = el("tbody");
    rows.forEach((row) => {
      const tr = el("tr");
      keys.forEach((key) => {
        const td = el("td", { "data-label": key.replaceAll("_", " ") }), value = row[key];
        if (["status", "health", "outcome", "decision", "state"].includes(key)) td.append(statusLabel(value));
        else td.append(typeof value === "object" ? el("code", { text: display(value) }) : document.createTextNode(display(value)));
        tr.append(td);
      });
      body.append(tr);
    });
    table.append(body);
    return el("div", { class: "table-wrap" }, table);
  }
  function objectView(object) {
    if (Array.isArray(object)) return recordTable(object);
    if (!object || typeof object !== "object") return el("p", { text: display(object) });
    const dl = el("dl", { class: "kv" });
    Object.entries(object).forEach(([key, value]) => {
      dl.append(el("dt", { text: key.replaceAll("_", " ") }));
      const dd = el("dd");
      if (["status", "health", "outcome", "decision", "service_state", "state"].includes(key)) dd.append(statusLabel(value));
      else if (typeof value === "object") dd.append(el("code", { text: display(value) }));
      else dd.textContent = display(value);
      dl.append(dd);
    });
    return dl;
  }
  function section(title, value, statusValue, depth = 0) {
    const block = el("section", { class: "section-block" }), heading = el("div", { class: "section-head" }, el("h3", { text: title }));
    if (statusValue) heading.append(statusLabel(statusValue));
    block.append(heading);
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const scalars = {}, nested = [];
      Object.entries(value).forEach(([key, item]) => item && typeof item === "object" ? nested.push([key, item]) : scalars[key] = item);
      if (Object.keys(scalars).length) block.append(objectView(scalars));
      nested.forEach(([key, item]) => {
        const disclosure = el("details", { class: "nested-detail", open: depth === 0 && statusRank(item && item.status) < 2 && !window.matchMedia("(max-width: 560px)").matches },
          el("summary", {}, statusLabel(item && item.status || "available", "quiet"), el("strong", { text: key.replaceAll("_", " ") })),
          section(`${key.replaceAll("_", " ")} record`, item, item && item.status, depth + 1)
        );
        block.append(disclosure);
      });
    } else block.append(objectView(value));
    return block;
  }

  function attentionFromHome(data) {
    const explicit = data.attention || [];
    if (explicit.length) return explicit.map((item) => ({ ...item, status: item.status || item.outcome || "attention", title: item.title || item.kind?.replaceAll("_", " ") || "Attention required", reason: item.reason || "Canonical detail requires operator judgment." }));
    const sources = data.views?.sources?.sources || [];
    const adverse = sources.find((source) => !["ok", "healthy"].includes(String(source.health).toLowerCase()));
    if (adverse) return [{ kind: "source", id: adverse.source_id, status: adverse.health, title: adverse.display_name || "Source coverage needs inspection", reason: adverse.failure_reason || "This source is not currently eligible for routine recall." }];
    const service = data.service || {};
    const serviceState = String(service.service_state || "unknown").toLowerCase(), serviceStatus = String(service.status || "unknown").toLowerCase();
    if (["error", "blocked"].includes(serviceState) || ["error", "unavailable", "unauthorized"].includes(serviceStatus)) return [{ kind: "service", status: service.status || service.service_state, title: "Local runtime needs inspection", reason: `Managed runtime is ${service.service_state || service.status || "unavailable"}.` }];
    return [];
  }
  function attentionAction(item, primary = false) {
    if (item.kind === "memory_proposal") return detailButton("Review proposal", "proposal", item.id);
    if (item.kind === "autonomy_tick") return detailButton("Read autonomy receipt", "tick", item.id);
    if (item.objective_id) return detailButton("Inspect objective", "objective", item.objective_id);
    return routeButton(item.kind === "service" ? "Inspect runtime posture" : "Inspect source coverage", "system", primary);
  }
  function renderHome(data) {
    const attention = attentionFromHome(data), lead = attention[0];
    const spread = el("div", { class: "attention-brief", "data-home-state": attention.length ? "attention" : "healthy", "data-attention-count": String(attention.length) }, el("aside", { class: "margin-label", text: `${data.attention_count || attention.length} decision-bearing item${(data.attention_count || attention.length) === 1 ? "" : "s"}\nSeverity derived from canonical child surfaces` }));
    const primary = el("section");
    if (lead) {
      primary.append(el("article", { class: "attention-lead" }, statusLabel(lead.status), el("h2", { text: lead.title }), el("p", { text: lead.reason }), attentionAction(lead, true)));
    } else primary.append(el("article", { class: "attention-lead" }, statusLabel("healthy"), el("h2", { text: "No judgment is waiting" }), el("p", { text: "Canonical attention queues contain no actionable records. Routine posture is summarized at right." })));
    const queue = el("div", { class: "attention-queue" });
    attention.slice(1).forEach((item) => queue.append(el("article", { class: "attention-item" }, statusLabel(item.status), el("div", {}, el("h3", { text: item.title }), el("p", { text: item.reason })), el("div", { class: "actions" }, attentionAction(item)))));
    const proposals = data.views?.proposals || {};
    if ((proposals.approval_needed_count || 0) > 0 && !attention.some((item) => item.kind === "memory_proposal")) queue.append(el("article", { class: "attention-item" }, statusLabel("pending"), el("div", {}, el("h3", { text: `${proposals.approval_needed_count} sourced proposal${proposals.approval_needed_count === 1 ? "" : "s"} await review` }), el("p", { text: "Review attached evidence before approving or rejecting memory promotion." })), el("div", { class: "actions" }, routeButton("Open Memory", "memory"))));
    const autonomy = data.views?.autonomy || {};
    if ((autonomy.receipt_count || 0) > 0) queue.append(el("article", { class: "attention-item" }, statusLabel("completed", "quiet"), el("div", {}, el("h3", { text: "Bounded work left a receipt" }), el("p", { text: `${autonomy.receipt_count} autonomy receipt${autonomy.receipt_count === 1 ? " is" : "s are"} available for inspection.` })), el("div", { class: "actions" }, routeButton("Read receipts", "council"))));
    primary.append(queue); spread.append(primary);
    const sourceView = data.views?.sources || {}, service = data.service || {};
    spread.append(el("aside", { class: "routine-posture" }, el("h2", { text: "Routine posture" }), el("p", { text: `${sourceView.source_count || 0} registered sources · ${sourceView.degraded_count || 0} degraded` }), el("ul", {}, el("li", { text: `Writeback ${data.views?.hermes?.writeback_allowed ? "available under authority" : "locked by default"}` }), el("li", { text: `Local runtime ${service.service_state || "unavailable"}` }), el("li", { text: "Canonical SQLite remains the authority" }))));
    content.append(spread);
  }

  function renderCitation(result, index) {
    const eligibility = result.eligibility || {}, provenance = result.provenance_trail || [];
    return el("article", { class: "citation", "data-citation-rank": String(result.rank || index + 1) },
      el("div", { class: "citation-index", text: `Citation ${String(result.rank || index + 1).padStart(2, "0")}` }),
      el("h2", { text: "Evidence remains the authority boundary" }),
      el("p", { class: "quote", text: `“${result.snippet || "Citation excerpt unavailable."}”` }),
      el("div", { class: "citation-meta" },
        el("div", {}, el("strong", { text: result.source_label || result.source_id || "Unknown source" }), el("br"), document.createTextNode(result.source_id || "unknown source ID")),
        el("div", {}, document.createTextNode(formatTime(result.occurred_at)), el("br"), document.createTextNode(`${freshness(result)} · ${result.authority_level || "unclassified"} authority`)),
        el("div", { class: "pointer" }, el("strong", { text: "Pointer" }), el("br"), pointerNode(result.source_pointer)),
        el("div", {}, el("strong", { text: "Eligibility and provenance" }), el("br"), document.createTextNode(`${Object.entries(eligibility).map(([key, value]) => `${key}: ${value}`).join(" · ") || "eligibility not emitted"}${provenance.length ? ` · ${provenance.join(" → ")}` : ""}`))
      )
    );
  }
  function renderRecall(payload) {
    const root = payload.data || {}, recall = root.recall || root, coverage = recall.source_coverage || {}, results = recall.cited_results || [];
    const coverageState = String(coverage.coverage_status || recall.status || "unknown").toLowerCase();
    const missingCoverage = coverage.missing_or_degraded_sources || [];
    const healthyCoverage = missingCoverage.length === 0 && !["error", "failed", "unavailable", "degraded", "missing", "unknown"].includes(coverageState);
    $("#route-title").textContent = results.length ? "A supported answer, with its record" : (healthyCoverage ? "No supported match" : "No supported answer");
    $("#route-description").textContent = results.length ? "Evidence and attribution form one reading sequence. Coverage remains context." : (healthyCoverage ? "Eligible sources were searched without weakening evidence requirements." : "Recall abstained because required source coverage is degraded or unavailable; recovery remains adjacent.");
    const layout = el("div", { class: "recall-layout", "data-recall-state": results.length ? "populated" : healthyCoverage ? "empty" : "degraded", "data-result-count": String(results.length) });
    layout.append(el("aside", { class: "margin-label", text: results.length ? `Cited recall\n${results.length} evidence record${results.length === 1 ? "" : "s"}` : `${healthyCoverage ? "No eligible match" : "Recall abstained"}\n0 evidence records` }));
    const primary = el("section", { class: "recall-primary" });
    if (results.length) {
      primary.append(el("p", { class: "answer", text: `The query returned ${results.length} eligible source-grounded record${results.length === 1 ? "" : "s"}. No uncited synthesis has been added; inspect the evidence and attribution below.` }));
      results.forEach((result, index) => primary.append(renderCitation(result, index)));
    } else if (healthyCoverage) {
      primary.append(emptyState("No supported match", "Eligible sources were searched, but none supported this query. Refine the question without weakening source requirements.", el("button", { type: "button", text: "Edit query above" })));
      $("button", primary).addEventListener("click", () => $("#recall-query").focus());
    } else {
      const missing = coverage.missing_or_degraded_sources || [];
      primary.append(el("section", { class: "abstention", role: "status" },
        statusLabel(coverage.coverage_status || recall.status),
        el("h2", { text: "No claim without support" }),
        el("p", { text: "Recall withheld an answer because required source coverage is degraded or unavailable. Query intent is preserved for a safe retry." }),
        el("ol", { class: "causal-chain" },
          el("li", { text: missing.length ? `${missing.length} required source${missing.length === 1 ? " is" : "s are"} degraded or unavailable.` : "Required source eligibility could not be established." }),
          el("li", { text: "Unsupported evidence was excluded from result ranking." }),
          el("li", { text: "The interface abstained rather than inventing an uncited answer." })
        ),
        el("div", { class: "actions" },
          routeButton("Inspect source coverage", "system", true),
          el("button", { type: "button", text: "Retry this query", "data-retry-recall": "true" })
        )
      ));
      $("[data-retry-recall]", primary).addEventListener("click", () => load("recall", lastRecallQuery));
    }
    layout.append(primary);
    layout.append(el("aside", { class: "marginalia" }, el("section", {}, el("h2", { text: "Coverage decision" }), el("p", { text: `${coverage.searched_source_ids?.length || 0} sources searched · ${coverage.missing_or_degraded_sources?.length || 0} degraded or missing · ${coverage.coverage_status || recall.status || "unavailable"}` })), el("section", {}, el("h2", { text: "Control scope" }), el("p", { text: "Run cited recall searches this question. Refresh this view reloads canonical Recall. Source recovery lives in System." }))));
    content.append(layout);
  }

  function recordRow(record, type, actions = []) {
    const statusValue = record.status || record.outcome || record.decision || "available";
    const id = record.proposal_id || record.memory_id || record.tick_id || record.objective_id || record.audit_id || record.operation_id || record.job_id || record.id || "record";
    let title = record.title || record.objective || record.summary || record.event_type || record.kind || id;
    let copy = record.summary || record.reason || record.body || `${type} · ${id}`;
    if (type === "autonomy tick") { title = "Bounded local autonomy tick"; copy = "Objective-bound work completed under policy; inspect its receipt for canonical detail."; }
    const className = statusValue === "completed" || statusValue === "written" ? "record receipt-record" : "record lifecycle-record";
    return el("article", { class: className }, statusLabel(statusValue), el("div", {}, el("h4", { text: title }), el("p", { text: copy }), el("div", { class: "record-meta" }, identifierNode(id))), actions.length ? el("div", { class: "actions" }, ...actions) : null);
  }
  function semanticRecord(record, kind) {
    const statusValue = record.status || record.outcome || record.decision || "available";
    const id = record.audit_id || record.job_id || record.decision_id || record.packet_id || record.assignment_id || record.handoff_id || record.review_id || record.record_id || record.id || "record";
    let title = record.title || record.event_type || record.kind || kind.replaceAll("_", " ");
    let copy = record.summary || record.reason || record.body || "Canonical detail is retained below.";
    if (kind === "policy") { title = `${record.action || "policy action"} → ${record.decision || "undecided"}`; copy = `${record.target_type || "target"} · ${record.target_id || "unbound"} · ${record.reason || "no reason emitted"}`; }
    if (kind === "job") { title = record.kind || "Bounded local job"; copy = `${record.created_at || "time unavailable"}${record.finished_at ? ` → ${record.finished_at}` : ""}`; }
    if (kind === "lifecycle") { title = record.event_type || "Lifecycle receipt"; copy = `${record.target_type || "record"} · ${record.target_id || "unbound"} · ${record.occurred_at || "time unavailable"}`; }
    return el("article", { class: `semantic-record semantic-${kind}` }, statusLabel(statusValue, ["ok", "healthy", "available"].includes(String(statusValue).toLowerCase()) ? "quiet" : ""), el("div", {}, el("h4", { text: title }), el("p", { text: copy }), identifierNode(id)));
  }
  function semanticBlock(title, rows, kind, emptyCopy = "No canonical records are present in this section.") {
    const block = el("section", { class: `section-block semantic-block semantic-block-${kind}` }, el("h3", { text: title })), list = el("div", { class: "semantic-list" });
    (rows || []).forEach((row) => list.append(semanticRecord(row, kind)));
    if (!(rows || []).length) list.append(emptyState("No records", emptyCopy));
    block.append(list); return block;
  }
  function renderMemory(payload) {
    const data = payload.data || {}, proposals = data.proposals || [], memories = data.memories || [];
    const proposalBlock = el("section", { class: "section-block" }, el("div", { class: "section-head" }, el("div", {}, el("h3", { text: `Proposals under review (${proposals.length})` }), el("p", { class: "section-note", text: "Evidence association and current lifecycle state remain first-order." }))));
    const proposalList = el("div", { class: "record-list" });
    proposals.forEach((proposal) => {
      const actions = [detailButton("Inspect / edit", "proposal", proposal.proposal_id)];
      if (["proposed", "edited"].includes(proposal.status)) actions.push(actionButton("Approve", "proposal.approve", { proposal_id: proposal.proposal_id, reviewer_actor_id: "actor_operator_compat02", expected_status: proposal.status }), actionButton("Reject", "proposal.reject", { proposal_id: proposal.proposal_id, reviewer_actor_id: "actor_operator_compat02", expected_status: proposal.status }));
      if (proposal.status === "approved") actions.push(actionButton("Write approved memory…", "memory.write", { proposal_id: proposal.proposal_id, expected_status: proposal.status }, true));
      proposalList.append(recordRow(proposal, "proposal", actions));
    });
    if (!proposals.length) proposalList.append(emptyState("No proposal awaits review", "Create a sourced proposal above or inspect promoted memories below."));
    proposalBlock.append(proposalList); content.append(proposalBlock);
    const memoryBlock = el("section", { class: "section-block" }, el("div", { class: "section-head" }, el("h3", { text: `Promoted memories (${memories.length})` })));
    const list = el("div", { class: "record-list" });
    memories.forEach((memory) => list.append(recordRow(memory, "memory", [detailButton("Versions & evidence", "memory", memory.memory_id)])));
    if (!memories.length) list.append(emptyState("No promoted memory", "Canonical storage contains no promoted memory record."));
    memoryBlock.append(list); content.append(memoryBlock);
    content.append(semanticBlock("Recent lifecycle receipts", data.audit_events || [], "lifecycle", "No lifecycle receipt has been emitted."));
  }
  function renderCouncil(payload) {
    const data = payload.data || {}, council = data.council || {}, autonomy = data.autonomy || {};
    const objectiveBlock = el("section", { class: "section-block" }, el("div", { class: "section-head" }, el("h3", { text: "Objectives and handoffs" })));
    const list = el("div", { class: "record-list" });
    (council.queues?.objectives || []).forEach((record) => list.append(recordRow(record, "objective", [detailButton("Open lifecycle", "objective", record.objective_id)])));
    if (!(council.queues?.objectives || []).length) list.append(emptyState("No active objective", "No Council objective is present in the canonical queue."));
    objectiveBlock.append(list); content.append(objectiveBlock);
    const tickBlock = el("section", { class: "section-block" }, el("div", { class: "section-head" }, el("h3", { text: `Bounded autonomy (${autonomy.tick_count || 0})` }), statusLabel(autonomy.status)));
    const ticks = el("div", { class: "record-list" });
    (autonomy.ticks || []).forEach((tick) => {
      const actions = [detailButton("Read receipt", "tick", tick.tick_id)];
      if (tick.status === "planned") actions.push(actionButton("Run", "autonomy.run", { tick_id: tick.tick_id, expected_status: tick.status }), actionButton("Pause…", "autonomy.pause", { tick_id: tick.tick_id, expected_status: tick.status }, true), actionButton("Kill…", "autonomy.kill", { tick_id: tick.tick_id, expected_status: tick.status }, true));
      if (tick.status === "paused") actions.push(actionButton("Resume", "autonomy.resume", { tick_id: tick.tick_id, expected_status: tick.status }), actionButton("Kill…", "autonomy.kill", { tick_id: tick.tick_id, expected_status: tick.status }, true));
      ticks.append(recordRow(tick, "autonomy tick", actions));
    });
    if (!(autonomy.ticks || []).length) ticks.append(emptyState("No bounded work is queued", "Autonomy has no planned, paused, or completed tick in this fixture."));
    tickBlock.append(ticks); content.append(tickBlock);
    const queueKinds = { assignments: "assignment", handoffs: "handoff", records: "council-record", reviews: "review" };
    Object.entries(council.queues || {}).filter(([name]) => name !== "objectives").forEach(([name, rows]) => content.append(semanticBlock(name.replaceAll("_", " "), rows, queueKinds[name] || "council-record")));
    content.append(semanticBlock("Autonomy jobs", autonomy.jobs || [], "job"), semanticBlock("Policy decisions", autonomy.policy_decisions || [], "policy"), semanticBlock("Evidence packets", council.evidence_packets || [], "evidence"));
  }
  function statusRank(statusValue) {
    const status = String(statusValue || "unavailable").toLowerCase();
    if (["error", "failed", "unavailable", "unauthorized", "missing"].includes(status)) return 0;
    if (["degraded", "unknown", "blocked", "attention", "stopped"].includes(status)) return 1;
    return 2;
  }
  function renderSystem(payload) {
    const data = payload.data || {};
    const entries = Object.entries(data).filter(([key, value]) => value && typeof value === "object" && !Array.isArray(value) && key !== "writeback_operations").sort((a, b) => statusRank(a[1].status || a[1].service_state) - statusRank(b[1].status || b[1].service_state));
    const summary = el("section", { class: "section-block" }, el("div", { class: "section-head" }, el("div", {}, el("h3", { text: "Decision-bearing posture" }), el("p", { class: "section-note", text: "Unavailable and degraded authority surfaces are listed before routine implementation detail." })), statusLabel(data.status)));
    const rows = el("div", { class: "surface-list" });
    entries.forEach(([key, value]) => {
      const counts = Object.entries(value).filter(([name, item]) => name.endsWith("_count") && typeof item === "number").slice(0, 3);
      const itemStatus = value.status || value.service_state;
      let note = counts.length ? counts.map(([name, item]) => `${name.replaceAll("_", " ")}: ${item}`).join(" · ") : "Canonical detail available below.";
      if (key === "service") note = `state ${value.service_state || "unknown"} · ${value.managed_runtime || "local runtime"}`;
      if (key === "projection") note = statusRank(itemStatus) < 2 ? "The non-canonical projection is unavailable. Canonical memory remains authoritative; review projection setup and regenerate the read-only view." : (value.projection_configured ? "Projection is configured, non-canonical, and read-only." : "Projection is not configured; canonical memory remains authoritative.");
      let recovery = null;
      if (statusRank(itemStatus) < 2) {
        recovery = el("button", { type: "button", text: key === "projection" ? "Review projection recovery" : `Inspect ${key.replaceAll("_", " ")} recovery` });
        recovery.addEventListener("click", () => { const detail = $(`details[data-system-key='${key}']`); if (detail) { detail.open = true; detail.scrollIntoView({ block: "start" }); detail.querySelector("summary")?.focus(); } });
      }
      rows.append(el("article", { class: "surface-row" }, statusLabel(itemStatus), el("div", {}, el("h4", { text: key.replaceAll("_", " ") }), el("p", { text: note }), recovery)));
    });
    summary.append(rows); content.append(summary);
    const details = el("section", { class: "system-details" }, el("div", { class: "section-head section-block" }, el("h3", { text: "Canonical detail" }), el("span", { class: "hint", text: "Exceptions are expanded first" })));
    const compact = window.matchMedia("(max-width: 560px)").matches;
    entries.forEach(([key, value], index) => details.append(el("details", { "data-system-key": key, open: statusRank(value.status || value.service_state) < 2 && (!compact || index === 0) }, el("summary", { tabindex: "-1" }, statusLabel(value.status || value.service_state), el("strong", { text: key.replaceAll("_", " ") })), section(`${key.replaceAll("_", " ")} record`, value, value.status || value.service_state))));
    if ((data.writeback_operations || []).length) details.append(section("Writeback receipts", data.writeback_operations));
    content.append(details);
  }

  function render(payload) {
    content.replaceChildren();
    if (currentRoute === "home") renderHome(payload.data || {});
    else if (currentRoute === "recall") renderRecall(payload);
    else if (currentRoute === "memory") renderMemory(payload);
    else if (currentRoute === "council") renderCouncil(payload);
    else if (currentRoute === "system") renderSystem(payload);
  }
  function setState(message, type = "") { state.textContent = message; state.className = `state ${type}`.trim(); announcer.textContent = message; }
  async function api(path, options = {}) {
    const response = await fetch(path, { cache: "no-store", ...options });
    let body; try { body = await response.json(); } catch (_) { throw new Error("invalid_server_response"); }
    if (!response.ok) throw new Error(body.error || `request_failed_${response.status}`);
    return body;
  }
  async function load(route = currentRoute, query = lastRecallQuery) {
    currentRoute = route; if (route === "recall") lastRecallQuery = query;
    setState("Loading canonical local records…"); content.replaceChildren();
    if (route === "system") $$("#system-tools [data-action]").forEach((button) => { button.disabled = true; button.title = "Waiting for authoritative system state"; });
    try {
      const suffix = route === "recall" ? `?query=${encodeURIComponent(query)}` : "";
      const payload = await api(`/api/view/${route}${suffix}`);
      render(payload);
      if (route === "recall") {
        const recallState = $(".recall-layout")?.dataset.recallState;
        if (recallState === "degraded") setState("Recall updated. No supported answer; required source coverage is degraded.", "warning");
        else if (recallState === "empty") setState("Recall updated. Eligible sources were searched; no supported match was found.");
        else setState("Recall updated with source-grounded evidence.", "success");
      } else setState(`Updated ${routes[route][1]}.`, "success");
      if (route === "system") $$("#system-tools [data-action]").forEach((button) => { button.disabled = false; button.removeAttribute("title"); });
      $("#connection").className = "connection connected"; $("#connection").lastChild.textContent = "Loopback connected";
    } catch (error) {
      setState(`Unable to load ${routes[route][1]}: ${error.message}. Retry preserves this route and query.`, "error");
      const retry = el("button", { type: "button", class: "primary-action", text: "Retry this view", "data-retry-view": "true" }); retry.addEventListener("click", () => load(route, query)); content.append(emptyState("This view is unavailable", "The request failed without changing canonical state.", retry));
      $("#connection").className = "connection unavailable"; $("#connection").lastChild.textContent = "Loopback unavailable";
    }
  }
  async function mutate(action, payload, trigger) {
    if (!token) { setState("Mutation session unavailable. Refresh the page.", "error"); return; }
    if (trigger) trigger.disabled = true; setState(`Applying ${action}…`);
    try {
      const result = await api(`/api/action/${encodeURIComponent(action)}`, { method: "POST", headers: { "Content-Type": "application/json", "X-Mnemoir-Mutation-Token": token }, body: JSON.stringify(payload) });
      setState(`${action} accepted. Authoritative readback and receipt are open.`, "success"); showReadback(result, trigger); await load(currentRoute, currentRoute === "recall" ? lastRecallQuery : "Council memory");
    } catch (error) { setState(`${action} was not applied: ${error.message}. Input is preserved; refresh authoritative state before retrying.`, "error"); }
    finally { if (trigger) trigger.disabled = false; }
  }
  function consequenceFor(action, payload) {
    const target = payload.proposal_id || payload.memory_id || payload.tick_id || "the local service";
    if (action === "memory.write") return `Approved proposal ${target} will become a new canonical memory version. Evidence and proposal history remain. The result can be superseded by a later sourced version or made inactive with Tombstone; history is never deleted. The backend returns a receipt and authoritative readback.`;
    if (action === "memory.tombstone") return `Memory ${target} will become inactive and leave normal recall. Existing versions, provenance, and audit evidence remain. Rollback can recover a retained version; a receipt records this action.`;
    if (action === "memory.rollback") return `Memory ${target} will receive a new active version copied from retained version ${payload.version}. Later history is not deleted; provenance and a recovery receipt remain.`;
    if (action === "autonomy.kill") return `Autonomy tick ${target} will be cancelled and cannot resume. Completed receipts remain; restart requires a new tick.`;
    if (action === "autonomy.pause") return `Autonomy tick ${target} will stop before its next bounded action. Existing receipts remain and policy may allow resume.`;
    if (action === "service.stop") return "The local background service will stop. This UI may lose managed-runtime updates; persisted SQLite data remains. Start can recover it and a receipt records the operation.";
    if (action === "service.restart") return "The local background service will stop and start. Brief unavailability is expected; persisted SQLite data remains and the operation is receipted.";
    if (action === "service.start") return "The local background service will start on this machine. This does not install autostart, cron, or a system service. Stop reverses runtime state and a receipt records it.";
    return `Action ${action} will apply to ${target}. The canonical backend revalidates policy and state, then returns an authoritative readback and receipt.`;
  }
  function confirmationLabel(action) {
    return ({
      "memory.write": "Approve and create version",
      "memory.tombstone": "Make memory inactive",
      "memory.rollback": "Create rollback version",
      "autonomy.kill": "Cancel bounded work",
      "autonomy.pause": "Pause bounded work",
      "service.start": "Start local service",
      "service.stop": "Stop local service",
      "service.restart": "Restart local service"
    })[action] || "Confirm action";
  }
  function confirmationHeading(action) {
    return ({
      "memory.write": "Create canonical memory version",
      "memory.tombstone": "Make canonical memory inactive",
      "memory.rollback": "Create canonical rollback version",
      "autonomy.kill": "Cancel bounded work",
      "autonomy.pause": "Pause bounded work",
      "service.start": "Start local service",
      "service.stop": "Stop local service",
      "service.restart": "Restart local service"
    })[action] || "Confirm consequential action";
  }
  function confirmAction(action, payload, trigger) {
    returnFocus = trigger; pendingConfirmation = { action, payload, trigger };
    $("#confirm-title").textContent = confirmationHeading(action); $("#confirm-copy").textContent = consequenceFor(action, payload); $("#confirm-reason").value = "";
    const submit = $("#confirm-submit"); submit.textContent = confirmationLabel(action);
    submit.className = ["memory.tombstone", "autonomy.kill", "service.stop"].includes(action) ? "danger" : "primary-action";
    confirmDialog.showModal(); $("#confirm-reason").focus();
  }
  confirmDialog.addEventListener("close", () => { if (confirmDialog.returnValue === "confirm" && pendingConfirmation) { const { action, payload, trigger } = pendingConfirmation, reason = $("#confirm-reason").value.trim(); if (reason) payload.reason = reason; mutate(action, payload, trigger); } pendingConfirmation = null; if (returnFocus) returnFocus.focus(); });
  function showReadback(result, trigger) {
    returnFocus = trigger || document.activeElement;
    const outcomes = { "memory.write": "Memory version created", "memory.tombstone": "Memory made inactive", "memory.rollback": "Rollback version created", "autonomy.kill": "Bounded work cancelled", "autonomy.pause": "Bounded work paused", "service.start": "Local service started", "service.stop": "Local service stopped", "service.restart": "Local service restarted" };
    $("#drawer-title").textContent = outcomes[result.action] || "Action receipt";
    const receiptMeta = el("div", { class: "receipt-meta" }, el("span", { text: "Receipt ID" }), el("code", { text: result.receipt_id || "not emitted" }));
    const memoryId = result.result && result.result.memory_id;
    let followup;
    if (memoryId) {
      const inspect = el("button", { type: "button", class: "primary-action", text: "Inspect memory record" });
      inspect.addEventListener("click", () => { drawer.close(); location.hash = "memory"; window.setTimeout(() => openDetail("memory", memoryId, $("[data-route='memory']")), 250); });
      followup = el("section", { class: "receipt-followup" }, el("h3", { text: "Recovery and next step" }), el("p", { text: "Inspect versions and evidence. A later sourced version may supersede this result; Tombstone makes it inactive without deleting history." }), inspect);
    } else {
      const destination = String(result.action || "").startsWith("service.") ? "system" : "council";
      const inspect = routeButton(destination === "system" ? "Review System posture" : "Review Council state", destination, true);
      followup = el("section", { class: "receipt-followup" }, el("h3", { text: "Recovery and next step" }), el("p", { text: destination === "system" ? "Review authoritative runtime posture. Stop reverses a start; restart re-establishes the managed local runtime without deleting persisted data." : "Review authoritative bounded-work state and retained receipts before issuing a superseding action." }), inspect);
    }
    drawerContent.replaceChildren(followup, receiptMeta, section("Result", result.result), section("Authoritative readback", result.readback));
    if (!drawer.open) drawer.showModal(); $(".drawer button[aria-label='Close detail']").focus();
  }
  async function openDetail(kind, id, trigger) {
    returnFocus = trigger; $("#drawer-title").textContent = `${kind}: ${id}`; drawerContent.replaceChildren(el("p", { text: "Loading canonical record…" })); drawer.showModal(); $(".drawer button[aria-label='Close detail']").focus();
    try {
      const result = await api(`/api/detail/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`); drawerContent.replaceChildren(section("Canonical record", result.data));
      if (kind === "proposal") {
        const proposal = result.data || {};
        if (["proposed", "edited", "approved"].includes(proposal.status)) {
          const form = el("form", { class: "form-grid" }, el("label", {}, "Title", el("input", { name: "title", maxlength: "300", required: true, value: proposal.title || "" })), el("label", {}, "Summary", el("textarea", { name: "summary", maxlength: "2000", required: true }, proposal.summary || "")), el("label", { class: "wide" }, "Body", el("textarea", { name: "body", maxlength: "10000", required: true }, proposal.body || "")), el("button", { class: "wide primary-action", type: "submit", text: "Save edited proposal" }));
          form.addEventListener("submit", (event) => { event.preventDefault(); const values = new FormData(form); mutate("proposal.edit", { proposal_id: id, expected_status: proposal.status, reviewer_actor_id: "actor_operator_compat02", reason: "operator_ui_content_edit", title: values.get("title"), summary: values.get("summary"), body: values.get("body") }, event.submitter); }); drawerContent.prepend(form);
        }
      }
      if (kind === "memory") {
        const memory = result.data.memory || {}, actions = el("div", { class: "actions" });
        if (memory.status !== "tombstoned") actions.append(actionButton("Tombstone…", "memory.tombstone", { memory_id: id, expected_status: memory.status }, true));
        (result.data.versions || []).forEach((version) => actions.append(actionButton(`Rollback to v${version.version}…`, "memory.rollback", { memory_id: id, version: version.version, expected_status: memory.status }, true))); drawerContent.prepend(actions);
      }
    } catch (error) { drawerContent.replaceChildren(emptyState("Detail unavailable", `${error.message}. Close this record and retry from the unchanged route.`)); }
  }
  function trapDialogFocus(dialog, event) {
    if (event.key !== "Tab" || !dialog.open) return;
    const focusable = $$("button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled]),[href],[tabindex]:not([tabindex='-1'])", dialog).filter((node) => node.offsetParent !== null);
    if (!focusable.length) return; const first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
  drawer.addEventListener("click", (event) => { if (event.target.matches("button[formmethod='dialog']")) drawer.close(); });
  drawer.addEventListener("close", () => { if (returnFocus) returnFocus.focus(); });
  [drawer, confirmDialog].forEach((dialog) => dialog.addEventListener("keydown", (event) => trapDialogFocus(dialog, event)));

  function navigate() {
    const route = location.hash.slice(1).split(/[?/]/)[0]; currentRoute = routes[route] ? route : "home";
    $$("[data-route]").forEach((link) => link.setAttribute("aria-current", link.dataset.route === currentRoute ? "page" : "false"));
    const meta = routes[currentRoute]; $("#route-code").textContent = meta[0]; $("#route-title").textContent = meta[1]; $("#route-description").textContent = meta[2];
    ["recall", "memory", "system"].forEach((name) => $(`#${name}-tools`).hidden = name !== currentRoute);
    load(currentRoute, currentRoute === "recall" ? ($("#recall-query").value || lastRecallQuery) : "Council memory"); $("#workspace").focus({ preventScroll: true });
  }
  $("#refresh").addEventListener("click", () => load(currentRoute, currentRoute === "recall" ? lastRecallQuery : "Council memory"));
  $("#recall-form").addEventListener("submit", (event) => { event.preventDefault(); const query = $("#recall-query").value.trim(); if (query) load("recall", query); });
  $("#proposal-form").addEventListener("submit", (event) => { event.preventDefault(); const form = new FormData(event.currentTarget), ids = (name) => String(form.get(name) || "").split(",").map((value) => value.trim()).filter(Boolean); mutate("proposal.create", { title: form.get("title"), summary: form.get("summary"), body: form.get("body"), evidence_ids: ids("evidence_ids"), source_event_ids: ids("source_event_ids") }, event.submitter); });
  $$("[data-action]").forEach((button) => button.addEventListener("click", () => button.dataset.confirm ? confirmAction(button.dataset.action, {}, button) : mutate(button.dataset.action, {}, button)));
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && drawer.open) drawer.close(); });
  window.addEventListener("hashchange", navigate);
  api("/api/session").then((session) => { token = session.mutation_token; navigate(); }).catch((error) => { setState(`Secure mutation session unavailable: ${error.message}`, "error"); $("#connection").className = "connection unavailable"; });
})();
