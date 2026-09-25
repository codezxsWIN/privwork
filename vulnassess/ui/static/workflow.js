import {SIZE, NODE_SPECS, EDGES, ICONS, buildNodes, connectedNodeIds, nodeDetails, evidenceKind, evidenceBasis} from './workflow-data.js';
import {readLayout, moveNode, positionNodes, pathNodeIds} from './workflow-layout.js';
import {requestAnalystProgress} from './analyst-client.js';
import {PREVIEW_SCENARIOS} from './workflow-preview.js';

const runSelect = document.getElementById('workflow-run');
const hostSelect = document.getElementById('workflow-host');
const findingSelect = document.getElementById('workflow-finding');
const viewport = document.getElementById('viewport');
const graph = document.getElementById('graph');
const message = document.getElementById('loading-state');
const inspector = document.getElementById('node-inspector');
const content = document.getElementById('node-content');
const runPanel = document.getElementById('run-panel');
const runTargets = document.getElementById('run-targets');
const runProgress = document.getElementById('run-progress');
const runSearch = document.getElementById('run-target-search');
const providerSelect = document.getElementById('analyst-provider');
const svgNamespace = 'http://www.w3.org/2000/svg';
const narrowViewport = matchMedia('(max-width: 960px)');
const layoutKey = 'vulnassess.workflow.layout.v1';
function loadLayout() {
  try { return readLayout(JSON.parse(localStorage.getItem(layoutKey)), NODE_SPECS, SIZE); }
  catch { return {}; }
}
const view = {assessment: null, scope: null, weights: null, host: '', finding: '', node: '', mode: narrowViewport.matches ? 'stages' : 'canvas', modeChosen: false, scale: 1, panX: 0, panY: 0, load: 0, analyses: new Map(), layout: loadLayout()};
function saveLayout() {
  try { localStorage.setItem(layoutKey, JSON.stringify(view.layout)); }
  catch { document.getElementById('workflow-announcement').textContent = 'Layout changed for this session, but could not be saved in this browser.'; }
}
const analysisStages = [
  ['records', 'Read stored assessment'],
  ['model', 'Check model access'],
  ['evidence', 'Gather target evidence'],
  ['coverage', 'Review coverage gaps'],
  ['prompt', 'Prepare grounded request'],
  ['generation', 'Generate response'],
  ['validation', 'Validate citations and scores'],
];
const runState = {busy: false, stop: false, targets: [], selected: new Set(), entries: new Map()};
const liveStages = [
  ['scope', 'Authorise target'], ['scanner', 'Scan services'], ['context', 'Infer context'],
  ...analysisStages.filter(([id]) => id !== 'records'),
];
const liveState = {active: false, busy: false, previewState: 'idle', previewScenario: null, target: '', provider: '', reuseRecent: false, stages: new Map(), scan: null, result: null, error: '', needsReview: false};
let previewSequence = 0;
const executionSteps = () => liveState.previewState !== 'idle' && liveState.previewScenario
  ? liveState.previewScenario.steps
  : liveStages.map(([id, label]) => ({id, label: liveState.reuseRecent && id === 'scanner' ? 'Reuse recent Nmap evidence' : liveState.reuseRecent && id === 'context' ? 'Reuse recorded context' : label}));

function appendInvestigation(holder, analyst) {
  const evidence = new Map((analyst.evidence || []).map(item => [item.id, item]));
  for (const investigation of analyst.analysis.investigations || []) {
    const section = element('section', 'ai-investigation');
    section.append(element('h3', '', 'AI investigation · unverified'));
    section.append(element('p', '', `Hypothesis: ${investigation.hypothesis}`));
    section.append(element('p', '', `Verify: ${investigation.verification}`));
    section.append(element('p', '', `Alternative: ${investigation.alternative}`));
    const citations = element('ul', 'ai-investigation-citations');
    for (const id of investigation.evidence_ids) {
      const item = evidence.get(id);
      citations.append(element('li', '', `${id} · ${item?.kind || 'evidence'}: ${item?.text || 'Citation unavailable'}`));
    }
    section.append(citations);
    holder.append(section);
  }
}

function appendDecisionFrame(holder, frame) {
  if (!frame) return;
  const section = element('section', 'decision-frame');
  section.append(element('h3', '', 'Context-aware priority boundary'));
  const context = frame.context || {};
  section.append(element('p', '', `Recorded role: ${String(context.role?.value || 'unknown').replaceAll('_', ' ')} · exposure: ${String(context.exposure?.value || 'unknown').replaceAll('_', ' ')}.`));
  const controls = Object.entries(context.controls || {}).map(([name, feature]) => `${name.replaceAll('_', ' ')}: ${feature.value === null ? 'unknown' : String(feature.value)}`);
  if (controls.length) section.append(element('p', '', `Recorded controls · ${controls.join(' · ')}`));
  const limits = frame.coverage_review?.limits || [];
  if (limits.length) {
    section.append(element('h3', '', 'Coverage and unknowns'));
    const coverageList = element('ul', '');
    for (const limit of limits) coverageList.append(element('li', '', limit));
    section.append(coverageList);
  }
  const scannerCoverage = Object.entries(frame.scanner_coverage || {});
  if (scannerCoverage.length) {
    section.append(element('h3', '', 'Scanner coverage'));
    const scanners = element('ul', '');
    for (const [tool, status] of scannerCoverage) scanners.append(element('li', '', `${tool}: ${status}`));
    section.append(scanners);
  }
  if (frame.mode === 'verification_only') {
    section.append(element('p', 'boundary-note', 'No vulnerability findings were recorded, so there is no scored finding-priority queue. The services below are verification candidates, not ranked vulnerabilities.'));
    const list = element('ul', '');
    for (const item of frame.verification_candidates || []) list.append(element('li', '', `${item.port}/${item.protocol} ${item.service || 'service'} · ${item.evidence_id}`));
    section.append(list);
  } else {
    section.append(element('p', '', frame.mode === 'scored_findings' ? 'Stored deterministic priority order · AI does not change these scores.' : 'Findings exist, but no stored risk scores are available. No risk order is claimed.'));
    const list = element('ol', '');
    for (const item of frame.priorities || []) {
      const cvss = item.base_score == null ? '' : ` · CVSS base ${item.base_score} → environmental ${item.env_score}`;
      const changes = Object.entries(item.env_modifications || {}).map(([metric, value]) => `${metric}:${value}`).join(', ');
      list.append(element('li', '', `${item.title} · ${item.band} ${item.risk}${cvss}${changes ? ` · recorded environmental changes ${changes}` : ''} · ${item.reason || 'No stored reason'} [${item.score_evidence_id}]`));
    }
    for (const item of frame.unscored_findings || []) list.append(element('li', '', `${item.title} · unscored [${item.finding_evidence_id}]`));
    section.append(list);
  }
  holder.append(section);
}

function appendModelContextEffect(holder, analyst) {
  const effect = analyst?.analysis?.context_effect;
  if (!effect) return;
  const section = element('section', 'analysis-context-effect');
  section.append(element('h3', '', 'AI context effect · cited interpretation'));
  section.append(element('p', '', effect.explanation));
  const evidence = new Map((analyst.evidence || []).map(item => [item.id, item]));
  appendQuotes(section, effect.evidence_ids.map(id => ({label: `Citation ${id}`, quote: evidence.get(id)?.text || 'Citation unavailable', source: analyst.model})));
  holder.append(section);
}

function renderLiveResult() {
  const holder = document.getElementById('live-result');
  holder.replaceChildren();
  holder.hidden = !(liveState.scan || liveState.result || liveState.error);
  const scan = liveState.scan || liveState.result;
  if (scan) {
    holder.append(element('h3', '', `Live scan · ${scan.target} (${scan.resolved_ip})`));
    const services = scan.services || [];
    holder.append(element('p', '', `${services.length} open services · ${scan.finding_count} vulnerability findings from the light scan`));
    const list = element('ul');
    for (const service of services) {
      list.append(element('li', '', `${service.port}/${service.protocol} ${service.name || 'unknown'} · ${service.product || 'product unknown'} ${service.version || ''}`));
    }
    holder.append(list);
    appendDecisionFrame(holder, scan.decision_frame || liveState.result?.decision_frame);
  }
  if (liveState.result?.analyst) {
    const analyst = liveState.result.analyst;
    holder.append(element('h3', '', `${analyst.model} · confidence ${analyst.analysis.confidence}`));
    holder.append(element('p', '', analyst.analysis.summary));
    appendModelContextEffect(holder, analyst);
    appendInvestigation(holder, analyst);
    for (const action of analyst.analysis.recommended_actions) {
      holder.append(element('p', 'analysis-action', `${action.order}. ${action.action} — ${action.reason} [${action.evidence_ids.join(', ')}]`));
    }
    for (const uncertainty of analyst.analysis.uncertainties) holder.append(element('p', '', `Uncertainty: ${uncertainty}`));
  }
  if (liveState.error) holder.append(element('p', 'analysis-error', liveState.error));
}

function renderLiveProgress() {
  const list = document.getElementById('live-progress');
  list.replaceChildren();
  for (const {id, label} of executionSteps()) {
    const entry = liveState.stages.get(id) || {state: 'pending', detail: 'Waiting'};
    const item = element('li', `run-progress-item state-${entry.state}`);
    item.append(element('strong', '', label), element('span', '', entry.state));
    item.append(element('small', '', entry.detail));
    list.append(item);
  }
  document.getElementById('start-live-run').disabled = liveState.busy;
  document.getElementById('new-target').disabled = liveState.busy;
  providerSelect.disabled = liveState.busy;
  const previewButton = document.getElementById('preview-flow');
  previewButton.disabled = liveState.busy && liveState.previewState !== 'running';
  previewButton.setAttribute('aria-pressed', String(liveState.previewState === 'running'));
  previewButton.textContent = liveState.previewState === 'running' ? 'Stop preview' : ['complete', 'stopped', 'blocked'].includes(liveState.previewState) ? 'Replay preview' : 'Preview flow';
  document.getElementById('preview-scenario').disabled = liveState.busy;
}

function renderLiveExecution() {
  const rail = document.getElementById('live-execution');
  rail.hidden = !liveState.active;
  if (!liveState.active) return;
  const isPreview = liveState.previewState !== 'idle';
  const steps = executionSteps();
  document.getElementById('live-path-boundary').hidden = isPreview;
  const context = document.getElementById('live-execution-context');
  context.hidden = !isPreview;
  context.textContent = isPreview ? liveState.previewScenario.context : '';
  document.getElementById('live-execution-mode').textContent = isPreview ? 'SIMULATED PREVIEW / NO SCAN OR MODEL CALL' : liveState.reuseRecent ? 'RE-ANALYSIS / RECENT SCAN / NO NMAP' : 'LIVE NMAP + AI / EVENT STREAM';
  const current = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running');
  const finished = [...liveState.stages.values()].filter(entry => ['complete', 'skipped'].includes(entry.state)).length;
  const currentLabel = current ? steps.find(step => step.id === current[0])?.label : liveState.error ? 'Run stopped' : liveState.result || finished === steps.length ? 'Run complete' : 'Preparing run';
  document.getElementById('live-execution-title').textContent = isPreview
    ? `${liveState.previewScenario.label} · ${liveState.previewState === 'complete' ? 'complete' : liveState.previewState === 'stopped' ? 'stopped' : liveState.previewState === 'blocked' ? 'blocked' : currentLabel}`
    : `${liveState.target} · ${currentLabel}`;
  document.getElementById('live-execution-count').textContent = isPreview
    ? `${finished} / ${steps.length} simulated stages`
    : `${finished} / ${steps.length} Nmap + AI path steps`;
  const last = [...liveState.stages.values()].at(-1);
  document.getElementById('live-execution-detail').textContent = current?.[1].detail
    || (isPreview ? last?.detail || `Preview ${liveState.previewState}. No scan or model call was made.`
      : liveState.error || (liveState.result ? 'Model output validated against the collected evidence.' : 'Waiting for the next stage.'));
  const list = document.getElementById('live-execution-steps');
  list.replaceChildren();
  for (const [index, {id, label}] of steps.entries()) {
    const event = liveState.stages.get(id);
    const state = event?.state || 'pending';
    const item = element('li', `live-execution-step state-${state}`);
    item.append(element('span', 'live-step-state', state === 'pending' ? 'waiting' : state));
    item.append(element('strong', '', `${String(index + 1).padStart(2, '0')} · ${label}`));
    let detail = event?.detail || (index === 0 ? (isPreview ? 'Preview will start here' : 'Waiting for authorization check') : 'Waiting for previous stage');
    if (id === 'scanner' && liveState.scan) {
      const services = liveState.scan.services.map(service => `${service.port}/${service.protocol} ${service.name || 'unknown'}${service.product ? ` · ${service.product}${service.version ? ` ${service.version}` : ''}` : ''}`);
      if (services.length) detail = `${detail} · ${services.join(' / ')}`;
    }
    if (id === 'validation' && liveState.result?.analyst?.analysis?.summary) {
      detail = `${detail} · ${liveState.result.analyst.analysis.summary}`;
    }
    if (state === 'error' && liveState.error) detail = liveState.error;
    item.title = detail;
    item.append(element('small', '', detail));
    list.append(item);
  }
  const output = document.getElementById('live-execution-output');
  output.replaceChildren();
  const analysis = liveState.result?.analyst;
  const frame = liveState.scan?.decision_frame || liveState.result?.decision_frame;
  document.getElementById('live-execution-details').hidden = !analysis && !frame;
  appendDecisionFrame(output, frame);
  if (analysis) {
    output.append(element('h3', '', `${analysis.model} · ${analysis.analysis.confidence} confidence · validated output`));
    output.append(element('p', '', analysis.analysis.summary));
    appendModelContextEffect(output, analysis);
    appendInvestigation(output, analysis);
    const actions = element('ul');
    for (const action of analysis.analysis.recommended_actions) {
      actions.append(element('li', '', `${action.order}. ${action.action} — ${action.reason} [${action.evidence_ids.join(', ')}]`));
    }
    for (const uncertainty of analysis.analysis.uncertainties) actions.append(element('li', '', `Uncertainty: ${uncertainty}`));
    if (actions.children.length) output.append(actions);
  }
}

function applyLiveRunToNodes(nodes) {
  if (!liveState.active) return nodes;
  const stageNode = {scope: 'scope', scanner: 'nmap', context: 'context', model: 'analyst', evidence: 'analyst', prompt: 'analyst', generation: 'analyst', validation: 'analyst'};
  for (const node of nodes) {
    const stage = liveState.previewState !== 'idle'
      ? executionSteps().filter(step => step.node === node.id).map(step => step.id)
      : liveStages.map(([id]) => id).filter(id => stageNode[id] === node.id);
    if (!stage.length) {
      if (liveState.previewState === 'idle') {
        node.state = 'skipped';
        node.status = 'Not run in this Nmap + AI path';
      }
      continue;
    }
    const mostRecent = stage.map(id => [id, liveState.stages.get(id)]).filter(([, entry]) => entry).at(-1);
    const entry = mostRecent?.[1];
    node.state = entry?.state || 'pending';
    node.status = liveState.previewState !== 'idle'
      ? entry?.state === 'running' ? 'Simulated step running' : entry?.state === 'complete' ? 'Simulated step complete' : entry?.state === 'skipped' ? 'Skipped (preview)' : entry?.state === 'error' ? 'Blocked (preview)' : 'Waiting (preview)'
      : entry?.detail || 'Waiting for upstream stage';
    if (node.id === 'nmap' && liveState.scan) {
      node.status = `${liveState.scan.services.length} services · ${liveState.scan.finding_count} findings`;
    }
    if (node.id === 'analyst' && liveState.result?.analyst) {
      node.state = 'complete';
      node.status = `Response validated · ${liveState.result.analyst.analysis.confidence} confidence`;
    }
    if (node.id === 'analyst' && liveState.error && !entry) {
      node.state = 'error';
      node.status = liveState.error;
    }
  }
  return nodes;
}

function liveFlowEdges() {
  if (!liveState.active) return [];
  const current = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running')?.[0];
  if (liveState.previewState !== 'idle') return executionSteps().find(step => step.id === current)?.edges || [];
  if (current === 'scanner') return ['scope:nmap'];
  if (current === 'context') return ['nmap:context'];
  if (['model', 'evidence', 'prompt', 'generation', 'validation'].includes(current)) return ['context:analyst'];
  return [];
}

function completedFlowEdges() {
  if (!liveState.active) return [];
  if (liveState.previewState !== 'idle') return [...new Set(executionSteps()
    .filter(step => liveState.stages.get(step.id)?.state === 'complete')
    .flatMap(step => step.edges))];
  const completed = new Set();
  if (liveState.stages.get('scanner')?.state === 'complete') completed.add('scope:nmap');
  if (liveState.stages.get('context')?.state === 'complete'
      || liveStages.slice(3).some(([id]) => liveState.stages.has(id))) {
    completed.add('nmap:context');
  }
  if (liveStages.slice(3).some(([id]) => liveState.stages.has(id))) completed.add('context:analyst');
  return [...completed];
}

// ==================== RUN ANALYSIS: LIVE RUN HANDLER (START) ====================
async function startLiveRun() {
  if (liveState.busy) return;
  const target = document.getElementById('new-target').value.trim();
  const provider = providerSelect.value;
  const reuseRecent = document.getElementById('live-run-mode').value === 'reuse';
  if (!target) {
    document.getElementById('target-check-result').textContent = 'Enter a target address first.';
    return;
  }
  if (provider !== 'ollama' && !document.getElementById('share-evidence').checked) {
    document.getElementById('target-check-result').textContent = 'Confirm evidence sharing before using a cloud model.';
    return;
  }
  liveState.busy = true;
  previewSequence++;
  liveState.previewState = 'idle';
  liveState.previewScenario = null;
  liveState.active = true;
  liveState.target = target;
  liveState.provider = provider;
  liveState.reuseRecent = reuseRecent;
  liveState.stages = new Map();
  liveState.scan = null;
  liveState.result = null;
  liveState.error = '';
  liveState.needsReview = false;
  renderLiveProgress();
  renderLiveExecution();
  renderLiveResult();
  fitPreviewPath();
  runPanel.hidden = true;
  document.getElementById('open-run').setAttribute('aria-expanded', 'false');
  document.getElementById('live-execution-title').focus({preventScroll: true});
  const accept = event => {
    if (event.type === 'stage' && liveStages.some(([id]) => id === event.stage)
        && ['running', 'complete'].includes(event.state) && typeof event.detail === 'string') {
      liveState.stages.set(event.stage, {state: event.state, detail: event.detail});
      renderLiveProgress();
      renderLiveExecution();
      renderGraph();
    } else if (event.type === 'scan' && event.scan && Array.isArray(event.scan.services)) {
      liveState.scan = event.scan;
      renderLiveResult();
      renderLiveExecution();
      renderGraph();
    } else if (event.type === 'result' && event.result?.analyst) {
      liveState.result = event.result;
      renderLiveResult();
      renderLiveExecution();
      renderGraph();
    } else if (event.type === 'needs-review' && typeof event.message === 'string') {
      const failure = new Error(event.message);
      failure.name = 'NeedsReviewError';
      throw failure;
    } else if (event.type === 'error' && typeof event.message === 'string') {
      throw new Error(event.message);
    } else {
      throw new Error('Invalid live assessment event.');
    }
  };
  try {
    const response = await fetch('/api/live-assessment/events', {
      method: 'POST', cache: 'no-store', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-VulnAssess-Action': 'live-assessment'},
      body: JSON.stringify({target, provider, share_evidence: provider !== 'ollama', reuse_recent: reuseRecent}),
    });
    if (!response.ok) {
      const failure = await response.json().catch(() => null);
      throw new Error(failure?.error?.message || 'Live assessment request failed.');
    }
    if (!response.body) throw new Error('Live assessment stream is unavailable.');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, {stream: true});
      if (buffer.length > 2_000_000) throw new Error('Live assessment response exceeded its size limit.');
      let newline;
      while ((newline = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line) accept(JSON.parse(line));
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) accept(JSON.parse(buffer));
    if (!liveState.result) throw new Error('Live assessment ended without a model result.');
  } catch (error) {
    liveState.error = error instanceof Error ? error.message : 'Live assessment failed.';
    liveState.needsReview = error instanceof Error && error.name === 'NeedsReviewError';
    const running = [...liveState.stages].reverse().find(([, entry]) => entry.state === 'running');
    if (running) liveState.stages.set(running[0], {state: 'error', detail: liveState.error});
    renderLiveResult();
    renderLiveExecution();
    renderGraph();
    document.getElementById('live-result').scrollIntoView({block: 'nearest'});
  } finally {
    liveState.busy = false;
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
  }
}
// ==================== RUN ANALYSIS: LIVE RUN HANDLER (END) ======================

async function previewLiveFlow() {
  if (liveState.previewState === 'running') {
    previewSequence++;
    const current = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running');
    if (current) liveState.stages.set(current[0], {state: 'pending', detail: 'Preview stopped here'});
    liveState.busy = false;
    liveState.previewState = 'stopped';
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
    return;
  }
  if (liveState.busy) return;
  const sequence = ++previewSequence;
  const scenario = PREVIEW_SCENARIOS[document.getElementById('preview-scenario').value] || PREVIEW_SCENARIOS.light;
  liveState.active = true;
  liveState.busy = true;
  liveState.previewState = 'running';
  liveState.previewScenario = scenario;
  liveState.target = '';
  liveState.provider = '';
  liveState.stages = new Map();
  liveState.scan = null;
  liveState.result = null;
  liveState.error = '';
  liveState.needsReview = false;
  renderLiveProgress();
  renderLiveExecution();
  renderLiveResult();
  fitPreviewPath();
  runPanel.hidden = true;
  document.getElementById('open-run').setAttribute('aria-expanded', 'false');
  document.getElementById('live-execution-title').focus({preventScroll: true});
  for (const step of scenario.steps) {
    if (sequence !== previewSequence) return;
    if (step.outcome === 'skipped') {
      liveState.stages.set(step.id, {state: 'skipped', detail: step.detail});
      renderLiveProgress();
      renderLiveExecution();
      renderGraph();
      continue;
    }
    liveState.stages.set(step.id, {state: 'running', detail: step.detail});
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
    await new Promise(resolve => setTimeout(resolve, 1250));
    if (sequence !== previewSequence) return;
    liveState.stages.set(step.id, {state: step.outcome, detail: step.detail});
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
    if (step.outcome === 'error') break;
  }
  if (sequence !== previewSequence) return;
  liveState.busy = false;
  liveState.previewState = [...liveState.stages.values()].some(entry => entry.state === 'error') ? 'blocked' : 'complete';
  renderLiveProgress();
  renderLiveExecution();
  renderGraph();
  document.getElementById('workflow-announcement').textContent = `${scenario.label} animation preview ${liveState.previewState}. No scan or model request was made.`;
}

function renderRunTargets() {
  const filter = runSearch.value.trim().toLowerCase();
  runTargets.replaceChildren();
  for (const host of view.assessment?.hosts || []) {
    const name = [host.ip, host.hostname].filter(Boolean).join(' · ');
    if (filter && !name.toLowerCase().includes(filter)) continue;
    const label = element('label', 'run-target');
    const input = element('input');
    input.type = 'checkbox';
    input.value = host.ip;
    input.checked = runState.selected.has(host.ip);
    input.disabled = runState.busy;
    label.append(input, element('span', '', name));
    runTargets.append(label);
  }
  if (!runTargets.children.length) runTargets.append(element('p', 'run-empty', 'No recorded target matches. Choose another assessment above to see its targets.'));
  document.getElementById('run-selection-note').textContent = `${runState.selected.size} selected · ${view.assessment?.hosts.length || 0} recorded in this assessment`;
}

function renderRunProgress() {
  runProgress.replaceChildren();
  const results = document.getElementById('recorded-analysis-results');
  results.replaceChildren();
  for (const host of runState.targets) {
    const entry = runState.entries.get(host) || {status: 'pending'};
    const item = element('li', `run-progress-item state-${entry.status}`);
    item.append(element('strong', '', host), element('span', '', entry.status === 'running' ? `${entry.stage || 'Preparing'} · ${entry.detail || 'Starting'}` : entry.status));
    if (entry.error) item.append(element('small', '', entry.error));
    runProgress.append(item);
    const analysis = view.analyses.get(`${view.assessment?.run.run_id}/${host}`)?.result;
    if (!analysis || !['complete', 'reused'].includes(entry.status)) continue;
    const card = element('section', 'recorded-analysis-card');
    card.append(element('h3', '', `Assessment · ${host}`));
    appendDecisionFrame(card, analysis.decision_frame);
    appendModelContextEffect(card, analysis);
    const actions = analysis.analysis?.recommended_actions || [];
    if (actions.length) {
      card.append(element('h3', '', analysis.decision_frame?.mode === 'verification_only' ? 'AI verification order · unscored' : 'AI remediation sequence · stored scores unchanged'));
      const actionList = element('ol', 'recorded-action-list');
      for (const action of actions) actionList.append(element('li', '', `${action.action} — ${action.reason} [${action.evidence_ids.join(', ')}]`));
      card.append(actionList);
    }
    const open = element('button', 'run-button', 'Open full context and AI assessment');
    open.type = 'button';
    open.addEventListener('click', () => {
      view.host = host;
      view.finding = '';
      hostSelect.value = host;
      populateFindings();
      updateLocation();
      runPanel.hidden = true;
      document.getElementById('open-run').setAttribute('aria-expanded', 'false');
      selectNode('analyst');
    });
    card.append(open);
    results.append(card);
  }
  document.getElementById('start-run').disabled = runState.busy;
  document.getElementById('stop-run').hidden = !runState.busy;
  if (!runState.busy) document.getElementById('stop-run').disabled = false;
}

async function startRun() {
  if (runState.busy || !view.assessment) return;
  const provider = providerSelect.value;
  if (provider !== 'ollama' && !document.getElementById('share-evidence').checked) {
    document.getElementById('run-selection-note').textContent = 'Confirm evidence sharing before using a cloud model.';
    return;
  }
  const hosts = [...runState.selected];
  if (!hosts.length) {
    document.getElementById('run-selection-note').textContent = 'Select at least one recorded target.';
    return;
  }
  runState.busy = true;
  runState.stop = false;
  runState.targets = hosts;
  runState.entries = new Map(hosts.map(host => [host, {status: 'pending'}]));
  renderRunTargets();
  renderRunProgress();
  const runId = view.assessment.run.run_id;
  for (const host of hosts) {
    if (runState.stop) {
      runState.entries.set(host, {status: 'stopped'});
      renderRunProgress();
      continue;
    }
    runState.entries.set(host, {status: 'running', stage: 'Read stored assessment'});
    renderRunProgress();
    if (view.assessment?.run.run_id === runId) {
      view.host = host;
      view.finding = '';
      hostSelect.value = host;
      populateFindings();
      updateLocation();
      renderGraph();
      renderInspector();
    }
    const cached = view.analyses.get(`${runId}/${host}`);
    const source = {openrouter: 'openrouter_deepseek_grounded_analysis', groq: 'groq_gpt_oss_120b_grounded_analysis', ollama: 'local_ollama_grounded_analysis'}[provider];
    const sameProvider = cached?.result?.source === source;
    const result = cached?.status === 'complete' && sameProvider ? cached : await analyzeTarget(host, runId, provider);
    runState.entries.set(host, result.status === 'complete' ? {status: sameProvider ? 'reused' : 'complete'} : {status: 'error', error: result.error});
    if (result.status !== 'complete') runState.stop = true;
    renderRunProgress();
  }
  runState.busy = false;
  renderRunTargets();
  renderRunProgress();
  const failed = [...runState.entries.values()].some(entry => entry.status === 'error');
  const providerLabel = {openrouter: 'DeepSeek', groq: 'Groq', ollama: 'Local'}[provider];
  document.getElementById('workflow-announcement').textContent = `${providerLabel} analysis ${failed ? 'stopped after an error' : 'run finished'}. Scanner and stored scores were not changed.`;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function svgElement(name, attributes = {}) {
  const node = document.createElementNS(svgNamespace, name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

function icon(name) {
  const svg = svgElement('svg', {viewBox: '0 0 24 24', 'aria-hidden': 'true'});
  for (const path of ICONS[name] || ICONS.report) svg.append(svgElement('path', {d: path}));
  return svg;
}

async function getRecord(path) {
  const response = await fetch(path, {cache: 'no-store', credentials: 'same-origin'});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || payload.reason || `Stored records unavailable: ${path}`);
  return payload;
}

function currentAnalysis() {
  return view.assessment ? view.analyses.get(`${view.assessment.run.run_id}/${view.host}`) : null;
}

function selection() { return {host: view.host, finding: view.finding}; }
function transform() {
  graph.style.transform = view.mode === 'stages' ? 'none' : `translate(${view.panX}px, ${view.panY}px) scale(${view.scale})`;
  document.getElementById('zoom-level').textContent = `${Math.round(view.scale * 100)}%`;
}

function setViewMode(mode) {
  view.mode = mode;
  viewport.dataset.view = mode;
  viewport.setAttribute('aria-label', mode === 'canvas' ? 'Assessment workflow canvas' : 'Assessment workflow stages');
  for (const button of document.querySelectorAll('[data-view-mode]')) button.setAttribute('aria-pressed', String(button.dataset.viewMode === mode));
  viewport.scrollTop = 0;
  fit();
}

function fit() {
  if (!view.assessment) return;
  const width = viewport.clientWidth;
  const height = viewport.clientHeight;
  const top = document.querySelector('.trace-controls').offsetHeight + 44;
  const bottom = document.querySelector('.canvas-footer').offsetHeight + 40;
  const availableHeight = height - top - bottom;
  view.scale = Math.max(0.18, Math.min(1, (width - 52) / SIZE.width, availableHeight / SIZE.height));
  view.panX = (width - SIZE.width * view.scale) / 2;
  view.panY = top + Math.max(0, (availableHeight - SIZE.height * view.scale) / 2);
  transform();
}

function fitPreviewPath() {
  if (!view.assessment || view.mode !== 'canvas' || !liveState.active) return fit();
  const path = pathNodeIds(executionSteps(), ['scope', 'nmap', 'context', 'analyst']);
  const nodes = positionNodes(buildNodes(view.assessment, view.scope), view.layout).filter(node => path.has(node.id));
  if (!nodes.length) return fit();
  const left = Math.min(...nodes.map(node => node.x)) - 100;
  const right = Math.max(...nodes.map(node => node.x)) + 100;
  const topNode = Math.min(...nodes.map(node => node.y)) - 65;
  const bottomNode = Math.max(...nodes.map(node => node.y)) + 135;
  const width = viewport.clientWidth;
  const height = viewport.clientHeight;
  const top = document.querySelector('.trace-controls').offsetHeight + 28;
  const bottom = document.querySelector('.canvas-footer').offsetHeight + 25;
  const availableHeight = height - top - bottom;
  view.scale = Math.max(.18, Math.min(1, (width - 40) / (right - left), availableHeight / (bottomNode - topNode)));
  view.panX = (width - (right - left) * view.scale) / 2 - left * view.scale;
  view.panY = top + Math.max(0, (availableHeight - (bottomNode - topNode) * view.scale) / 2) - topNode * view.scale;
  transform();
}

function zoom(factor, point = {x: viewport.clientWidth / 2, y: viewport.clientHeight / 2}) {
  const previous = view.scale;
  view.scale = Math.max(.18, Math.min(2.2, previous * factor));
  view.panX = point.x - (point.x - view.panX) * view.scale / previous;
  view.panY = point.y - (point.y - view.panY) * view.scale / previous;
  transform();
}

function edgePath(from, to) {
  const horizontal = Math.abs(to.x - from.x) > Math.abs(to.y - from.y) * .75;
  if (horizontal) {
    const direction = Math.sign(to.x - from.x) || 1;
    const start = {x: from.x + 50 * direction, y: from.y};
    const end = {x: to.x - 50 * direction, y: to.y};
    const middle = (start.x + end.x) / 2;
    return `M${start.x},${start.y} C${middle},${start.y} ${middle},${end.y} ${end.x},${end.y}`;
  }
  const side = Math.max(from.x, to.x) + 105;
  const start = {x: from.x + 50, y: from.y};
  const end = {x: to.x + 50, y: to.y};
  return `M${start.x},${start.y} C${side},${start.y} ${side},${end.y} ${end.x},${end.y}`;
}

function renderGraph() {
  if (!view.assessment) return;
  viewport.dataset.execution = liveState.active ? 'true' : 'false';
  viewport.dataset.preview = liveState.previewState !== 'idle' ? 'true' : 'false';
  const nodes = applyLiveRunToNodes(positionNodes(buildNodes(view.assessment, view.scope, selection(), currentAnalysis()), view.layout));
  const analysis = currentAnalysis();
  const currentLive = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running');
  document.getElementById('canvas-status').textContent = liveState.previewState !== 'idle'
    ? `Simulated preview / ${liveState.previewScenario.label} / ${currentLive ? executionSteps().find(step => step.id === currentLive[0])?.label : liveState.previewState}`
    : liveState.active
    ? `Live run / ${currentLive ? `${executionSteps().find(step => step.id === currentLive[0])?.label} · ${currentLive[1].detail}` : liveState.result ? 'complete · model output validated' : liveState.needsReview ? 'Needs review · model output rejected' : liveState.error ? 'stopped · stage failed' : 'starting'}`
    : analysis?.status === 'running'
    ? `Local analyst / ${analysisStages.find(([id]) => id === analysis.stage)?.[1] || 'Starting'}`
    : analysis?.status === 'complete' ? 'Local analyst complete / stored scores unchanged'
    : analysis?.status === 'needs_review' ? 'Needs review / model output rejected / stored scores unchanged'
    : analysis?.status === 'error' ? 'Local analyst failed / stored scores unchanged'
    : 'Stored records / no pipeline execution';
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const connected = view.node ? connectedNodeIds(view.node) : null;
  const paths = document.getElementById('connections');
  paths.setAttribute('viewBox', `0 0 ${SIZE.width} ${SIZE.height}`);
  paths.replaceChildren();
  const definitions = svgElement('defs');
  const arrow = svgElement('marker', {id: 'flow-arrow', markerWidth: 6, markerHeight: 6, refX: 5, refY: 3, orient: 'auto', markerUnits: 'strokeWidth'});
  arrow.append(svgElement('path', {d: 'M0,0 L6,3 L0,6', class: 'arrow-fill'}));
  definitions.append(arrow);
  paths.append(definitions);
  const flowEdges = new Set(liveFlowEdges());
  const completedEdges = new Set(completedFlowEdges());
  const previewEdges = liveState.previewState !== 'idle'
    ? new Set(executionSteps().flatMap(step => step.edges)) : null;
  for (const edge of EDGES) {
    const from = nodeMap.get(edge.from);
    const to = nodeMap.get(edge.to);
    const missing = edge.optional || ['missing', 'optional'].includes(from.state) || ['missing', 'optional'].includes(to.state);
    const identity = `${edge.from}:${edge.to}`;
    const active = view.node === edge.from || view.node === edge.to;
    paths.append(svgElement('path', {d: edgePath(from, to), class: `connection${missing ? ' optional' : ''}${active ? ' highlighted' : ''}${view.node && !active && !liveState.active ? ' faded' : ''}${previewEdges && !previewEdges.has(identity) ? ' out-of-preview' : ''}`, 'marker-end': 'url(#flow-arrow)', 'data-edge': identity}));
    if (completedEdges.has(identity)) paths.append(svgElement('path', {d: edgePath(from, to), class: 'connection-flow-done', 'data-flow-complete': identity}));
    if (active) paths.append(svgElement('path', {d: edgePath(from, to), class: 'connection-trace', pathLength: 100}));
    if (flowEdges.has(identity)) paths.append(svgElement('path', {d: edgePath(from, to), class: 'connection-flow', pathLength: 100, 'data-live-edge': identity}));
  }
  for (const identity of ['nmap:context', 'context:analyst']) {
    if (!flowEdges.has(identity) && !completedEdges.has(identity)) continue;
    const [from, to] = identity.split(':');
    const flow = edgePath(nodeMap.get(from), nodeMap.get(to));
    paths.append(svgElement('path', {d: flow, class: 'connection optional', 'data-edge': identity}));
    if (completedEdges.has(identity)) paths.append(svgElement('path', {d: flow, class: 'connection-flow-done', 'data-flow-complete': identity}));
    if (flowEdges.has(identity)) paths.append(svgElement('path', {d: flow, class: 'connection-flow', pathLength: 100, 'data-live-edge': identity}));
  }
  const list = document.getElementById('node-list');
  list.replaceChildren();
  const previewPath = pathNodeIds(executionSteps(), ['scope', 'nmap', 'context', 'analyst']);
  for (const node of nodes) {
    const button = element('button', `flow-node group-${node.group} state-${node.state}`);
    button.type = 'button';
    button.dataset.node = node.id;
    if (previewPath.has(node.id)) button.dataset.executionPath = 'true';
    button.style.left = `${node.x}px`;
    button.style.top = `${node.y}px`;
    button.setAttribute('aria-label', `${node.title}: ${node.status}. Drag to arrange, or use Alt and arrow keys.`);
    button.title = `${node.title} / ${node.subtitle} / ${node.status} · Drag to arrange`;
    button.setAttribute('aria-pressed', String(view.node === node.id));
    if (view.node && !connected.has(node.id)) button.classList.add('muted-node');
    const disc = element('span', 'node-disc');
    disc.append(icon(node.icon));
    const stateMark = element('span', 'node-state-mark');
    stateMark.setAttribute('aria-hidden', 'true');
    stateMark.textContent = node.state === 'error' ? '!' : '';
    disc.append(stateMark);
    button.append(disc, element('strong', 'node-title', node.title), element('span', 'node-subtitle', node.subtitle), element('span', 'node-status', node.status));
    button.addEventListener('keydown', event => {
      const offsets = {ArrowLeft: [-20, 0], ArrowRight: [20, 0], ArrowUp: [0, -20], ArrowDown: [0, 20]};
      if (view.mode !== 'canvas' || !event.altKey || !offsets[event.key]) return;
      event.preventDefault();
      const [dx, dy] = offsets[event.key];
      view.layout = moveNode(view.layout, node.id, node.x + dx, node.y + dy, SIZE);
      saveLayout();
      renderGraph();
      document.querySelector(`[data-node="${node.id}"]`)?.focus({preventScroll: true});
      document.getElementById('workflow-announcement').textContent = `${node.title} moved. Layout saved.`;
    });
    button.addEventListener('click', () => selectNode(node.id));
    list.append(button);
  }
  const lanes = document.getElementById('lanes');
  if (!lanes.children.length) {
    const labels = [
      {text: '01 / EVIDENCE', x: 65, y: 30}, {text: '02 / INTELLIGENCE', x: 585, y: 0},
      {text: '03 / RISK & PRIORITY', x: 945, y: 245}, {text: '04 / OUTPUTS', x: 1320, y: 30},
    ];
    for (const label of labels) {
      const item = element('span', 'lane-label', label.text);
      item.style.left = `${label.x}px`;
      item.style.top = `${label.y}px`;
      lanes.append(item);
    }
  }
}

function rows(items) {
  const list = element('dl', 'detail-rows');
  for (const item of items) list.append(element('dt', '', item.label), element('dd', 'evidence', item.value === null || item.value === undefined ? 'Not recorded' : String(item.value)));
  return list;
}

function appendQuotes(parent, items) {
  for (const item of items) {
    const group = element('div', 'evidence-item');
    group.append(element('span', 'detail-label', item.label));
    if (Object.hasOwn(item, 'value')) group.append(element('strong', 'feature-label', String(item.value).replaceAll('_', ' ')));
    if (item.confidence !== undefined) group.append(element('small', 'detail-hint', `Confidence ${item.confidence} · ${item.source}`));
    group.append(element('blockquote', 'evidence', item.quote));
    if (item.source) group.append(element('small', 'evidence-source', item.source));
    parent.append(group);
  }
}

function updateProjectLink() {
  if (!view.assessment) return;
  const parameters = new URLSearchParams();
  if (view.host) parameters.set('asset', view.host);
  if (view.finding) parameters.set('finding', view.finding);
  const section = view.finding ? 'project-doors' : 'project-workflow';
  document.getElementById('assessment-link').href = `/?run=${encodeURIComponent(view.assessment.run.run_id)}#${section}${parameters.size ? `?${parameters}` : ''}`;
}

function updateLocation() {
  const parameters = new URLSearchParams();
  if (view.node) parameters.set('node', view.node);
  if (view.host) parameters.set('host', view.host);
  if (view.finding) parameters.set('finding', view.finding);
  history.replaceState(null, '', `${location.pathname}${location.search}${parameters.size ? `#${parameters}` : ''}`);
  updateProjectLink();
}

function selectNode(identity) {
  view.node = identity;
  updateLocation();
  inspector.hidden = false;
  renderGraph();
  renderInspector();
  fit();
  content.querySelector('h2').focus({preventScroll: true});
  document.getElementById('workflow-announcement').textContent = `${content.querySelector('h2').textContent} selected`;
}

function renderInspector() {
  if (!view.node || !view.assessment) return;
  const nodes = applyLiveRunToNodes(buildNodes(view.assessment, view.scope, selection(), currentAnalysis()));
  const node = nodes.find(item => item.id === view.node);
  const details = nodeDetails(view.node, view.assessment, view.scope, view.weights, selection(), currentAnalysis());
  content.replaceChildren();
  const heading = element('div', 'node-detail-title');
  const glyph = element('span', `inspector-glyph group-${node.group}`);
  glyph.append(icon(node.icon));
  const title = element('h2', '', node.title);
  title.tabIndex = -1;
  heading.append(glyph, title);
  content.append(heading, element('p', 'node-description', node.subtitle), element('span', `detail-status state-${node.state}`, node.status));
  if (liveState.active && node.state === 'skipped' && liveState.previewState === 'idle') {
    content.append(element('p', 'boundary-note', 'Not run in this Nmap + AI path. Any records below belong to the selected stored assessment, not this live run.'));
  }
  const logic = element('div', 'node-operation');
  for (const [label, value] of [['INPUT', details.input], ['OPERATION', details.operation], ['OUTPUT', details.output]]) {
    const section = element('div', 'operation-row');
    section.append(element('span', 'detail-label', label), element('p', '', value));
    logic.append(section);
  }
  content.append(logic);
  if (details.rows.length) content.append(rows(details.rows));
  appendQuotes(content, details.quotes);
  if (view.node === 'analyst') renderAnalyst();
  if (details.message) content.append(element('p', 'boundary-note', details.message));
  if (details.records.length) {
    const disclosure = element('details', 'raw-records');
    disclosure.append(element('summary', '', 'Raw records'), element('pre', 'evidence', JSON.stringify(details.records, null, 2)));
    content.append(disclosure);
  }
  const module = element('div', 'module-path');
  module.append(element('span', 'detail-label', 'IMPLEMENTATION'), element('span', 'evidence', details.provenance));
  content.append(module);
  const links = element('div', 'node-neighbours');
  for (const edge of EDGES.filter(edge => edge.from === view.node || edge.to === view.node)) {
    const other = nodes.find(item => item.id === (edge.from === view.node ? edge.to : edge.from));
    const button = element('button', 'neighbour-link', `${edge.from === view.node ? 'To' : 'From'} ${other.title}`);
    button.type = 'button';
    button.addEventListener('click', () => selectNode(other.id));
    links.append(button);
  }
  content.append(links);
}

function renderAnalyst() {
  const holder = element('section', 'analyst-action');
  holder.append(element('p', 'analyst-scope', view.host ? `Target: ${view.host}` : 'Select a target above to analyze its stored evidence.'));
  const button = element('button', 'analyze-button', currentAnalysis()?.status === 'running' ? 'Request in progress' : 'Analyze target');
  button.type = 'button';
  button.id = 'workflow-analyze';
  button.disabled = !view.host || currentAnalysis()?.status === 'running';
  button.addEventListener('click', () => analyzeTarget());
  holder.append(button);
  const basis = evidenceBasis(view.assessment, view.host);
  let ledger = null;
  if (basis) {
    ledger = element('div', 'analyst-basis');
    ledger.append(element('h3', '', 'Evidence-only view · no AI conclusion'));
    for (const [heading, lines] of [
      ['Observed', basis.observed.length ? basis.observed : ['No services recorded.']],
      ['Context effect', basis.context],
      ['Not established', basis.notChecked.length ? basis.notChecked : ['No specific coverage gap recorded.']],
      ['Next verification', [basis.nextVerification]],
    ]) {
      const section = element('section', 'analyst-basis-section');
      section.append(element('h4', '', heading));
      const list = element('ul', '');
      for (const line of lines) list.append(element('li', '', line));
      section.append(list);
      ledger.append(section);
    }
  }
  const live = currentAnalysis();
  if (live) {
    const progress = element('ol', 'analysis-progress');
    progress.setAttribute('aria-label', 'Local analyst stages');
    for (const [id, label] of analysisStages) {
      const state = live.steps?.[id]?.state || 'pending';
      const item = element('li', `analysis-progress-step state-${state}`);
      item.dataset.stage = id;
      item.append(element('span', 'analysis-progress-state', state.replace('-', ' ')), element('strong', '', label));
      const detail = element('span', 'analysis-progress-detail', live.steps?.[id]?.detail || 'Not started');
      detail.dataset.progressDetail = id;
      item.append(detail);
      progress.append(item);
    }
    holder.append(progress);
  }
  if (live?.status === 'running') holder.append(element('p', 'analysis-wait', 'Only the local analyst steps above are running. Scanner and score nodes show stored records.'));
  if (live?.status === 'error' || live?.status === 'needs_review') holder.append(element('p', 'analysis-error', live.error));
  if (live?.result) {
    const result = live.result;
    appendDecisionFrame(holder, result.decision_frame);
    holder.append(element('p', 'analysis-summary', result.analysis.summary));
    appendModelContextEffect(holder, result);
    const evidenceMap = new Map(result.evidence.map(item => [item.id, item]));
    for (const action of result.analysis.recommended_actions) {
      const record = element('div', 'analysis-action');
      record.append(element('h3', '', action.action), element('p', '', action.reason));
      appendQuotes(record, action.evidence_ids.map(identity => ({label: `Citation ${identity}`, quote: evidenceMap.get(identity)?.text || 'Citation not present in response', source: result.model})));
      holder.append(record);
    }
    for (const correlation of result.analysis.correlations || []) {
      const record = element('div', 'analysis-action');
      record.append(element('h3', '', 'Correlated evidence'), element('p', '', correlation.observation));
      appendQuotes(record, correlation.evidence_ids.map(identity => ({label: `Citation ${identity}`, quote: evidenceMap.get(identity)?.text || 'Citation not present in response', source: result.model})));
      holder.append(record);
    }
    appendInvestigation(holder, result);
    for (const uncertainty of result.analysis.uncertainties) holder.append(element('p', 'boundary-note', uncertainty));
  }
  if (ledger) holder.append(ledger);
  content.append(holder);
}

async function analyzeTarget(hostIp = view.host, runId = view.assessment?.run.run_id, provider = 'ollama') {
  if (!hostIp || !runId || !view.assessment) return {status: 'error', error: 'No recorded target selected'};
  const key = `${runId}/${hostIp}`;
  if (view.analyses.get(key)?.status === 'running') return {status: 'error', error: 'Analysis already running for this target'};
  view.analyses.set(key, {runId, hostIp, status: 'running', stage: '', steps: {}});
  renderGraph();
  renderInspector();
  try {
    const response = await requestAnalystProgress(runId, hostIp, event => {
      const live = view.analyses.get(key);
      if (!live || live.status !== 'running' || !analysisStages.some(([id]) => id === event.stage)) return;
      const previousState = live.steps[event.stage]?.state;
      live.stage = event.stage;
      live.steps[event.stage] = {state: event.state, detail: event.detail};
      if (runState.entries.get(hostIp)?.status === 'running') {
        runState.entries.set(hostIp, {status: 'running', stage: analysisStages.find(([id]) => id === event.stage)[1], detail: event.detail});
        renderRunProgress();
      }
      if (view.assessment?.run.run_id === runId && view.host === hostIp) {
        if (previousState !== event.state) {
          renderGraph();
          renderInspector();
          document.getElementById('workflow-announcement').textContent = `${analysisStages.find(([id]) => id === event.stage)[1]}: ${event.state}`;
        } else {
          const detail = document.querySelector(`[data-progress-detail="${event.stage}"]`);
          if (detail) detail.textContent = event.detail;
        }
      }
    }, provider);
    const live = view.analyses.get(key);
    view.analyses.set(key, {...live, status: 'complete', result: response});
  } catch (error) {
    const live = view.analyses.get(key);
    const steps = {...live?.steps};
    steps[live?.stage || 'records'] = {state: 'error', detail: error.message};
    view.analyses.set(key, {...live, status: error.name === 'NeedsReviewError' ? 'needs_review' : 'error', steps, error: error.message});
  }
  if (view.assessment?.run.run_id === runId && view.host === hostIp) {
    renderGraph();
    renderInspector();
    document.getElementById('workflow-announcement').textContent = view.analyses.get(key).status === 'complete' ? 'Analyst response received. Stored scores unchanged.' : view.analyses.get(key).status === 'needs_review' ? 'Needs review. Model output rejected; no partial result shown.' : 'Analysis failed. No result substituted.';
  }
  return view.analyses.get(key);
}

function populateFindings() {
  const findings = view.assessment.findings.filter(finding => !view.host || finding.host_ip === view.host);
  findingSelect.replaceChildren(element('option', '', 'All findings'));
  findingSelect.options[0].value = '';
  for (const finding of findings) {
    const option = element('option', '', `${finding.host_ip} / ${finding.title}`);
    option.value = finding.id;
    findingSelect.append(option);
  }
  if (!findings.some(finding => finding.id === view.finding)) view.finding = '';
  findingSelect.value = view.finding;
  findingSelect.disabled = false;
}

function populateSelection() {
  hostSelect.replaceChildren(element('option', '', 'All recorded hosts'));
  hostSelect.options[0].value = '';
  for (const host of view.assessment.hosts) {
    const option = element('option', '', host.ip);
    option.value = host.ip;
    hostSelect.append(option);
  }
  if (!view.assessment.hosts.some(host => host.ip === view.host)) view.host = '';
  hostSelect.value = view.host;
  hostSelect.disabled = false;
  populateFindings();
}

async function loadWorkflow() {
  const sequence = ++view.load;
  message.hidden = false;
  message.querySelector('strong').textContent = 'Opening the assessment';
  message.querySelector('p').textContent = 'Reading local records.';
  graph.hidden = true;
  document.getElementById('refresh-workflow').disabled = true;
  try {
    const index = await getRecord('/api/runs');
    if (!index.runs.length) throw new Error('No stored runs. Import an authorized capture through the CLI, then refresh.');
    const requested = new URLSearchParams(location.search).get('run') || index.selected_run || index.runs[0].run_id;
    const [assessment, scope, weights] = await Promise.all([getRecord(`/api/run/${encodeURIComponent(requested)}`), getRecord('/api/scope'), getRecord('/api/weights')]);
    if (sequence !== view.load) return;
    view.assessment = assessment;
    view.scope = scope;
    view.weights = weights;
    runSelect.replaceChildren(...index.runs.map(run => { const option = element('option', '', run.run_id); option.value = run.run_id; return option; }));
    runSelect.value = requested;
    runSelect.disabled = false;
    const parameters = new URLSearchParams(location.hash.slice(1));
    view.host = parameters.get('host') || '';
    view.finding = parameters.get('finding') || '';
    populateSelection();
    if (!runState.busy) {
      runState.selected = new Set(view.host ? [view.host] : assessment.hosts.map(host => host.ip));
      renderRunTargets();
    }
    document.getElementById('canvas-caption').textContent = `Recorded assessment / ${assessment.run.run_id}`;
    document.getElementById('record-summary').textContent = `${assessment.hosts.length} assets / ${assessment.findings.length} findings / ${assessment.scores.length} scored`;
    document.getElementById('run-hash').textContent = `config ${assessment.run.config_hash}`;
    document.getElementById('data-kind').textContent = evidenceKind(assessment);
    updateProjectLink();
    graph.hidden = false;
    message.hidden = true;
    renderGraph();
    if (buildNodes(assessment, scope).some(node => node.id === parameters.get('node'))) selectNode(parameters.get('node'));
    fit();
  } catch (error) {
    if (sequence !== view.load) return;
    view.assessment = null;
    inspector.hidden = true;
    hostSelect.disabled = true;
    findingSelect.disabled = true;
    message.querySelector('strong').textContent = 'Records unavailable';
    message.querySelector('p').textContent = error.message;
    document.getElementById('canvas-caption').textContent = 'The stored assessment could not be loaded.';
    document.getElementById('record-summary').textContent = '';
  } finally {
    if (sequence === view.load) document.getElementById('refresh-workflow').disabled = false;
  }
}

document.getElementById('refresh-workflow').addEventListener('click', loadWorkflow);
// ==================== RUN ANALYSIS: PANEL OPEN/CLOSE CONTROLS (START) ====================
document.getElementById('open-run').addEventListener('click', () => {
  runPanel.hidden = !runPanel.hidden;
  document.getElementById('open-run').setAttribute('aria-expanded', String(!runPanel.hidden));
  if (!runPanel.hidden) { renderRunTargets(); runSearch.focus(); }
});
document.getElementById('close-run').addEventListener('click', () => {
  runPanel.hidden = true;
  document.getElementById('open-run').setAttribute('aria-expanded', 'false');
  document.getElementById('open-run').focus();
});
// ==================== RUN ANALYSIS: PANEL OPEN/CLOSE CONTROLS (END) ====================
document.getElementById('start-run').addEventListener('click', startRun);
document.getElementById('start-live-run').addEventListener('click', startLiveRun);
document.getElementById('import-nessus').addEventListener('click', async () => {
  const status = document.getElementById('nessus-import-status');
  const button = document.getElementById('import-nessus');
  const file = document.getElementById('nessus-file').files[0];
  const target = document.getElementById('nessus-target').value.trim() || view.host;
  const newRun = document.getElementById('nessus-destination').value === 'new';
  const run = newRun ? `nessus-${Date.now()}-${crypto.randomUUID().slice(0, 8)}` : view.assessment?.run?.run_id;
  if (!run || !target || !file) { status.textContent = 'Enter an authorised target IP and choose a .nessus export.'; return; }
  if (!file.name.toLowerCase().endsWith('.nessus') || file.size > 16 * 1024 * 1024) { status.textContent = 'Choose a .nessus export smaller than 16 MB.'; return; }
  button.disabled = true;
  status.textContent = 'Checking the report and updating the assessment…';
  try {
    const response = await fetch('/api/nessus-import', {method: 'POST', headers: {
      'Content-Type': 'application/xml', 'X-VulnAssess-Action': 'nessus-import',
      'X-VulnAssess-Run': run, 'X-VulnAssess-Target': target, 'X-VulnAssess-New-Run': String(newRun),
    }, body: file});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || 'Report import failed');
    status.textContent = `${result.import.findings.nessus} Nessus findings stored; ${result.scores} priorities calculated. Opening assessment…`;
    location.href = `/workflow?run=${encodeURIComponent(result.run_id)}#host=${encodeURIComponent(target)}`;
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});
document.getElementById('preview-flow').addEventListener('click', previewLiveFlow);
document.getElementById('stop-run').addEventListener('click', () => { runState.stop = true; document.getElementById('stop-run').disabled = true; });
providerSelect.addEventListener('change', () => {
  document.getElementById('cloud-consent').hidden = providerSelect.value === 'ollama';
  document.getElementById('share-evidence').checked = false;
});
runSearch.addEventListener('input', renderRunTargets);
runTargets.addEventListener('change', event => {
  if (event.target.type !== 'checkbox') return;
  if (event.target.checked) runState.selected.add(event.target.value);
  else runState.selected.delete(event.target.value);
  renderRunTargets();
});
// ==================== RUN ANALYSIS: TARGET SCOPE CHECK (START) ====================
document.getElementById('check-target').addEventListener('click', async () => {
  const input = document.getElementById('new-target');
  const output = document.getElementById('target-check-result');
  const target = input.value.trim();
  output.textContent = 'Checking the local authorization scope and scanner availability…';
  try {
    const result = await getRecord(`/api/target-check?target=${encodeURIComponent(target)}`);
    const scanners = await getRecord('/api/scanner-status');
    const nikto = scanners.nikto.status === 'available'
      ? `Nikto executable found (${scanners.nikto.detail});`
      : `Nikto ${scanners.nikto.status}: ${scanners.nikto.detail};`;
    output.textContent = `${result.submitted || result.target}: ${result.reason}${result.missing?.length ? ` Missing: ${result.missing.join(', ')}.` : ''} ${nikto} Nessus: ${scanners.nessus.detail}`;
  } catch (error) {
    output.textContent = error.message;
  }
});
// ==================== RUN ANALYSIS: TARGET SCOPE CHECK (END) ======================
runSelect.addEventListener('change', () => { location.href = `/workflow?run=${encodeURIComponent(runSelect.value)}`; });
hostSelect.addEventListener('change', () => { view.host = hostSelect.value; view.finding = ''; populateFindings(); updateLocation(); renderGraph(); renderInspector(); });
findingSelect.addEventListener('change', () => {
  view.finding = findingSelect.value;
  if (view.finding) {
    view.host = view.assessment.findings.find(finding => finding.id === view.finding).host_ip;
    hostSelect.value = view.host;
    populateFindings();
  }
  updateLocation();
  renderGraph();
  renderInspector();
});
document.getElementById('close-node').addEventListener('click', () => {
  const identity = view.node;
  view.node = '';
  inspector.hidden = true;
  updateLocation();
  renderGraph();
  fit();
  document.querySelector(`[data-node="${identity}"]`)?.focus({preventScroll: true});
});
for (const button of document.querySelectorAll('[data-view-mode]')) button.addEventListener('click', () => {
  view.modeChosen = true;
  setViewMode(button.dataset.viewMode);
});
narrowViewport.addEventListener('change', event => { if (!view.modeChosen) setViewMode(event.matches ? 'stages' : 'canvas'); });
document.getElementById('fit-workflow').addEventListener('click', fit);
document.getElementById('reset-layout').addEventListener('click', () => {
  view.layout = {};
  try { localStorage.removeItem(layoutKey); } catch { /* The in-memory layout is still reset. */ }
  renderGraph();
  fit();
  document.getElementById('workflow-announcement').textContent = 'Workflow layout reset.';
});
document.getElementById('zoom-in').addEventListener('click', () => zoom(1.2));
document.getElementById('zoom-out').addEventListener('click', () => zoom(1 / 1.2));
let drag = null;
viewport.addEventListener('pointerdown', event => {
  if (view.mode !== 'canvas' || event.button !== 0) return;
  const button = event.target.closest('.flow-node');
  if (!button && event.target.closest('button, a, select, input')) return;
  const node = button && positionNodes(NODE_SPECS, view.layout).find(item => item.id === button.dataset.node);
  drag = {pointer: event.pointerId, x: event.clientX, y: event.clientY, panX: view.panX, panY: view.panY, node, moved: false};
  if (!node) viewport.setPointerCapture(event.pointerId);
  viewport.classList.add(node ? 'arranging' : 'panning');
});
viewport.addEventListener('pointermove', event => {
  if (!drag || drag.pointer !== event.pointerId) return;
  const dx = event.clientX - drag.x;
  const dy = event.clientY - drag.y;
  if (drag.node) {
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    if (!drag.moved) viewport.setPointerCapture(event.pointerId);
    drag.moved = true;
    view.layout = moveNode(view.layout, drag.node.id, drag.node.x + dx / view.scale, drag.node.y + dy / view.scale, SIZE);
    renderGraph();
  } else {
    view.panX = drag.panX + dx;
    view.panY = drag.panY + dy;
    transform();
  }
});
function stopDrag() {
  if (drag?.node && drag.moved) {
    saveLayout();
    document.getElementById('workflow-announcement').textContent = `${drag.node.title} moved. Layout saved.`;
  }
  drag = null;
  viewport.classList.remove('panning', 'arranging');
}
viewport.addEventListener('pointerup', stopDrag);
viewport.addEventListener('pointercancel', stopDrag);
viewport.addEventListener('wheel', event => {
  if (view.mode !== 'canvas' || event.target.closest('select')) return;
  event.preventDefault();
  if (event.ctrlKey || event.metaKey) {
    const rect = viewport.getBoundingClientRect();
    zoom(event.deltaY < 0 ? 1.1 : 1 / 1.1, {x: event.clientX - rect.left, y: event.clientY - rect.top});
  } else { view.panX -= event.deltaX; view.panY -= event.deltaY; transform(); }
}, {passive: false});
viewport.addEventListener('keydown', event => {
  if (view.mode !== 'canvas' || event.target !== viewport) return;
  const offsets = {ArrowLeft: [60, 0], ArrowRight: [-60, 0], ArrowUp: [0, 60], ArrowDown: [0, -60]};
  if (offsets[event.key]) { event.preventDefault(); view.panX += offsets[event.key][0]; view.panY += offsets[event.key][1]; transform(); }
  if (event.key === '+' || event.key === '=') { event.preventDefault(); zoom(1.2); }
  if (event.key === '-') { event.preventDefault(); zoom(1 / 1.2); }
  if (event.key === '0') { event.preventDefault(); fit(); }
});
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !inspector.hidden) document.getElementById('close-node').click(); });
window.addEventListener('resize', () => liveState.active ? fitPreviewPath() : fit());
new ResizeObserver(() => {
  if (viewport.clientHeight > 0) liveState.active ? fitPreviewPath() : fit();
}).observe(viewport);
setViewMode(view.mode);
loadWorkflow();
