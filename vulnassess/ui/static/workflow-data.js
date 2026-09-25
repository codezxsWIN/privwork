export const SIZE = Object.freeze({width: 1500, height: 740});

export const NODE_SPECS = Object.freeze([
  {id: 'scope', title: 'Target & scope', subtitle: 'Permission boundary', icon: 'target', x: 100, y: 365, group: 'source'},
  {id: 'nmap', title: 'Nmap', subtitle: 'Ports & services', icon: 'radar', x: 270, y: 170, group: 'source'},
  {id: 'nessus', title: 'Nessus report', subtitle: 'Imported network findings', icon: 'browser', x: 270, y: 365, group: 'source'},
  {id: 'nikto', title: 'Nikto', subtitle: 'Web server findings', icon: 'terminal', x: 270, y: 560, group: 'source'},
  {id: 'canonical', title: 'Normalize & store', subtitle: 'Canonical finding records', icon: 'merge', x: 465, y: 365, group: 'transform'},
  {id: 'nvd', title: 'NVD', subtitle: 'CVEs & CVSS vectors', icon: 'database', x: 600, y: 90, group: 'intel'},
  {id: 'epss', title: 'EPSS', subtitle: 'Exploitation evidence', icon: 'chart', x: 770, y: 90, group: 'intel'},
  {id: 'kev', title: 'CISA KEV', subtitle: 'Known exploitation', icon: 'flag', x: 940, y: 90, group: 'intel'},
  {id: 'intel', title: 'Enrich findings', subtitle: 'CVE matches & feed dates', icon: 'link', x: 770, y: 275, group: 'transform'},
  {id: 'context', title: 'Infer context', subtitle: 'Role · exposure · controls', icon: 'layers', x: 770, y: 550, group: 'transform'},
  {id: 'shadow', title: 'Role classifier', subtitle: 'Optional learned evidence', icon: 'model', x: 465, y: 590, group: 'optional'},
  {id: 'score', title: 'Calculate risk', subtitle: 'CVSS Environmental + threat', icon: 'formula', x: 985, y: 365, group: 'decision'},
  {id: 'queue', title: 'Prioritize', subtitle: 'Stored risk order', icon: 'queue', x: 1175, y: 365, group: 'decision'},
  {id: 'rationale', title: 'Explain the score', subtitle: 'Recorded reason & rationale', icon: 'text', x: 1175, y: 165, group: 'output'},
  {id: 'report', title: 'Assessment report', subtitle: 'Findings & provenance', icon: 'report', x: 1390, y: 165, group: 'output'},
  {id: 'analyst', title: 'Local AI analyst', subtitle: 'Cited target assessment', icon: 'model', x: 1175, y: 590, group: 'optional'},
  {id: 'evaluation', title: 'Expert evaluation', subtitle: 'Agreement & critical queue', icon: 'compare', x: 1390, y: 365, group: 'optional'},
  {id: 'rescan', title: 'Re-scan comparison', subtitle: 'Comparable evidence required', icon: 'repeat', x: 1390, y: 590, group: 'optional'},
]);

export const EDGES = Object.freeze([
  {from: 'scope', to: 'nmap'}, {from: 'scope', to: 'nessus'}, {from: 'scope', to: 'nikto'},
  {from: 'nmap', to: 'canonical'}, {from: 'nessus', to: 'canonical'}, {from: 'nikto', to: 'canonical'},
  {from: 'canonical', to: 'intel'}, {from: 'canonical', to: 'context'},
  {from: 'nvd', to: 'intel'}, {from: 'epss', to: 'intel'}, {from: 'kev', to: 'intel'},
  {from: 'canonical', to: 'shadow', optional: true}, {from: 'shadow', to: 'context', optional: true},
  {from: 'intel', to: 'score'}, {from: 'context', to: 'score'},
  {from: 'score', to: 'queue'}, {from: 'score', to: 'rationale'},
  {from: 'rationale', to: 'report'}, {from: 'queue', to: 'report'},
  {from: 'queue', to: 'evaluation', optional: true},
  {from: 'queue', to: 'analyst', optional: true},
  {from: 'queue', to: 'rescan', optional: true},
]);

export const ICONS = Object.freeze({
  target: ['M12 3v4m0 10v4M3 12h4m10 0h4', 'M12 5a7 7 0 1 0 0 14 7 7 0 0 0 0-14', 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6'],
  radar: ['M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l7-7', 'M12 3v9h9'],
  browser: ['M3 5h18v15H3ZM3 9h18M6 7h.1M9 7h.1M8 13l-2 2 2 2m8-4 2 2-2 2'],
  terminal: ['M3 5h18v15H3ZM7 10l3 3-3 3m6 0h4'],
  merge: ['M3 5h4l5 7 5-7h4M3 19h4l5-7h9M18 9l3 3-3 3'],
  database: ['M4 6c0-4 16-4 16 0s-16 4-16 0Zm0 0v12c0 4 16 4 16 0V6M4 12c0 4 16 4 16 0'],
  chart: ['M4 4v16h17M8 16v-4m5 4V8m5 8V5'],
  flag: ['M5 21V3h13l-3 5 3 5H5'],
  link: ['m10 8 3-3a4 4 0 0 1 6 6l-3 3m-2 2-3 3a4 4 0 0 1-6-6l3-3m1 5 6-6'],
  layers: ['m12 3 10 5-10 5L2 8 10-5Zm-10 9 10 5 10-5M2 16l10 5 10-5'],
  model: ['M8 4h8l4 8-4 8H8l-4-8 4-8ZM8 4l8 16M16 4 8 20M4 12h16'],
  formula: ['M6 4h12M6 20h12M17 4 8 12l9 8'],
  queue: ['M8 5h13M8 12h9M8 19h5M3 5h.1M3 12h.1M3 19h.1'],
  text: ['M4 4h16v13H9l-5 4V4Zm4 5h8M8 13h5'],
  report: ['M6 2h9l4 4v16H6V2Zm8 0v5h5M9 11h7m-7 4h7m-7 4h4'],
  compare: ['M5 4v16M19 4v16M8 8h8m-3-3 3 3-3 3M16 16H8m3-3-3 3 3 3'],
  repeat: ['M20 9a8 8 0 0 0-14-3L3 9m0-6v6h6M4 15a8 8 0 0 0 14 3l3-3m0 6v-6h-6'],
});

function recordState(records, yes = 'Stored records') {
  return records.length ? {state: 'stored', status: yes} : {state: 'missing', status: 'No stored output'};
}

export function currentSlice(assessment, hostIp = '', findingId = '') {
  const selectedHost = hostIp || assessment.findings.find(finding => finding.id === findingId)?.host_ip || '';
  const hosts = assessment.hosts.filter(host => !selectedHost || host.ip === selectedHost);
  const findings = assessment.findings.filter(finding => (!selectedHost || finding.host_ip === selectedHost) && (!findingId || finding.id === findingId));
  const identities = new Set(findings.map(finding => finding.id));
  const hostAddresses = new Set(hosts.map(host => host.ip));
  return {
    hosts, findings,
    scores: assessment.scores.filter(score => identities.has(score.finding_id)),
    enrichments: assessment.enrichments.filter(item => identities.has(item.finding_id)),
    profiles: assessment.context.filter(profile => hostAddresses.has(profile.host_ip)),
    rationales: assessment.rationales.filter(item => identities.has(item.finding_id)),
  };
}

export function buildNodes(assessment, scope, selection = {}, analysis = null) {
  const slice = currentSlice(assessment, selection.host, selection.finding);
  const contextHasLearnedSource = slice.profiles.some(profile => profile.role?.source === 'llm');
  const hasSource = tool => slice.findings.some(finding => finding.tool === tool)
    || (assessment.run.summary.imports || []).some(item => (!selection.host || item.target_ip === selection.host) && Object.hasOwn(item.findings || {}, tool));
  const states = {
    scope: scope ? {state: 'configured', status: 'Current configuration'} : {state: 'missing', status: 'Configuration missing'},
    canonical: recordState(slice.findings), intel: recordState(slice.enrichments, 'Matches stored'),
    context: recordState(slice.profiles, 'Context stored'),
    shadow: {state: 'optional', status: contextHasLearnedSource ? 'Learned role recorded' : 'Not run in viewer'},
    score: recordState(slice.scores, 'Scores stored'), queue: recordState(slice.scores, 'Stored order'),
    rationale: recordState(slice.rationales.length ? slice.rationales : slice.scores.filter(item => item.reason), 'Reasons stored'),
    report: {state: 'optional', status: 'Artifact not attached'}, analyst: {state: 'optional', status: 'Not run'},
    evaluation: {state: 'optional', status: 'No result attached'}, rescan: {state: 'optional', status: 'No comparison attached'},
  };
  for (const tool of ['nmap', 'nessus', 'nikto']) states[tool] = hasSource(tool) ? {state: 'stored', status: tool === 'nessus' ? 'Report imported' : 'Scanner evidence stored'} : {state: 'missing', status: tool === 'nessus' ? 'No .nessus report imported' : 'No scan evidence recorded'};
  for (const feed of ['nvd', 'epss', 'kev']) states[feed] = recordState(assessment.feeds_meta.filter(item => item.feed === feed), 'Snapshot loaded');
  if (analysis && analysis.runId === assessment.run.run_id && analysis.hostIp === selection.host) {
    const activeStage = {
      records: 'Reading assessment', model: 'Checking model', evidence: 'Gathering evidence', prompt: 'Preparing request',
      generation: 'Generating response', validation: 'Validating citations',
    }[analysis.stage] || 'Starting local analysis';
    states.analyst = analysis.status === 'complete' ? {state: 'live', status: 'Response received'}
      : analysis.status === 'running' ? {state: 'running', status: activeStage} : {state: 'error', status: analysis.status === 'needs_review' ? 'Needs review' : 'Request failed'};
  }
  return NODE_SPECS.map(spec => ({...spec, ...states[spec.id]}));
}

export function connectedNodeIds(identity) {
  return new Set([identity, ...EDGES.filter(edge => edge.from === identity || edge.to === identity).flatMap(edge => [edge.from, edge.to])]);
}

function quotesFromFeatures(profile) {
  return [['Role', profile.role], ['Exposure', profile.exposure], ...Object.entries(profile.controls || {}), ...Object.entries(profile.manual || {})]
    .filter(([, feature]) => feature).map(([name, feature]) => {
      const legacyUnknown = Object.hasOwn(profile.controls || {}, name) && feature.value === false && feature.source === 'rule' && feature.evidence === 'none observed';
      return {label: name.replaceAll('_', ' '), value: legacyUnknown || feature.value === null ? 'Unknown' : feature.value, confidence: legacyUnknown ? 0 : feature.confidence, source: feature.source, quote: feature.evidence};
    });
}

export function evidenceBasis(assessment, hostIp) {
  const host = (assessment?.hosts || []).find(item => item.ip === hostIp);
  const profile = (assessment?.context || []).find(item => item.host_ip === hostIp);
  if (!host || !profile) return null;
  const imports = (assessment.run?.summary?.imports || []).filter(item => item.target_ip === hostIp);
  const findings = (assessment.findings || []).filter(item => item.host_ip === hostIp);
  const hasTool = tool => imports.some(item => Object.hasOwn(item.findings || {}, tool)) || findings.some(item => item.tool === tool);
  const notChecked = [];
  for (const [tool, name] of [['nessus', 'Nessus'], ['nikto', 'Nikto']]) {
    if (!hasTool(tool)) notChecked.push(`No ${name} evidence attached; its coverage is unknown.`);
  }
  for (const [key, label] of [['waf', 'WAF'], ['auth_required', 'Authentication'], ['rate_limiting', 'Rate limiting'], ['tls', 'TLS']]) {
    const feature = profile.controls?.[key];
    if (!feature || feature.value === null || (feature.value === false && feature.source === 'rule' && feature.evidence === 'none observed')) {
      notChecked.push(`${label} presence was not established by the attached evidence.`);
    }
  }
  if (!findings.length) notChecked.push('No vulnerability findings were recorded; this does not prove the target is vulnerability-free.');
  return {
    observed: (host.services || []).map(service => `${service.port}/${service.protocol} ${service.name || 'service'}${service.product ? ` · ${service.product}` : ''}${service.version ? ` ${service.version}` : ''}`),
    context: [
      `Role inferred from evidence: ${String(profile.role?.value || 'unknown').replaceAll('_', ' ')}.`,
      `Exposure inferred from scope/address: ${String(profile.exposure?.value || 'unknown').replaceAll('_', ' ')}. This guides verification priority, not vulnerability certainty.`,
    ],
    notChecked,
    nextVerification: 'Review intended exposure and validate observed service configuration using authorised tests.',
  };
}

export function nodeDetails(identity, assessment, scope, weights, selection = {}, analysis = null) {
  const slice = currentSlice(assessment, selection.host, selection.finding);
  const base = {rows: [], quotes: [], records: [], message: '', provenance: ''};
  const findingQuotes = slice.findings.map(finding => ({label: `${finding.tool} / ${finding.title}`, quote: finding.evidence, source: finding.provenance.raw_path}));
  if (identity === 'scope') return {...base, input: 'Target addresses', operation: 'Check current lab configuration before any import or scanner command.', output: 'Explicit target boundary',
    rows: (scope?.values.lab_targets || []).map(target => ({label: target.name, value: target.ip})), records: scope ? [scope] : [],
    message: 'This shows configuration, not proof of a past safety check or canary request count.', provenance: 'config/scope.yaml'};
  if (['nmap', 'nessus', 'nikto'].includes(identity)) {
    const imports = (assessment.run.summary.imports || []).filter(item => (!selection.host || item.target_ip === selection.host) && Object.hasOwn(item.findings || {}, identity));
    const findings = slice.findings.filter(finding => finding.tool === identity);
    return {...base, input: identity === 'nessus' ? 'Completed .nessus XML export' : 'Scanner artifact', operation: 'Scope-checked import; retain the native identity and original evidence.', output: 'Stored observations',
      rows: imports.flatMap(item => [{label: 'Recorded target', value: item.target_ip}, {label: 'Stored import counter', value: item.findings[identity]}]),
      quotes: findings.map(finding => ({label: finding.title, quote: finding.evidence, source: finding.provenance.raw_path})), records: findings,
      message: identity === 'nessus' ? 'Nessus runs separately. Import its completed .nessus XML export for an authorized target to populate this path. A zero-finding import still records coverage.' : 'The quick live button does not launch this scanner. Scanner artifacts retain their source and run.', provenance: `readers/${identity === 'nmap' ? 'nmap_xml' : identity === 'nessus' ? 'nessus_xml' : 'nikto_json'}.py`};
  }
  if (identity === 'canonical') return {...base, input: 'Scanner-native findings', operation: 'Normalize identities and provenance into the canonical schema, then persist records in SQLite.', output: 'One inspectable record per finding',
    rows: slice.findings.map(finding => ({label: finding.tool_native_id, value: finding.id})), quotes: findingQuotes, records: slice.findings,
    message: 'Exact finding identity is retained. Preview grouping does not silently merge the ranking queue.', provenance: 'schema.py / store.py'};
  if (['nvd', 'epss', 'kev'].includes(identity)) {
    const metadata = assessment.feeds_meta.find(feed => feed.feed === identity);
    const labels = {nvd: ['Vulnerability catalog', 'CVEs and CVSS vectors'], epss: ['Exploitation predictions', 'Per-CVE probability and percentile'], kev: ['Known exploitation catalog', 'CVE membership and recorded date']};
    return {...base, input: labels[identity][0], operation: 'Read a human-provided local feed snapshot.', output: labels[identity][1],
      rows: metadata ? [{label: 'Snapshot date', value: metadata.file_date}, {label: 'Rows stored', value: metadata.rows}, {label: 'SHA-256', value: metadata.sha256}, {label: 'Local path', value: metadata.path}] : [],
      records: metadata ? [metadata] : [], message: 'Feed metadata is current store state, not a frozen per-run snapshot. Nothing is downloaded.', provenance: 'intel.py / feeds_meta'};
  }
  if (identity === 'intel') return {...base, input: 'Finding identity + dated feed facts', operation: 'Match explicit CVEs or supported CPE version ranges. Preserve unmatched findings.', output: 'Stored enrichment records',
    rows: slice.enrichments.flatMap(item => [{label: 'CVE', value: item.cve_id}, {label: 'Match method', value: item.match_method}, {label: 'Match confidence', value: item.match_confidence}, {label: 'EPSS percentile', value: item.epss_percentile}, {label: 'KEV', value: item.kev}]), records: slice.enrichments,
    message: slice.enrichments.length ? 'These are stored matches; loading this diagram does not rematch records.' : 'No enrichment stored for this selection. A native-severity fallback may still be recorded.', provenance: 'intel.py / enrichments'};
  if (identity === 'context') return {...base, input: 'Services, scanner evidence and scope tags', operation: 'Retain the role, exposure and controls that the context pipeline recorded, including their source and confidence.', output: 'Deployment context',
    quotes: slice.profiles.flatMap(profile => quotesFromFeatures(profile).map(item => ({...item, label: `${profile.host_ip} / ${item.label}`}))), records: slice.profiles,
    message: 'Source labels show rule, manual or learned provenance. Older rule records encoded “none observed” as false; this view interprets those controls as unknown without rewriting the raw record.', provenance: 'context.py / context_profiles'};
  if (identity === 'shadow') return {...base, input: 'Host service features', operation: 'The optional local role classifier predicts a role from scan-derived features. Its use belongs to pipeline configuration.', output: 'Optional learned role evidence', records: slice.profiles.filter(profile => profile.role?.source === 'llm'),
    message: 'The graph does not run this classifier. A recorded learned-source role is shown as recorded, not claimed to be a fresh prediction.', provenance: 'role_model.py / context.py'};
  if (identity === 'score') return {...base, input: 'Context + CVSS + EPSS + KEV', operation: 'Apply the published deterministic formula and configuration. This is arithmetic, not an LLM judgment.', output: 'Stored score breakdown',
    rows: slice.scores.flatMap(score => [{label: 'Host', value: score.host_ip}, {label: 'Base score', value: score.base_score}, {label: 'Environmental', value: score.env_score}, {label: 'Threat multiplier', value: score.threat_multiplier}, {label: 'Risk', value: score.risk}, {label: 'Band', value: score.band}, {label: 'Weights hash', value: score.weights_hash}]),
    quotes: slice.scores.filter(score => score.env_vector).map(score => ({label: 'Environmental vector', quote: score.env_vector, source: score.finding_id})), records: slice.scores,
    message: 'Values are copied from stored scores. The current config may differ from the historical score inputs.', provenance: 'scoring.py / cvss31.py'};
  if (identity === 'queue') return {...base, input: 'Stored score rows', operation: 'Use the risk-descending order and stable finding identity already returned by the store.', output: 'Prioritized findings',
    rows: slice.scores.map(score => ({label: `${score.host_ip} / ${score.cve_id || score.finding_id}`, value: `${score.risk} · ${score.band}`})), records: slice.scores,
    message: 'Risk is not model confidence. The diagram does not alter the order.', provenance: 'store.py / scores'};
  if (identity === 'rationale') return {...base, input: 'Validated score inputs and context', operation: 'Read the deterministic reason and any separately stored rationale with its provenance.', output: 'Recorded explanation',
    quotes: [...slice.scores.filter(score => score.reason).map(score => ({label: 'Deterministic reason', quote: score.reason, source: score.finding_id})), ...slice.rationales.map(item => ({label: item.source, quote: item.text, source: item.finding_id}))], records: slice.rationales,
    message: 'The optional live target analyst below is a different operation, not the scorer.', provenance: 'scoring.describe / explain.py'};
  if (identity === 'analyst') {
    const response = analysis?.runId === assessment.run.run_id && analysis?.hostIp === selection.host ? analysis : null;
    return {...base, input: 'Selected host, findings, context, scores and cited evidence', operation: 'An explicit Analyze target request calls the selected analyst provider and validates its structured response.', output: 'Model-written assessment with citations',
      rows: response?.result ? [{label: 'Model', value: response.result.model}, {label: 'Response source', value: response.result.source}, {label: 'Advisory confidence', value: response.result.analysis?.confidence}, {label: 'Scores changed', value: response.result.canonical_scores_changed}] : [], records: response?.result ? [response.result] : [],
      message: ['error', 'needs_review'].includes(response?.status) ? response.error : 'No model runs when this page opens or when nodes are selected. An AI response never feeds back into risk scoring.', provenance: 'analyst.analyze_target / selected provider'};
  }
  if (identity === 'report') return {...base, input: 'Priorities, explanations and provenance', operation: 'The CLI can produce a report or an offline viewer export from these records.', output: 'Shareable assessment artifact',
    rows: [{label: 'Selected run', value: assessment.run.run_id}], message: 'A report artifact is not attached to this API payload; its existence is not inferred from a scored run.', provenance: 'pipeline.do_report / report.py / ui export'};
  if (identity === 'evaluation') return {...base, input: 'Stored rankings + independently supplied expert judgments', operation: 'Compare with CVSS-only and CVSS+EPSS baselines using the research harness.', output: 'Agreement and critical-queue results',
    message: 'No persisted evaluation is attached. Tau-b, NDCG and Kendall\'s W are not calculated or invented by this visualization.', provenance: 'evaluate.py / cohort.py / experiments.py'};
  return {...base, input: 'Two comparable recorded observations', operation: 'Compare coverage and finding identity; missing evidence alone is not a confirmed fix.', output: 'Candidate change states for human review',
    message: 'No re-scan observation artifacts are attached. This node is not a scanner command or proof of remediation.', provenance: 'diff.py / rescan.py'};
}

export function evidenceKind(assessment) {
  const paths = assessment.findings.map(finding => finding.provenance.raw_path);
  return paths.some(path => String(path).toLowerCase().includes('synthetic')) ? 'SYNTHETIC INPUTS' : 'STORED ASSESSMENT';
}
