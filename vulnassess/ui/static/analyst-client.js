export function validateAnalystResponse(result, runId, hostIp) {
  const analysis = result?.analysis;
  if (result?.run_id !== runId || result?.host_ip !== hostIp || result?.canonical_scores_changed !== false
      || typeof result.model !== 'string' || !Array.isArray(result.evidence)
      || typeof analysis?.summary !== 'string' || !['low', 'medium', 'high'].includes(analysis.confidence)
      || !Array.isArray(analysis.recommended_actions) || !Array.isArray(analysis.correlations)
      || !Array.isArray(analysis.uncertainties)) {
    throw new Error('Analyst response does not match the requested system or score boundary.');
  }
  const evidenceIds = new Set();
  for (const item of result.evidence) {
    if (!item || typeof item.id !== 'string' || typeof item.text !== 'string' || evidenceIds.has(item.id)) {
      throw new Error('Analyst response contains invalid evidence references.');
    }
    evidenceIds.add(item.id);
  }
  const validCitations = item => Array.isArray(item.evidence_ids)
    && item.evidence_ids.every(identity => evidenceIds.has(identity))
    && Array.isArray(item.finding_ids) && item.finding_ids.every(identity => typeof identity === 'string');
  if (analysis.recommended_actions.some(item => !item || typeof item.action !== 'string'
      || typeof item.reason !== 'string' || !Number.isInteger(item.order) || item.order < 1 || !validCitations(item))
      || analysis.correlations.some(item => !item || typeof item.observation !== 'string' || !validCitations(item))
      || analysis.uncertainties.some(item => typeof item !== 'string')) {
    throw new Error('Analyst response contains invalid or uncited content.');
  }
  return result;
}

export async function requestAnalyst(runId, hostIp) {
  const response = await fetch(`/api/analyst/${encodeURIComponent(runId)}/${encodeURIComponent(hostIp)}`, {
    cache: 'no-store', credentials: 'same-origin',
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error?.message || 'Local analyst request failed.');
  return validateAnalystResponse(body, runId, hostIp);
}

export async function requestAnalystProgress(runId, hostIp, onProgress = () => {}, provider = 'ollama') {
  if (!['ollama', 'openrouter', 'groq'].includes(provider)) throw new Error('Unknown analyst provider.');
  const cloud = provider !== 'ollama';
  const response = await fetch(`/api/analyst/${encodeURIComponent(runId)}/${encodeURIComponent(hostIp)}/events`, {
    cache: 'no-store', credentials: 'same-origin',
    ...(cloud ? {method: 'POST', headers: {'Content-Type': 'application/json', 'X-VulnAssess-Action': 'cloud-analyst'}, body: JSON.stringify({provider, share_evidence: true})} : {}),
  });
  if (!response.ok) {
    const failure = await response.json().catch(() => null);
    throw new Error(failure?.error?.message || 'Live analyst request is unavailable.');
  }
  if (!response.body) throw new Error('Live analyst progress is unavailable.');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let result = null;
  const accept = line => {
    if (!line) return;
    const event = JSON.parse(line);
    if (event.type === 'stage') {
      if (typeof event.stage !== 'string' || !['running', 'complete'].includes(event.state)
          || typeof event.detail !== 'string') throw new Error('Invalid analyst progress event.');
      onProgress(event);
    } else if (event.type === 'result') {
      result = validateAnalystResponse(event.result, runId, hostIp);
    } else if (event.type === 'needs-review') {
      const failure = new Error(typeof event.message === 'string' ? event.message : 'Needs review: analyst output was rejected.');
      failure.name = 'NeedsReviewError';
      throw failure;
    } else if (event.type === 'error') {
      throw new Error(typeof event.message === 'string' ? event.message : 'Local analysis failed.');
    } else {
      throw new Error('Unknown analyst progress event.');
    }
  };
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, {stream: true});
      if (buffer.length > 2_000_000) throw new Error('Analyst progress response exceeded its size limit.');
      let boundary;
      while ((boundary = buffer.indexOf('\n')) !== -1) {
        accept(buffer.slice(0, boundary));
        buffer = buffer.slice(boundary + 1);
      }
    }
    buffer += decoder.decode();
    accept(buffer);
    if (!result) throw new Error('Local analysis ended before returning a validated result.');
    return result;
  } finally {
    if (!result) await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function createAnalysisQueue({request = requestAnalyst, onChange = () => {}} = {}) {
  let state = {busy: false, stopRequested: false, stopReason: '', runId: null, entries: []};
  const snapshot = () => ({...state, entries: state.entries.map(entry => ({...entry}))});
  const publish = () => onChange(snapshot());
  return {
    snapshot,
    stopAfterCurrent() {
      if (!state.busy) return false;
      state.stopRequested = true;
      state.stopReason = 'Stopped by request; this system was not started.';
      publish();
      return true;
    },
    async start(runId, hosts) {
      if (state.busy) throw new Error('An analysis request is already in progress.');
      if (typeof runId !== 'string' || !runId || !Array.isArray(hosts) || !hosts.length
          || hosts.some(host => typeof host !== 'string' || !host) || new Set(hosts).size !== hosts.length) {
        throw new Error('Choose an existing assessment and distinct recorded systems.');
      }
      state = {
        busy: true, stopRequested: false, stopReason: '', runId,
        entries: hosts.map(hostIp => ({hostIp, status: 'queued', result: null, error: null})),
      };
      try {
        publish();
        for (const entry of state.entries) {
          if (state.stopRequested) {
            entry.status = 'not-run';
            entry.error = state.stopReason;
            continue;
          }
          entry.status = 'running';
          publish();
          try {
            entry.result = validateAnalystResponse(await request(runId, entry.hostIp), runId, entry.hostIp);
            entry.status = 'complete';
          } catch (error) {
            entry.status = 'error';
            entry.error = error instanceof Error ? error.message : 'Local analysis failed.';
            state.stopRequested = true;
            state.stopReason = 'Not started because an earlier request failed.';
          }
          publish();
        }
      } finally {
        state.busy = false;
        publish();
      }
      return snapshot();
    },
  };
}
