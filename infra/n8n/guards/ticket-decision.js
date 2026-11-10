// Pure offline decision node. No HTTP, credentials, static data or target calls.
function decide(input) {
  const out = (decision, reason, extra = {}) => ({
    version: 1, decision, reason, allow_target_call: false,
    automatic_retry: false, ...extra,
  });
  const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
  const str = x => typeof x === 'string' && x.length > 0 && x.length <= 300 && !/[\x00-\x1f\x7f]/.test(x);
  const tid = x => typeof x === 'string' && /^T-[0-9]{8}-[0-9]{4}$/.test(x);
  const statuses = ['open', 'responding', 'verified', 'restored', 'closed'];
  const vias = ['portal', 'wazuh-ar', 'pfsense', 'manual'];
  const actionName = x => typeof x === 'string' && /^[a-z][a-z_]{1,31}$/.test(x);
  const bot = x => typeof x === 'string' && /^([0-9]{3}|manual)$/.test(x);
  const fields = ['asset_id', 'via', 'action', 'target'];
  const resource = x => obj(x) && Object.keys(x).length === 4 &&
    str(x.asset_id) && str(x.target) && vias.includes(x.via) && actionName(x.action);
  const same = (a, b) => fields.every(k => a[k] === b[k]);
  const ref = x => obj(x) && bot(x.bot) && vias.includes(x.via) && actionName(x.action) && str(x.target);
  if (!obj(input) || !['apply', 'release', 'record_response'].includes(input.mode))
    return out('hold', 'invalid_input');
  const expected = input.expected, observation = input.observation;
  if (!obj(expected) || !obj(observation)) return out('hold', 'invalid_input');
  // observation is supplied by a future HTTP adapter, not proof of a live call.
  if (input.mode !== 'record_response' &&
      (!resource(expected.resource) || !['A', 'B', 'C', 'D'].includes(expected.seat)))
    return out('hold', 'invalid_scope');
  if (observation.transport_error === true || observation.status == null)
    return out('hold', input.mode === 'record_response' ? 'reconcile_record_same_request' : 'store_unavailable');
  const body = observation.body;
  if (input.mode === 'record_response') {
    if (!tid(expected.ticket_id) && expected.ticket_id !== null) return out('hold', 'invalid_scope');
    if (observation.status === 409 && obj(body) && body.ok === false && obj(body.error)) {
      if (body.error.code === 'IDEMPOTENCY_CONFLICT') return out('hold', 'resolve_key_body_conflict');
      if (body.error.code === 'INVALID_TRANSITION') return out('hold', 'resolve_cycle_or_asset_scope');
    }
    if (Number.isInteger(observation.status) && observation.status >= 500)
      return out('hold', 'reconcile_record_same_request');
    if (![200, 201].includes(observation.status) || !obj(body) || body.ok !== true ||
        !tid(body.ticket_id) || !statuses.includes(body.status) ||
        typeof body.created !== 'boolean' || typeof body.duplicate !== 'boolean' ||
        (expected.ticket_id !== null && body.ticket_id !== expected.ticket_id))
      return out('hold', 'invalid_record_response');
    return out('record_acknowledged', 'effect_not_inferred', {ticket_id: body.ticket_id});
  }
  if (observation.status !== 200 || !obj(body) || body.ok !== true)
    return out('hold', 'store_query_failed');
  if (input.mode === 'apply') {
    const query = observation.query;
    if (!str(expected.group_key) || !bot(expected.bot) || !obj(query) ||
        query.seat !== expected.seat || query.group_key !== expected.group_key || Object.keys(query).length !== 2)
      return out('hold', 'query_scope_mismatch');
    if (typeof body.exists !== 'boolean' || !Array.isArray(body.applied_actions) ||
        !body.applied_actions.every(a => ref(a) && ['applied', 'already_applied'].includes(a.result)))
      return out('hold', 'invalid_open_response');
    if (!body.exists) {
      if (body.ticket_id !== null || body.status !== null || body.applied_actions.length !== 0)
        return out('hold', 'invalid_open_response');
      return out('apply_candidate', 'no_open_ticket_snapshot');
    }
    if (!tid(body.ticket_id) || !statuses.slice(0, 4).includes(body.status))
      return out('hold', 'invalid_open_response');
    if (body.status === 'restored') return out('hold', 'close_restored_before_new_cycle');
    const r = expected.resource;
    if (body.applied_actions.some(a => a.bot === expected.bot && a.via === r.via &&
        a.action === r.action && a.target === r.target))
      return out('skip_active', 'matching_active_action', {ticket_id: body.ticket_id});
    return out('apply_candidate', 'no_matching_active_action_snapshot', {ticket_id: body.ticket_id});
  }
  if (!tid(expected.owner_ticket_id) || !resource(observation.query) || !same(observation.query, expected.resource) ||
      !resource(body.resource) || !same(body.resource, expected.resource))
    return out('hold', 'query_scope_mismatch');
  if (!Array.isArray(body.tickets)) return out('hold', 'invalid_active_response');
  const seen = new Set();
  for (const t of body.tickets) {
    if (!obj(t) || !tid(t.ticket_id) || seen.has(t.ticket_id) || !['A', 'B', 'C', 'D'].includes(t.seat) ||
        !statuses.includes(t.status) || !Array.isArray(t.active_actions) || t.active_actions.length === 0 ||
        !t.active_actions.every(a => ref(a) && ['via', 'action', 'target'].every(k => a[k] === expected.resource[k])))
      return out('hold', 'invalid_active_response');
    seen.add(t.ticket_id);
  }
  const own = body.tickets.find(t => t.ticket_id === expected.owner_ticket_id);
  if (own && own.seat !== expected.seat) return out('hold', 'owner_seat_mismatch');
  const others = body.tickets.filter(t => t.ticket_id !== expected.owner_ticket_id);
  if (others.length) return out('hold', 'other_active_claims', {blocking_ticket_ids: others.map(t => t.ticket_id)});
  if (!own) return out('hold', body.tickets.length ? 'owner_claim_missing' : 'no_recorded_claims');
  if (own.status === 'closed') return out('hold', 'closed_claim_needs_reconciliation');
  return out('release_candidate', 'owner_only_snapshot_requires_serialization');
}

return $input.all().map(item => ({json: decide(item.json)}));
