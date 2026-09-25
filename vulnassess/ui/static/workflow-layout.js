const NODE_HALF_WIDTH = 82;
const NODE_TOP = 49;
const NODE_BOTTOM = 130;

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

export function moveNode(layout, id, x, y, size) {
  return {
    ...layout,
    [id]: {
      x: clamp(Math.round(x), NODE_HALF_WIDTH, size.width - NODE_HALF_WIDTH),
      y: clamp(Math.round(y), NODE_TOP, size.height - NODE_BOTTOM),
    },
  };
}

export function readLayout(raw, specs, size) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const result = {};
  for (const {id} of specs) {
    const point = raw[id];
    if (point && Number.isFinite(point.x) && Number.isFinite(point.y)) {
      result[id] = moveNode({}, id, point.x, point.y, size)[id];
    }
  }
  return result;
}

export function positionNodes(nodes, layout) {
  return nodes.map(node => ({...node, ...(layout[node.id] || {})}));
}

export function pathNodeIds(steps, fallback) {
  const ids = steps.flatMap(step => [step.node, ...(step.edges || []).flatMap(edge => edge.split(':'))]).filter(Boolean);
  return new Set(ids.length ? ids : fallback);
}
