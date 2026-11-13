import { CytoscapeElement } from './types';
import { ExperimentalResponse } from './experimentalState';

export type ExperimentalBranch = 'rag' | 'graphrag';
export interface ExperimentalPreset { case_id: string; query: string; scenario_id: string }
export interface ExperimentalConfiguration {
  mode: 'experimental_offline_demo' | 'experimental_live_demo' | 'historical_replay_only';
  presets: ExperimentalPreset[];
  llm_http_attempts: number;
  maximum_llm_requests: number;
  stopped_reason: string | null;
  [key: string]: any;
}
export interface ExperimentalQuery { query: string; scenario_id: string; branch: ExperimentalBranch }

export function initialOfflineDemo(config: ExperimentalConfiguration): ExperimentalPreset | null {
  if (config.runtime_mode !== 'offline_source_review' || config.mode !== 'experimental_offline_demo' ||
      config.generation_disabled !== true || config.maximum_llm_requests !== 0) return null;
  const valid = (config.presets || []).filter(p => initialExperimentalPreset([p]));
  return valid.find(p => p.scenario_id === 'mshta-powershell') || valid[0] || null;
}

export function initialExperimentalPreset(presets: ExperimentalPreset[] | undefined): ExperimentalPreset | null {
  return (presets || []).find(p => p && typeof p.case_id === 'string' && !!p.case_id.trim() &&
    typeof p.query === 'string' && !!p.query.trim() &&
    ['mshta-powershell', 'purplesharp-ad', 'regsvr32-c2'].includes(p.scenario_id)) || null;
}

let artifactProfile: string | undefined;
export function selectArtifactProfile(profile: string): void { artifactProfile = profile; }

export class ExperimentalApiError extends Error {
  constructor(public readonly status: number, public readonly payload: unknown, detail: string) {
    super(`Experimental HTTP ${status};${detail} chưa có câu trả lời được chấp nhận.`);
  }
}

export async function experimentalApi<T>(path: string, init?: RequestInit, selection?: { profile?: string }): Promise<T> {
  const profile = selection ? selection.profile : artifactProfile;
  const suffix = profile ? `${path.includes('?') ? '&' : '?'}profile=${encodeURIComponent(profile)}` : '';
  const response = await fetch(`/experimental-api/${path}${suffix}`, init);
  if (!response.ok) {
    const failure = await response.json().catch(() => null);
    const detail = typeof failure?.detail === 'string' ? ` ${failure.detail}` : '';
    throw new ExperimentalApiError(response.status, failure, detail);
  }
  return response.json();
}

// The service owns generation mode, global attempt cap and the authentication/429 stop latch.
// A live server also requires explicit consent in this dashboard. Never send a hunt to it by default.
export async function runExperimental(
  request: ExperimentalQuery, liveEnabled: boolean,
  onConfiguration: (config: ExperimentalConfiguration) => void,
): Promise<ExperimentalResponse> {
  const selection = { profile: artifactProfile };
  const config = await experimentalApi<ExperimentalConfiguration>('config', undefined, selection);
  if (selection.profile !== artifactProfile) throw new Error('Cấu hình artifacts đã đổi; chưa gửi hunt.');
  onConfiguration(config);
  if (config.mode === 'historical_replay_only') throw new Error(`Profile chỉ cho phép saved replay/fixtures. ${config.release_limitation || ''}`);
  if (config.mode === 'experimental_live_demo' && !liveEnabled) {
    throw new Error('Server đang ở chế độ live. Bật Live rõ ràng hoặc khởi động lại service mặc định offline. Chưa gửi hunt.');
  }
  let response: ExperimentalResponse;
  try {
    response = await experimentalApi<ExperimentalResponse>('hunt', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
    }, selection);
  } catch (error) {
    // 507 carries accounting/validation that must remain reviewable and downloadable.
    // It can never be displayed as an accepted answer, even if computed_outcome passed.
    const body = error instanceof ExperimentalApiError ? error.payload as ExperimentalResponse | null : null;
    if (!(error instanceof ExperimentalApiError) || error.status !== 507 ||
        !body || body.outcome !== 'persistence_error' || !body.request || !body.result ||
        !body.configuration || !body.provenance) throw error;
    response = { ...body, report: null };
  }
  assertCurrentRequest(response, request);
  return response;
}

export function assertCurrentRequest(response: ExperimentalResponse, request: ExperimentalQuery): void {
  if (!response?.request || response.request.query !== request.query || response.request.scenario_id !== request.scenario_id ||
      response.request.branch !== request.branch) {
    throw new Error('Response không khớp câu hỏi/kịch bản/nhánh hiện tại; không hiển thị bằng chứng.');
  }
}

/** Project only the graph supplied by this response; never reconstruct a RAG graph from the corpus. */
export function experimentalGraph(response: ExperimentalResponse | null): CytoscapeElement[] {
  if (!response || response.request.branch !== 'graphrag' || response.outcome === 'abstain') return [];
  const traversal = response.context?.traversal;
  if (!traversal) return [];
  const nodes: CytoscapeElement[] = (traversal.nodes || []).map((node: any) => ({ data: {
    id: node.node_id, label: node.label, type: node.attributes?.entity_type || node.node_type,
    status: node.status, properties: { ...node.attributes, source: node.source,
      source_references: node.source_references, source_ground_truth: response.context?.source_ground_truth },
  } }));
  const ids = new Set(nodes.map(node => node.data.id));
  const edges: CytoscapeElement[] = (traversal.edges || [])
    .filter((edge: any) => ids.has(edge.source_node_id) && ids.has(edge.target_node_id))
    .map((edge: any) => ({ data: { id: edge.edge_id, source: edge.source_node_id, target: edge.target_node_id,
      label: edge.edge_type, type: edge.edge_type, status: edge.status,
      properties: { ...edge.attributes, source: edge.source, source_references: edge.source_references,
        evidence_ids: edge.evidence_ids } } }));
  return [...nodes, ...edges];
}
