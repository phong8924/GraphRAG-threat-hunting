export interface ExperimentalResponse {
  request: { query: string; scenario_id: string; branch: string };
  outcome: string;
  result: Record<string, any>;
  scope: Record<string, any> | null;
  gate: Record<string, any> | null;
  eligibility: Record<string, any> | null;
  validation: Record<string, any> | null;
  report: Record<string, any> | null;
  diagnostic: Record<string, any> | null;
  context: Record<string, any> | null;
  messages: Record<string, any> | null;
  evidence_contract: Record<string, any> | null;
  configuration: Record<string, any>;
  provenance: Record<string, any>;
  human_review_required: boolean;
  // Presentation metadata only; original generation/validation records stay intact.
  display_origin?: 'fresh' | 'current_session' | 'saved';
  display_compact?: boolean;
  revalidation?: Record<string, any> | null;
  presentation?: SourcePresentation;
  generation_evidence?: { created_utc: string; model_output_sha256: string | null; new_llm_response: boolean; benchmark_result: false };
}

export interface SourcePresentation {
  schema_version: 'source-presentation/v1';
  scope: 'scenario_overview';
  scenario_id: string;
  title: string;
  description: string;
  not_llm_generated: true;
  review_status: string;
  source_ground_truth: { path: string; sha256: string };
  metrics: { label: string; value: number }[];
  evidence_cards: { evidence_id: string; title: string; summary: string; status: string; observation_count: number;
    event_ids: string[]; source_references: { source_file: string; raw_record_ref: string }[]; json_pointer: string }[];
  relationships: { relationship_id: string; source: string; target: string; action: string; status: string;
    source_references: { source_file: string; raw_record_ref: string }[]; json_pointer: string }[];
  techniques: { external_id: string; name: string; status: string; evidence_support: string; json_pointer: string }[];
  limitations: string[];
  source_limitations: string[];
}

export function boundSourcePresentation(value: ExperimentalResponse | null): SourcePresentation | null {
  const presentation = value?.presentation;
  if (!value || value.outcome !== 'offline_source_review' || presentation?.schema_version !== 'source-presentation/v1' ||
      presentation.scope !== 'scenario_overview' || presentation.not_llm_generated !== true ||
      presentation.scenario_id !== value.request.scenario_id || !presentation.source_ground_truth?.sha256 ||
      presentation.source_ground_truth.sha256 !== value.context?.source_ground_truth?.sha256) return null;
  return presentation;
}

export function acceptedExperimentalDraft(value: ExperimentalResponse): boolean {
  return value.outcome === 'accepted_draft' && value.validation?.status === 'passed' &&
    !!value.report && value.result.fallback_used === false;
}

export function experimentalStatus(value: ExperimentalResponse): string {
  switch (value.outcome) {
    case 'accepted_draft': return acceptedExperimentalDraft(value) ? 'Accepted draft — vẫn cần human review' : 'Trạng thái draft không hợp lệ — xem diagnostic';
    case 'validation_failed': return 'Validation_failed — rejected output, không phải accepted answer';
    case 'abstain': return 'Abstain — không gọi LLM';
    case 'provider_error': return 'Provider error — chưa có câu trả lời LLM; không fallback';
    case 'persistence_error': return 'Persistence error (507) — lưu/xác minh thất bại; session đã dừng, xem diagnostic';
    case 'rate_limited': return 'Rate limited (429) — dừng session, không retry/fallback';
    case 'dry_run_no_generation': return 'Proceed / offline dry-run — chưa gọi LLM, chưa có answer';
    case 'offline_source_review': return 'Nguồn đã truy xuất (BM25/graph) — chưa chạy E5, gate hoặc LLM';
    case 'not_run': return 'Not run — chưa gửi request LLM; xem lý do dừng';
    case 'interrupted': return 'Interrupted — lượt bị ngắt; xem attempt count và checkpoint';
    case 'not_run_request_limit': return 'Đã hết request cap — không gọi LLM';
    case 'not_run_after_stop': return 'Session đã dừng — không gọi LLM; xem stopped_reason';
    default: return 'Runtime error — xem diagnostic, không có accepted answer';
  }
}
