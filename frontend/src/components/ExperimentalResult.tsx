import React from 'react';
import { acceptedExperimentalDraft, boundSourcePresentation, ExperimentalResponse, experimentalStatus } from '../experimentalState';
import { SourcePresentationCard } from './SourcePresentation';
import { LiveReport } from './LiveReport';

export function ExperimentalDetails({ title, value }: { title: string; value: unknown }) {
  return <details className="glass-card border rounded-lg p-2 text-[10px] min-w-0">
    <summary className="cursor-pointer text-cyan-400">{title}</summary>
    <pre className="min-w-0 whitespace-pre-wrap break-all mt-2 select-text">{JSON.stringify(value, null, 2)}</pre>
  </details>;
}

export function ExperimentalResult({ response }: { response: ExperimentalResponse }) {
  if (response.outcome === 'abstain' && response.provenance.mode === 'offline_source_review') {
    return <div className="glass-card border rounded-2xl p-4 space-y-3" data-testid="source-scope-help">
      <h2 className="font-semibold">Cùng khám phá một kịch bản có sẵn</h2>
      <p className="text-xs text-soc-muted leading-relaxed">Câu hỏi này chưa gắn với nguồn điều tra của kịch bản. Chọn một trong ba nút Demo phía trên để xem ngay bằng chứng và đồ thị, hoặc nhắc tới mshta.exe, regsvr32.exe hay PurpleSharp trong câu hỏi.</p>
      <p className="text-[10px] text-amber-400">Chưa tạo kết luận an ninh · không gọi LLM</p>
    </div>;
  }
  if (boundSourcePresentation(response)) {
    return <SourcePresentationCard response={response} />;
  }
  const accepted = acceptedExperimentalDraft(response);
  const saved = response.display_origin === 'saved' || response.provenance.mode === 'saved_experimental_replay';
  const reread = response.display_origin === 'current_session' || (!response.display_origin && response.provenance.display_source?.startsWith('current_session_result'));
  const reasons = response.result.abstention_stage === 'context_budget' ? ['context_budget_exceeded'] :
    response.gate?.reason_codes || response.scope?.reason_codes || [];
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url;
    link.download = `experimental-${response.provenance.mode}-${response.request.branch}-${response.outcome}.json`;
    link.click(); URL.revokeObjectURL(url);
  };
  return <div className="space-y-3 select-text break-words" data-testid="experimental-result">
    <div className="glass-card border rounded-xl p-3 space-y-2 text-xs">
      <p className="text-cyan-400 font-mono">{response.request.branch.toUpperCase()} · {response.request.scenario_id}</p>
      {!response.display_compact && <p className="whitespace-pre-wrap">{response.request.query}</p>}
      <h2 className={accepted ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'} data-testid="experimental-outcome">{experimentalStatus(response)}</h2>
      <p className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-2 text-[11px] text-cyan-400" data-testid="response-origin">
        {saved ? 'Kết quả LLM đã lưu · đọc lại · 0 API calls' : reread ? 'Kết quả trong phiên hiện tại · đọc lại · 0 API calls' : response.generation_evidence?.new_llm_response ? 'Phản hồi LLM mới' : 'Kết quả của lượt xử lý'}
        {response.generation_evidence?.created_utc && <span className="block text-[10px] text-soc-muted mt-1">Sinh lúc: {response.generation_evidence.created_utc}</span>}
        {response.configuration?.model?.model_name && <span className="block text-[10px] text-soc-muted">Model lúc sinh: {response.configuration.model.model_name}</span>}
      </p>
      {!response.display_compact && <p className="text-[10px] text-soc-muted break-all">Nguồn: {response.provenance.mode} · {response.provenance.mode === 'saved_experimental_replay'
        ? `Replay: 0 request mới; lịch sử ${response.provenance.historical_llm_http_attempts} attempt`
        : saved || reread ? `Đọc lại: 0 request mới; lần sinh gốc ${response.result.llm_http_attempts ?? 0} LLM HTTP attempts`
        : `Lượt này: ${response.result.llm_http_attempts ?? 0} LLM HTTP attempts`} · Cần human review.</p>}
      {response.provenance.source_generation_profile && <p className="text-[10px] text-amber-300">Kết quả lịch sử: {response.provenance.source_generation_profile} · validator lúc sinh: {response.provenance.historical_validator_policy?.policy_id}. Giữ nguyên validation và trạng thái lúc sinh.</p>}
      {!response.display_compact && <p className="text-[10px]">Eligibility: {response.eligibility?.decision || response.result.eligibility_decision || response.gate?.decision || response.scope?.decision || 'not_assessed'} · stage: {response.result.abstention_stage || '—'}</p>}
      {!!reasons.length && <p className="text-[10px] break-all">Lý do: {reasons.join(', ')}</p>}
      <button onClick={download} className="text-cyan-400 underline text-[10px]">{accepted ? 'Tải JSON (draft + provenance)' : 'Tải diagnostic JSON'}</button>
    </div>
    {accepted && <article className="space-y-3" data-testid="accepted-answer">
      <h3 className="font-semibold text-emerald-400">{response.provenance.source_generation_profile ? 'Historical accepted draft · validation lúc sinh · chưa human-approved' : 'Accepted draft · chưa human-approved'}</h3>
      {!saved && !reread && response.generation_evidence?.new_llm_response && <p className="text-[10px] text-cyan-400" data-testid="fresh-llm-evidence">
        LLM trả lời mới · {response.generation_evidence.created_utc} · không phải historical replay
      </p>}
      <LiveReport response={response} />
      <ExperimentalDetails title="Chi tiết draft và citations" value={response.report} />
    </article>}
    {response.diagnostic && <ExperimentalDetails title="Rejected diagnostic — không phải accepted answer" value={response.diagnostic} />}
    {response.revalidation && <ExperimentalDetails title={`Revalidation offline riêng · ${response.revalidation.validator_policy_id} · ${response.revalidation.status} · không generation mới`} value={response.revalidation} />}
    {response.result.provider_error && <ExperimentalDetails title="Provider error — không retry/fallback" value={response.result.provider_error} />}
    <ExperimentalDetails title="Chi tiết kỹ thuật của response" value={{ scope: response.scope, gate: response.gate,
      eligibility: response.eligibility, validation: response.validation, result: response.result,
      configuration: response.configuration, provenance: response.provenance, messages: response.messages }} />
  </div>;
}
