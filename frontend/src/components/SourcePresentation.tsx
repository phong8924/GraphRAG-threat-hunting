import React from 'react';
import { ExperimentalResponse, SourcePresentation } from '../experimentalState';

export function PresentationCard({ title, children, highlighted = false, testId }: {
  title?: string; children: React.ReactNode; highlighted?: boolean; testId?: string;
}) {
  return <section data-testid={testId} className={highlighted
    ? 'rounded-2xl border border-cyan-500/30 bg-cyan-500/5 p-4 space-y-2'
    : 'glass-card border rounded-xl p-3 space-y-2'}>
    {title && <h3 className="text-xs font-semibold text-cyan-400">{title}</h3>}{children}
  </section>;
}

export function EvidenceSourceCard({ title, summary, status, references, pointer, sourcePath, testId, children }: {
  title: string; summary?: string; status?: string;
  references: { source_file?: string; raw_record_ref?: string }[];
  pointer?: string; sourcePath?: string; testId?: string; children?: React.ReactNode;
}) {
  return <PresentationCard testId={testId}>
    <div className="flex justify-between items-start gap-2"><h4 className="text-xs font-semibold break-words">{title}</h4>
      {status && <span className="text-[10px] text-soc-muted shrink-0">{status}</span>}</div>
    {summary && <p className="text-[11px] leading-relaxed text-soc-muted whitespace-pre-wrap">{summary}</p>}
    {references.map((ref, i) => <p key={i} className="text-[10px] font-mono text-cyan-400 break-all">{[ref.source_file, ref.raw_record_ref].filter(Boolean).join(' · ')}</p>)}
    {(pointer || sourcePath || children) && <details className="text-[10px] border-t pt-2">
      <summary className="cursor-pointer text-cyan-400">Đối chiếu nguồn</summary>
      {sourcePath && <p className="mt-2 break-all">{sourcePath}</p>}{pointer && <p className="mt-1 break-all">{pointer}</p>}{children}
    </details>}
  </PresentationCard>;
}

export const sourceStatus = (status: string) => status === 'observed' ? 'Quan sát' : status === 'inferred' ? 'Tương quan' : 'Ứng viên';

export function sourceMarkdown(value: SourcePresentation): string {
  return [`# ${value.title}`, '', 'Tổng quan kịch bản từ dữ liệu nguồn · không phải câu trả lời LLM · cần người duyệt.', '', value.description, '',
    ...value.metrics.map(m => `- ${m.label}: ${m.value}`), '', '## Quan hệ trong dữ liệu', '',
    ...value.relationships.map(r => `- ${r.source} → ${r.action} → ${r.target} (${sourceStatus(r.status)}; ${r.json_pointer})`), '',
    '## Bằng chứng', '', ...value.evidence_cards.map(e => `- ${e.title}: ${e.summary} (${e.source_references.map(r => r.raw_record_ref).join(', ')}; ${e.json_pointer})`), '',
    '## Giới hạn', '', ...value.limitations.map(text => `- ${text}`), '', `Nguồn GT: ${value.source_ground_truth.path}`, `SHA-256: ${value.source_ground_truth.sha256}`].join('\n');
}

export function SourcePresentationCard({ response }: { response: ExperimentalResponse }) {
  const value = response.presentation!;
  const supported = value.techniques.filter(t => t.evidence_support === 'supported_by_observed_behavior');
  const download = () => {
    const url = URL.createObjectURL(new Blob([sourceMarkdown(value)], { type: 'text/markdown;charset=utf-8' }));
    const a = document.createElement('a'); a.href = url; a.download = `source-demo-${value.scenario_id}.md`; a.click(); URL.revokeObjectURL(url);
  };
  return <article className="space-y-4 select-text" data-testid="source-presentation">
    <PresentationCard highlighted>
      <div className="flex items-center justify-between gap-2 text-[10px]"><span className="uppercase tracking-wider text-cyan-400">Hồ sơ kịch bản · dữ liệu thật</span><span className="text-soc-muted">{response.request.branch.toUpperCase()}</span></div>
      <h2 className="font-semibold text-lg leading-snug">{value.title}</h2>
      <p className="text-xs leading-relaxed text-soc-muted">{value.description}</p>
      <p className="text-[10px] text-amber-400">Tổng quan offline từ nguồn cố định · chưa gọi LLM · cần người duyệt</p>
    </PresentationCard>
    <div className="grid grid-cols-2 gap-2">{value.metrics.map(m => <div key={m.label} className="glass-card rounded-xl border p-3">
      <div className="text-xl font-semibold text-cyan-400">{m.value}</div><div className="text-[10px] text-soc-muted mt-1">{m.label}</div>
    </div>)}</div>
    <section className="space-y-2"><h3 className="text-xs font-semibold">Quan hệ trong dữ liệu</h3>
      {value.relationships.map((r, i) => <div key={r.relationship_id} className="glass-card border rounded-xl p-3 flex gap-3">
        <span className="shrink-0 flex items-center justify-center rounded-full bg-cyan-500/10 text-cyan-400 w-6 h-6 text-[10px]">{i + 1}</span>
        <div className="min-w-0 space-y-1"><p className="text-xs break-words"><strong>{r.source}</strong><span className="text-soc-muted"> → {r.action} → </span><strong>{r.target}</strong></p>
          <p className="text-[10px] text-soc-muted">{sourceStatus(r.status)} · {r.source_references.map(ref => ref.raw_record_ref).slice(0, 3).join(' · ')}</p></div>
      </div>)}
    </section>
    {supported.length > 0 && <section className="space-y-2"><h3 className="text-xs font-semibold">MITRE ATT&amp;CK · ánh xạ ứng viên</h3>
      <div className="flex flex-wrap gap-2">{supported.map(t => <span key={t.external_id} className="border border-amber-500/30 bg-amber-500/5 text-amber-400 rounded-lg px-2 py-1 text-[10px]" title={t.name}>{t.external_id} · ứng viên</span>)}</div>
    </section>}
    <section className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 space-y-2"><h3 className="text-xs font-semibold text-amber-400">Giới hạn kết luận</h3>
      {value.limitations.map(text => <p key={text} className="text-[11px] leading-relaxed text-soc-muted">{text}</p>)}
    </section>
    <p className="text-[10px] text-soc-muted">Số liệu trên thuộc toàn bộ hồ sơ kịch bản. Kết quả truy xuất cho câu hỏi bên dưới được giữ riêng; bản ghi nguồn có thể là hai góc nhìn của cùng một sự kiện.</p>
    <details className="glass-card border rounded-xl p-3 text-[10px]"><summary className="cursor-pointer text-cyan-400">Câu hỏi và nguồn của lượt truy xuất</summary>
      <p className="mt-2 whitespace-pre-wrap">{response.request.query}</p><p className="mt-2 text-soc-muted">{response.context?.retrieval?.hits?.length || 0} chunks · {response.context?.traversal?.nodes?.length || 0} nodes · BM25 / JSON graph</p>
      <p className="mt-2 break-all">GT: {value.source_ground_truth.path}</p><p className="mt-1 break-all">SHA-256: {value.source_ground_truth.sha256}</p>
    </details>
    <button type="button" onClick={download} className="rounded-lg border border-cyan-500/30 text-cyan-400 px-3 py-2 text-[11px]">Tải bản trình bày có dẫn nguồn</button>
  </article>;
}
