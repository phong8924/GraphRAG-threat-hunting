import React from 'react';
import { ExperimentalResponse } from '../experimentalState';
import { EvidenceSourceCard, PresentationCard } from './SourcePresentation';

const text = (value: unknown): string | undefined => typeof value === 'string' && value.trim() ? value : undefined;
const objects = (value: unknown): Record<string, any>[] => Array.isArray(value)
  ? value.filter(v => v && typeof v === 'object' && !Array.isArray(v)) : [];
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter(v => text(v)) : [];

/** Resolve only citations actually returned by the report against its supplied units. */
export function liveCitations(response: ExperimentalResponse) {
  const units = objects(response.evidence_contract?.units);
  return [...new Set(strings(response.report?.evidence_refs))].map(reference => {
    const unit = units.find(u => u.source?.object_id === reference) ||
      units.find(u => u.object_type === 'evidence' && objects(u.source_references).some(r => r.raw_record_ref === reference)) ||
      units.find(u => objects(u.source_references).some(r => r.raw_record_ref === reference));
    return { reference, unit, summary: text(unit?.properties?.source_object?.summary) || text(unit?.properties?.summary) || text(unit?.text),
      references: objects(unit?.source_references), pointer: text(unit?.source?.json_pointer) };
  });
}

export function LiveReport({ response }: { response: ExperimentalResponse }) {
  const report = response.report!;
  const compact = response.display_compact === true;
  const chain = objects(report.attack_chain).filter(s => text(s.source_entity) || text(s.target_entity) || text(s.action));
  const techniques = objects(report.mitre_mappings).filter(t => text(t.technique_id) || text(t.technique_name));
  const sigma = strings(report.sigma_matches);
  const limits = strings(report.unverified_claims);
  const citations = liveCitations(response);
  const commands = new Map<string, { source_file?: string; raw_record_ref?: string }[]>();
  for (const citation of citations) for (const observation of objects(citation.unit?.properties?.source_observations)) {
    const fields = observation.canonical_fields;
    if (!text(fields?.command_line) || !String(fields?.process_name || '').toLowerCase().endsWith('powershell.exe')) continue;
    const refs = commands.get(fields.command_line) || [];
    if (!refs.some(ref => ref.raw_record_ref === observation.raw_record_ref && ref.source_file === observation.source_file))
      refs.push({ source_file: observation.source_file, raw_record_ref: observation.raw_record_ref });
    commands.set(fields.command_line, refs);
  }
  return <div className="space-y-4" data-testid="live-report-cards">
    {text(report.direct_answer) && <PresentationCard title="Câu trả lời từ LLM" highlighted testId="live-direct-answer">
      <p className={`${compact ? 'text-xs' : 'text-sm'} font-medium leading-relaxed whitespace-pre-wrap`}>{report.direct_answer}</p>
    </PresentationCard>}
    {!!commands.size && <PresentationCard title="Command line · bản ghi tạo tiến trình" testId="live-command-line">
      {[...commands].map(([command, refs]) => <div key={command} className="space-y-2">
        <code className="block whitespace-pre-wrap break-words text-[11px] text-cyan-300">{command}</code>
        {refs.map((ref, index) => <p key={index} className="text-[10px] font-mono text-soc-muted break-all">{ref.source_file} · {ref.raw_record_ref}</p>)}
      </div>)}
    </PresentationCard>}
    {!compact && text(report.executive_summary) && <PresentationCard title="Tóm tắt">
      <p className="text-xs leading-relaxed whitespace-pre-wrap">{report.executive_summary}</p>
    </PresentationCard>}
    {!compact && text(report.technical_analysis) && <PresentationCard title="Phân tích" testId="technical-analysis">
      <p className="text-xs leading-relaxed whitespace-pre-wrap">{report.technical_analysis}</p>
    </PresentationCard>}
    {!!chain.length && <PresentationCard title="Các bước quan hệ" testId="readable-attack-chain">
      <ol className="space-y-3">{chain.map((step, index) => <li key={index} className="flex gap-3">
        {typeof step.step_number === 'number' && <span className="shrink-0 rounded-full bg-cyan-500/10 text-cyan-400 w-6 h-6 flex items-center justify-center text-[10px]">{step.step_number}</span>}
        <div className="min-w-0 space-y-1"><p className="text-xs">{[text(step.source_entity), text(step.action), text(step.target_entity)].filter(Boolean).join(' → ')}</p>
          {text(step.evidence_ref) && <p className="text-[10px] text-cyan-400 break-all">{step.evidence_ref}</p>}
          {text(step.timestamp) && <p className="text-[10px] text-soc-muted">{step.timestamp}</p>}</div>
      </li>)}</ol>
    </PresentationCard>}
    {!!citations.length && <section className="space-y-2" data-testid="live-citations">
      <h3 className="text-xs font-semibold">Bằng chứng được trích dẫn</h3>
      {compact ? <div className="glass-card rounded-xl border p-3 flex flex-wrap gap-2">{citations.map(citation =>
        <span key={citation.reference} className="text-[10px] text-cyan-400 font-mono break-all">{citation.reference}</span>)}</div> : citations.map(citation => <EvidenceSourceCard key={citation.reference} title={citation.reference}
        summary={citation.summary} status={text(citation.unit?.status)} references={citation.references}
        sourcePath={citation.unit ? text(response.evidence_contract?.source_ground_truth?.path) : undefined}
        pointer={citation.pointer} testId="live-citation-card">
        {citation.unit && <pre className="whitespace-pre-wrap break-all mt-2">{JSON.stringify(citation.unit, null, 2)}</pre>}
      </EvidenceSourceCard>)}
    </section>}
    {!!techniques.length && <PresentationCard title="MITRE ATT&CK" testId="live-mitre">
      {techniques.map((mapping, index) => <div key={index} className="space-y-1 border-l-2 border-amber-500/30 pl-3">
        <p className="text-xs text-amber-400">{[text(mapping.technique_id), text(mapping.technique_name)].filter(Boolean).join(' · ')}</p>
        {text(mapping.rationale) && <p className="text-[11px] leading-relaxed">{mapping.rationale}</p>}
        <p className="text-[10px] text-soc-muted">{[text(mapping.assessment_status), text(mapping.review_status), text(mapping.evidence_support)].filter(Boolean).join(' · ')}</p>
      </div>)}
    </PresentationCard>}
    {!!sigma.length && <PresentationCard title="Sigma · từ response LLM" testId="live-sigma">
      {sigma.map((rule, index) => <p key={index} className="text-[11px] font-mono break-all">{rule}</p>)}
    </PresentationCard>}
    {!!limits.length && <section className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 space-y-2" data-testid="live-limitations">
      <h3 className="text-xs font-semibold text-amber-400">Giới hạn kết luận</h3>
      {limits.map((claim, index) => <p key={index} className="text-[11px] leading-relaxed text-soc-muted">{claim}</p>)}
    </section>}
    {compact && text(report.technical_analysis) && <details className="glass-card border rounded-xl p-3 text-[11px]">
      <summary className="cursor-pointer text-cyan-400">Phân tích đầy đủ</summary>
      <p className="mt-2 whitespace-pre-wrap leading-relaxed">{report.technical_analysis}</p>
    </details>}
  </div>;
}
