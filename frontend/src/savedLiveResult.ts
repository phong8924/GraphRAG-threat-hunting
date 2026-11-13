import { ExperimentalConfiguration } from './experimentalDashboard';
import { ExperimentalResponse } from './experimentalState';

/** Read an integrity-bound, genuine saved LLM response. Never issues a POST. */
export async function loadSavedLiveResult(config: ExperimentalConfiguration): Promise<ExperimentalResponse | null> {
  if (!config.current_source_profile || config.runtime_mode !== 'interactive_per_question') return null;
  const indexResponse = await fetch('/live-results/current.json');
  if (indexResponse.status === 404) return null;
  if (!indexResponse.ok) throw new Error('Không đọc được danh mục kết quả Live đã lưu.');
  const index = await indexResponse.json();
  if (index.schema_version !== 'saved-live-result/v1' || !/^\/live-results\/[a-zA-Z0-9_-]+\.json$/.test(index.response_url) ||
      !/^[a-f0-9]{64}$/.test(index.response_sha256)) throw new Error('Danh mục kết quả đã lưu không hợp lệ.');
  const result = await fetch(index.response_url);
  if (!result.ok) throw new Error('Không đọc được response LLM đã lưu.');
  const body = await result.text();
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))))
    .map(byte => byte.toString(16).padStart(2, '0')).join('');
  if (hash !== index.response_sha256) throw new Error('Hash response LLM đã lưu không khớp; không hiển thị.');
  const response = JSON.parse(body) as ExperimentalResponse;
  const sid = response.request?.scenario_id;
  const expectedSource = config.artifacts?.[sid]?.gt_path?.sha256;
  if (!response.result || !response.provenance || !response.configuration || !response.context ||
      response.provenance.mode !== 'interactive_per_question' || !response.generation_evidence?.new_llm_response ||
      !expectedSource || response.context.source_ground_truth?.sha256 !== expectedSource ||
      response.configuration.model?.model_name !== config.model?.model_name ||
      response.configuration.model?.base_url !== config.model?.base_url) {
    throw new Error('Response đã lưu không khớp nguồn/model của profile Live hiện tại.');
  }
  return { ...response, display_origin: 'saved' };
}
