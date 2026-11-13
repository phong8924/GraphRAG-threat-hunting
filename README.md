# RAG / GraphRAG + LLM cho Threat Hunting

**Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT.** Hệ thống hỗ trợ truy tìm dựa trên Mordor/Security-Datasets, Sigma, MITRE ATT&CK và CTI. Kết quả là draft có nguồn, cần người duyệt.

Ba kịch bản: PurpleSharp (password spraying/Kerberoasting), MSHTA khởi chạy PowerShell, và Regsvr32 với scriptlet HTTP/quan hệ tiến trình–mạng. Process creation chỉ chứng minh khởi chạy; không tự suy ra cmdlet hoàn tất, output hoặc trạng thái dịch vụ. Sigma/MITRE không tự trở thành ground truth đã được con người xác nhận.

## Kiến trúc

```text
Raw logs + Sigma + ATT&CK + CTI
  -> canonical evidence / reviewed draft -> corpus + JSON graph + E5 index
  -> RAG: hybrid retrieval (BM25 + E5 / RRF)
  -> GraphRAG: cùng retrieval + mở rộng quan hệ JSON graph
  -> source-evidence gate -> context budget -> LLM -> schema/guardrail/validator
  -> dashboard ba cột, citations và giới hạn kết luận
```

Benchmark/rubric chỉ dùng đánh giá, không đưa đáp án tham chiếu vào context runtime.

## Thư mục

```text
src/threat_hunting/       backend, retrieval, graph, gate, LLM, validator
frontend/                React/TypeScript source, lockfile và build dist đang dùng
scripts/                 chuẩn bị dữ liệu/model, chạy, kiểm tra và thực nghiệm
configs/                 profile Live và các file được pin/provenance tham chiếu
data/                    10 đầu vào nguyên bản, giữ tên và SHA-256
benchmarks/integrated/   12 câu hỏi và criteria đánh giá
outputs/integrated/      consumers đang dùng và dependency lịch sử bắt buộc
outputs/experiments/deepseek-final-nothinking-20261112T143858Z/
                        results, responses, validation, citations, source receipts
packaging/               danh mục file/hash, nguồn tải, model download, hạn chế provenance
tests/                   kiểm thử chức năng được giữ lại
LICENSES/                giấy phép/thông tin nguồn bên thứ ba
```

## Cài đặt

Môi trường đã kiểm chứng: Windows, Python **3.12**, CPU; Node.js/npm cần khi build lại frontend. Giữ đúng numerical stack vì thay phiên bản có thể làm context hash khác. Không kèm `.venv`, `node_modules` hoặc model cache.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.lock
.venv\Scripts\python.exe -m pip install --no-deps -e .
Copy-Item .env.example .env
.venv\Scripts\python.exe -B scripts\prepare_embedding.py
.venv\Scripts\python.exe -B scripts\verify_portable.py
```

`prepare_embedding.py` chỉ tải model embedding công khai, không gọi LLM. Model `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`; danh mục SHA-256 từng file nằm trong `packaging/embedding_download.json`. Khoảng 470 MiB được tải riêng vào cache người dùng; không đưa vào Git. Sau lần đầu có thể kiểm tra hoàn toàn offline bằng `prepare_embedding.py --check`.

10 đầu vào đã có đầy đủ; kiểm size/hash trong `packaging/inputs.json`. Nếu clone dùng LFS, chạy `git lfs install` và `git lfs pull`. Khi cần lấy lại từ upstream đúng revision/hash:

```powershell
.venv\Scripts\python.exe -B scripts\restore_public_inputs.py --download
```

Tool chỉ chấp nhận đúng file/hash, không ghi đè raw khác. Các script `inspect_mordor.py`, `normalize_mordor.py`, `build_*`, `ingest_cti_reports.py`, `build_vector_index.py` được giữ cho thao tác từng tầng (`--help`). Consumers đã pin được cung cấp để chạy lại retrieval/generation; không ghi đè chúng bằng dữ liệu mới rồi giữ pin cũ.

## Cấu hình và chạy

`.env.example` giữ endpoint `https://api.deepseek.com`, model `deepseek-flash`, temperature 0, max_tokens 16384, thinking disabled, timeout 180s, mỗi lần generate một HTTP attempt và validator 120/80. Chỉ điền `LLM_API_KEY` vào `.env` cục bộ nếu dùng Live. Không commit `.env`.

**Xem kết quả đã lưu, không cần API key, 0 API calls:**

```powershell
.\START_RESULTS_DEEPSEEK.cmd
```

Mở **http://127.0.0.1:8034/results**, chọn `PS-DIRECT / graphrag`, `AUTH-CTI / graphrag`, `NET-DIRECT / graphrag` để xem ba kịch bản. Giữ nhãn kết quả đã lưu và validation gốc; POST generation bị chặn. Adapter bản phân phối dùng public settings từ study pin, kiểm nguyên hash core/build/consumers/results và dựng context từ cùng pipeline. Nó không tạo câu trả lời mới. Cần E5 đã chuẩn bị để dựng lại context đúng hash.

**Live:** dừng server xem kết quả trước để giải phóng cổng 8034, điền key trong `.env`, rồi chạy:

```powershell
.\START_DASHBOARD_LIVE.cmd
```

Mở **http://127.0.0.1:8034/**; chỉ gửi câu hỏi sau khi bật Live rõ ràng. Tối đa 6 requests/phiên; không retry/fallback ở dashboard. Live dùng nguyên `dashboard_live_v10.json` / `runtime_manifest_live_v9.json`. Thay model/provider/settings/numerical environment cần pin **mới** bằng `pin_current_interactive.py`; không sửa hash hoặc ghi đè pin lịch sử. `.env.example` không chứa key, vì vậy Live chưa thể generate cho tới khi bạn điền key.

Build frontend đang được giữ và kiểm hash cùng source nên không cần npm để xem/chạy bản hiện tại. Nếu sửa UI:

```powershell
cd frontend
npm ci
npm run build
cd ..
# Tạo config/profile và manifest MỚI bằng tool pin_current_interactive.py trước khi chạy.
```

Không thêm cache/ảnh/tập tin ngoài build vào `frontend/src` hoặc `dist`, vì inventory build được kiểm nghiêm ngặt.

## Chạy lại bộ 12 × 2

Giữ cùng generation config cho hai nhánh. Script tạo thư mục timestamp mới, không gọi lại hoặc ghi đè bộ kết quả đã lưu:

```powershell
# Chỉ chuẩn bị 24 lượt, không gọi LLM:
.venv\Scripts\python.exe -B scripts\rerun_paired.py
# Khi chủ động chấp nhận chi phí API, chuẩn bị và gọi các lượt đủ điều kiện:
.venv\Scripts\python.exe -B scripts\rerun_paired.py --live
```

Dùng shared `prepare_branch` / `generate_branch`, giữ gate, context limits và validator. Khoảng nghỉ tối thiểu 60 giây; tối đa một retry cho 429/503/timeout theo policy, không fallback hoặc gọi tới khi accepted. Gate thiếu bằng chứng/over-budget giữ abstain. AUTH-DIRECT/RAG chạy đầu. Results được ghi sau từng lượt, kèm nguồn/context hash/finish_reason/usage/diagnostic; không coi response bị cắt là accepted. Không chạy trực tiếp runner trong thư mục kết quả lịch sử để tạo đợt mới.

## Kết quả cuối đã lưu

`outputs/experiments/deepseek-final-nothinking-20261112T143858Z/` chứa `results.json`, `results.csv`, `report.md`; mỗi lượt có response/provider response/validation/citations và receipts tham chiếu consumer gốc. Schema report dùng `evidence_refs`; xem `citations_resolved.json` và `reference_checks`. Full context dựng lại trong RAM, kiểm hash, không âm thầm thay bằng demo.

| Nhánh | accepted_draft | validation_failed | abstain | HTTP attempts |
|---|---:|---:|---:|---:|
| RAG | 6 | 0 | 6 | 6 |
| GraphRAG | 8 | 1 | 3 | 9 |

Đủ 24 cặp, 15 requests; không retry/lỗi dịch vụ/phản hồi bị cắt trong đợt này. 527.405 prompt + 23.029 completion = 550.434 tokens; chi phí tiền tệ chưa biết vì provider không trả. 7 lượt abstain do gate, 2 do context budget. Chỉ 4 câu có cả hai nhánh đủ điều kiện. **accepted_draft không phải accuracy** hoặc human approval; vẫn cần đánh giá nội dung/citations độc lập. NET-CORRELATE/GraphRAG bị từ chối do gộp references/unsupported checked steps; giữ nguyên kết quả đó.

## Dữ liệu lớn, giấy phép và giới hạn

`.gitattributes` giữ nguyên bytes các file đã pin và cấu hình Git LFS cho hai file lớn: ATT&CK JSON (~51 MiB) và PurpleSharp (~38 MiB). Trước lần `git add` đầu tiên, cài Git LFS. Working tree phải chứa dữ liệu thực sau `git lfs pull` trước khi kiểm hash; Git LFS lưu pointers trong Git theo cơ chế bình thường. Model E5 tải riêng theo revision/hash, không kèm weight 471 MB. Xem `packaging/large_files.json`.

`LICENSES/` và `configs/knowledge/public_input_sources_v1.json` ghi upstream/revision/giấy phép của Mordor/Security-Datasets, Sigma, ATT&CK và thông tin E5/CTI. Source gốc chưa có giấy phép chung cho code dự án; bản sao không tự gán giấy phép mới.

16 artifacts provenance lịch sử đã thiếu ngay ở nguồn (liệt kê trong `packaging/missing_historical_provenance.json`). Không dựng lại hoặc đổi hash cho chúng. Chúng không được launcher hiện tại đọc; consumers có nội dung evidence/CTI nhúng và hash riêng nên chạy/xem lại bộ hiện tại vẫn được. Chưa thể tuyên bố tái dựng byte-identical toàn bộ quá trình tạo ground truth/CTI lịch sử từ các file thiếu này. Đây là giới hạn lineage, không phải dữ liệu runtime bị âm thầm bỏ khỏi bản sao.

Kiểm nhanh chức năng giữ lại:

```powershell
.venv\Scripts\python.exe -B -m pytest tests\test_llm_client.py tests\test_llm_guardrail.py tests\test_source_evidence_contract.py -q
```
