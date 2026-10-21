
**Đề tài:** Chuẩn hóa IoC sang STIX/TAXII và đánh giá độ tin cậy của Threat Feed mở
**Người thực hiện** Mỹ Phương (Fern)
**Phiên bản:** v2 (tag `prereg-v2`), sửa đổi của bản gốc v1 (tag `prereg-v1`, commit `ff52514`)

**Trạng thái dữ liệu khi cố định đề cương:**
- Bản gốc **v1** được commit lúc **2026-10-21 15:15 (+07), tức 08:15 UTC**, **trước** mọi lần tải dữ liệu. Xem lại bản gốc bằng lệnh: `git show prereg-v1:docs/PREREGISTRATION.md`.
- Lần tải pilot duy nhất chạy lúc **2026-10-21 08:28 UTC** (8 feed), khoảng 13 phút sau commit v1. Sau lần tải này mình **chỉ kiểm tra cấu trúc** (số dòng, tiêu đề, ngày cập nhật của từng feed) và chỉnh đề cương theo đó. **Chưa có bất kỳ phân tích chất lượng nào** (độ chính xác, độ trùng, vòng đời) được tính trên dữ liệu.
- Bản **v2** này là bản sửa đổi sau pilot, được tag **trước** khi bật thu thập liên tục. Mọi thay đổi so với v1 nằm trong `docs/DEVIATIONS.md` (mục "Sửa đổi từ v1 sang v2").

> Quy tắc: mọi thay đổi sau tag `prereg-v2` phải ghi vào `docs/DEVIATIONS.md` kèm ngày và lý do. Không sửa file này sau khi đã tag.

---

## 1. Câu hỏi nghiên cứu và giả thuyết

**RQ1.** Trích xuất IoC từ văn bản phi cấu trúc đạt chất lượng thế nào, và lọc ngữ cảnh có cải thiện so với regex thuần không?
- **H1:** Pipeline (regex + khử defang + lọc ngữ cảnh) có macro-F1 cao hơn regex thuần ít nhất **0,05**.
- *Bác bỏ H1 nếu:* chênh lệch < 0,02 hoặc khoảng tin cậy 95% bootstrap của chênh lệch chứa 0.

**RQ2.** Chất lượng của cùng một feed có khác nhau giữa các loại IoC mà feed đó cung cấp không?
- **H2:** Với feed có nhiều loại IoC (ThreatFox: ip, domain, url, hash), độ chính xác chênh nhau giữa ít nhất một cặp loại IoC **≥ 0,10**, và khoảng tin cậy 95% bootstrap của chênh lệch không chứa 0.
- *Bác bỏ H2 nếu:* mọi cặp có khoảng tin cậy chứa 0.
- *Quy tắc domain:* IoC loại domain gồm domain do feed công bố và hostname trích từ URL (gắn nhãn `derived_from_url`, báo cáo riêng).
- Lý do viết lại: hầu hết feed chỉ cung cấp một loại IoC, nên so sánh thứ hạng feed giữa các loại IoC không có ý nghĩa.

**RQ3.** Thời gian một IoC nằm trong feed và thời gian nó còn hoạt động có phụ thuộc loại IoC và feed không?
- **H3a:** Thời gian nằm trong feed (listing duration) khác nhau theo loại IoC và theo feed (kiểm định log-rank, p < 0,05).
- **H3b (khám phá, không có ngưỡng quyết định):** So sánh chính sách suy giảm (decay) với TTL cố định 7 và 30 ngày trên các IoC có tín hiệu hoạt động độc lập (xem mục 3). Do cửa sổ quan sát ngắn (~10 ngày), phần này chỉ báo cáo mô tả, không kết luận về chính sách tối ưu.

**RQ4.** Chuẩn hóa tự động có đáng giá không?
- **H4:** Pipeline tự động nhanh hơn xử lý tay ít nhất **5 lần** (cùng 30 báo cáo) và giữ lại ≥ **85%** thực thể/quan hệ so với bản chuẩn gán tay.
- *Bác bỏ H4 nếu:* một trong hai điều kiện không đạt.

**RQ5 (mô-đun AI A1, nếu kịp).** LLM có trích xuất tốt hơn không và có ảo giác bao nhiêu?
- **H5a:** Sau grounding check (IoC phải xuất hiện nguyên văn trong tài liệu gốc sau khi khử defang), tỷ lệ IoC ảo giác ≤ **1%**.
- **H5b:** Regex + LLM có recall ≥ recall của regex thuần.
- *Bác bỏ nếu:* H5a > 1% hoặc H5b recall thấp hơn.

> Kết quả bác bỏ giả thuyết vẫn được báo cáo đầy đủ và trung thực.

---

## 2. Dữ liệu và thu thập

**Cửa sổ phân tích chính thức:** 2026-10-21 08:00 UTC đến 2026-10-31 23:59 UTC (khoảng 10 ngày). Đóng băng dữ liệu ngày 2026-11-01. Lần tải 08:28 UTC ngày 21/10 là lần đầu của cửa sổ này.

**Tần suất:** mỗi giờ mỗi feed (khoảng cách tối thiểu 60 phút), thời gian UTC. Bản thô lưu gzip kèm SHA-256; mọi lần tải (kể cả lỗi, không đổi) đều ghi vào `data/manifest/manifest.jsonl`.

**Bảy feed (cố định):**

| Feed | Tổ chức vận hành | Loại IoC | Bản chất danh sách |
|------|------------------|----------|--------------------|
| URLhaus | abuse.ch | url | Cửa sổ trượt "recent" (có trường trạng thái online/offline) |
| ThreatFox | abuse.ch | ip, domain, url, hash | Cửa sổ trượt "recent" |
| MalwareBazaar | abuse.ch | hash | Cửa sổ trượt "recent" |
| OpenPhish | OpenPhish | url | Cửa sổ trượt (feed cộng đồng, ~300 dòng) |
| Blocklist.de | Blocklist.de | ip | Danh sách IP đang bị liệt kê |
| CINS Army | CINS Score | ip | Danh sách IP giới hạn trên (đúng 15.000 dòng lúc pilot) |
| Emerging Threats compromised IPs | Proofpoint | ip | Danh sách IP đang bị liệt kê |

**Feed đã loại sau pilot:** Feodo Tracker. Lúc pilot chỉ có 5 bản ghi và ngày cập nhật cuối là 2026-03-04, không đủ dữ liệu để đo. Spamhaus DROP, AlienVault OTX, PhishTank loại từ đầu (lý do ở `docs/DECISIONS.md`).

**Số dòng dữ liệu lúc pilot (chỉ để mô tả quy mô):** URLhaus 33.899; Blocklist.de 25.745; CINS 15.000; ThreatFox 7.861; MalwareBazaar 1.632; Emerging Threats 481; OpenPhish 300.

**Tập báo cáo phi cấu trúc (E1):** 60–100 báo cáo/blog công khai, chọn trước khi chạy pipeline; chỉ lưu liên kết, ngày truy cập và bản trích phục vụ nghiên cứu. Gán nhãn bởi hai người độc lập nếu có thể, tính Cohen's kappa (mục tiêu ≥ 0,7); nếu chỉ một người gán, ghi rõ là hạn chế.

**Quy tắc loại trừ (cố định từ bây giờ):**
- Loại IP thuộc dải riêng/dành riêng (RFC 1918, loopback, v.v.).
- Loại domain/URL ví dụ trong tài liệu (example.com, localhost).
- Không loại IoC nào sau khi đã thấy kết quả chấm điểm.

---

## 3. Ground truth và định nghĩa vòng đời

**Nhãn "độc hại" (cho độ chính xác):**
- **GT-1 (VirusTotal):** ≥ **5** engine đánh dấu malicious (hash, URL) hoặc ≥ **3** (IP, domain). Tra bằng **mẫu phân tầng ngẫu nhiên** theo feed × loại IoC (tối đa ~100 IoC mỗi tầng, seed 42), tra sau ít nhất 48 giờ kể từ lần đầu thấy, ghi ngày truy vấn và cache kết quả.
- **GT-2 (nguồn độc lập):** IoC xuất hiện ở ít nhất **hai tổ chức vận hành khác nhau** trong cửa sổ thu thập. Đếm theo tổ chức, không đếm theo feed (4 feed của abuse.ch chỉ tính là một).
- **Nhãn cuối:** thỏa GT-1 hoặc GT-2. Báo cáo kết quả theo từng mức riêng, không chỉ mức gộp.
- **Báo động giả (FP):** IoC nằm trong Tranco top 10.000 (ghi ngày tải snapshot), dải IP hạ tầng/CDN công khai, hoặc bị gỡ khỏi feed gốc kèm ghi chú false positive.

**Vòng đời (tách làm hai đại lượng để không nhầm):**
- **Thời gian nằm trong feed (listing duration):** từ lần đầu quan sát đến khi biến mất khỏi **ba lần chụp liên tiếp** (~3 giờ). Đây là *hành vi của feed*, không phải bằng chứng IoC hết hoạt động, nhất là với feed dạng cửa sổ trượt hoặc giới hạn trên (URLhaus, ThreatFox, MalwareBazaar, OpenPhish, CINS). Còn đang trong feed đến hết cửa sổ thì tính là bị cắt cụt (censored).
- **Thời gian còn hoạt động (activity lifetime):** chỉ tính khi có tín hiệu độc lập với việc feed xóa: (a) URLhaus: trường trạng thái chuyển sang offline; (b) domain: không resolve DNS ba lần kiểm tra hằng ngày liên tiếp (mẫu ngẫu nhiên, tối thiểu cần thiết). **Không truy cập trực tiếp URL độc hại.** Các IoC không có tín hiệu thì tính là bị cắt cụt.

---

## 4. Mô hình chấm điểm độ tin cậy

Điểm của feed f cho loại IoC t: **S(f,t) = 0,2·A + 0,2·T + 0,2·U + 0,2·C + 0,2·St** (mỗi chiều chuẩn hóa về 0–1).

- **A (Accuracy):** tỷ lệ IoC được xác nhận độc hại (precision) trên mẫu GT.
- **T (Timeliness):** chỉ tính trên IoC xuất hiện ở ít nhất 2 feed. T = tỷ lệ các IoC đó mà feed f là feed **đầu tiên** quan sát được (độ phân giải 1 giờ). Feed không có IoC chung thì ghi "không đủ dữ liệu", không tự gán 0.
- **U (Uniqueness):** số IoC độc hại chỉ feed này có / tổng IoC của feed (UTC).
- **C (Context):** tỷ lệ IoC có đủ thẻ loại mối đe dọa, malware family hoặc dấu thời gian do nguồn cung cấp. Feed chỉ là danh sách trần (Blocklist.de, CINS, Emerging Threats, OpenPhish) sẽ có C rất thấp theo thiết kế, ghi chú rõ đây là đặc điểm của định dạng, không phải lỗi.
- **St (Stability):** trung bình của (1 − hệ số biến thiên của số IoC mới theo ngày, chuẩn hóa) và tỷ lệ lần tải thành công.

**Phân tích độ nhạy:** đổi mỗi trọng số ±20% (các trọng số khác chia lại cho tổng = 1), báo cáo thay đổi thứ hạng bằng Kendall tau với thứ hạng gốc.
**Ánh xạ Admiralty:** S ≥ 0,80 → A; 0,65–0,79 → B; 0,50–0,64 → C; 0,35–0,49 → D; < 0,35 → E; F = không đủ dữ liệu (< 30 IoC trong cửa sổ).

---

## 5. Thí nghiệm và chỉ số

| Mã | Thí nghiệm | Chỉ số chính | Tiêu chí |
|----|-----------|--------------|----------|
| E1 | Trích xuất IoC | Precision, recall, macro-F1 (bootstrap 1000 lần, CI 95%) | H1 |
| E2 | Hợp lệ STIX/TAXII | % đối tượng qua stix2-validator; round-trip không mất trường bắt buộc | 100% qua validator, 0 lỗi |
| E3 | Chất lượng feed | S(f,t); chênh lệch độ chính xác theo loại IoC trong cùng feed (bootstrap CI); đường cong độ bao phủ biên | H2 |
| E4a | Thời gian nằm trong feed | Kaplan-Meier, log-rank theo loại IoC và theo feed | H3a |
| E4b | Thời gian còn hoạt động (khám phá) | Kaplan-Meier trên URLhaus và domain; so sánh decay với TTL 7/30 ngày (FPR, recall), chỉ mô tả | H3b (khám phá) |
| E5 | Mất mát thông tin | % thực thể/quan hệ giữ lại so với bản chuẩn gán tay | H4 |
| E7 | Hiệu quả vận hành | Thời gian xử lý trung bình trên 30 báo cáo, tay so với tự động | H4 |
| E8 | LLM trích xuất (A1, tùy chọn) | Tỷ lệ ảo giác sau grounding check; recall; chạy lặp 3 lần | H5 |

Phần tùy chọn bị cắt nếu trễ tiến độ: tích hợp SIEM (E6), ML dự đoán độ tin cậy (E9), vòng đời động và phát hiện trôi dạt (E10, E11).

**Thống kê:** báo cáo khoảng tin cậy, không chỉ giá trị trung bình; có baseline cho mọi so sánh; seed ngẫu nhiên cố định = 42.
**Với mô hình AI:** ghi tên và phiên bản mô hình, temperature, prompt đầy đủ, lưu đầu ra thô kèm hash.

---

## 6. Mối đe dọa đến tính hợp lệ (dự kiến)

- Thời gian quan sát ngắn (~10 ngày): IoC sống lâu hơn cửa sổ bị cắt cụt; không suy diễn ngoài khoảng quan sát.
- Chỉ có **5 tổ chức vận hành** trong 7 feed; 3 feed cùng thuộc abuse.ch. Hash chỉ có 2 feed, domain gốc chỉ có ThreatFox, nên kết luận về hash và domain yếu hơn IP và URL.
- Chọn feed theo khả năng truy cập, không ngẫu nhiên; toàn feed quốc tế.
- Một số feed là cửa sổ trượt hoặc có giới hạn trên (OpenPhish ~300 dòng, CINS 15.000 dòng), nên "biến mất khỏi feed" không đồng nghĩa IoC hết độc hại.
- "Lần đầu thấy" của danh sách trần là thời điểm mình quan sát, không phải thời điểm feed công bố.
- Ground truth dựa vào VirusTotal có thiên lệch (IoC mới có thể chưa được engine nhận diện); mẫu GT bị giới hạn bởi hạn mức API miễn phí.
- Gán nhãn bởi số ít người.

---

## 7. Ghi chú đạo đức và pháp lý

- Chỉ dùng feed công khai, tuân thủ điều khoản sử dụng và giới hạn truy cập của từng nguồn.
- Không công bố lại toàn bộ dữ liệu feed có giấy phép hạn chế; chỉ công bố số liệu tổng hợp.
- Không tấn công, không quét chủ động, không truy cập trực tiếp URL độc hại; kiểm tra DNS ở mức tối thiểu cần thiết.
- Dữ liệu gửi API bên ngoài (VirusTotal, LLM) chỉ gồm dữ liệu công khai.
