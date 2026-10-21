
**Đề tài:** Chuẩn hóa IoC sang STIX/TAXII và đánh giá độ tin cậy của Threat Feed mở
**Người thực hiện** Mỹ Phương (Fern)
**Ngày viết:** 2026-10-19 (viết TRƯỚC khi thu thập dữ liệu và chạy thí nghiệm)
**Phiên bản:** v1 (tag `prereg-v1`)

> Quy tắc: mọi thay đổi sau commit này phải ghi vào `docs/DEVIATIONS.md` kèm ngày và lý do. Không sửa file này sau khi đã tag; nếu cần thì tạo phiên bản mới và giữ nguyên bản cũ trong lịch sử Git.

---

## 1. Câu hỏi nghiên cứu và giả thuyết

**RQ1.** Trích xuất IoC từ văn bản phi cấu trúc đạt chất lượng thế nào, và lọc ngữ cảnh có cải thiện so với regex thuần không?
- **H1:** Pipeline (regex + khử defang + lọc ngữ cảnh) có macro-F1 cao hơn regex thuần ít nhất **0,05**.
- *Bác bỏ H1 nếu:* chênh lệch < 0,02 hoặc khoảng tin cậy 95% bootstrap của chênh lệch chứa 0.

**RQ2.** Chất lượng của cùng một feed có khác nhau giữa các loại IoC mà feed đó cung cấp không?
- **H2:** Với feed có nhiều loại IoC (ThreatFox: ip, domain, url, hash; URLhaus: host dạng IP so với host dạng domain), độ chính xác chênh nhau giữa các loại ít nhất 0,10, khoảng tin cậy 95% bootstrap của chênh lệch không chứa 0.
- *Bác bỏ H2 nếu:* mọi chênh lệch đều có khoảng tin cậy chứa 0.

**RQ3.** Chính sách suy giảm theo loại IoC (decay) có tốt hơn TTL cố định không?
- **H3a:** Thời gian sống trung vị theo thứ tự: hash > domain > IP > URL.
- **H3b:** So với TTL cố định 30 ngày, chính sách decay giảm tỷ lệ báo động giả (FPR) tương đối ≥ **20%** trong khi giữ ≥ **95%** độ bao phủ (recall) của TTL 30 ngày.
- *Bác bỏ H3b nếu:* một trong hai điều kiện không đạt.

**RQ4.** Chuẩn hóa tự động có đáng giá không?
- **H4:** Pipeline tự động nhanh hơn xử lý tay ít nhất **5 lần** (cùng 30 báo cáo) và giữ lại ≥ **85%** thực thể/quan hệ so với bản chuẩn gán tay.
- *Bác bỏ H4 nếu:* một trong hai điều kiện không đạt.

**RQ5 (mô-đun AI A1, nếu kịp).** LLM có trích xuất tốt hơn không và có ảo giác bao nhiêu?
- **H5a:** Sau grounding check (IoC phải xuất hiện nguyên văn trong tài liệu gốc sau khử defang), tỷ lệ IoC ảo giác còn ≤ **1%**.
- **H5b:** Regex + LLM có recall ≥ recall của regex thuần.
- *Bác bỏ nếu:* H5a > 1% hoặc H5b recall thấp hơn.

> Kết quả bác bỏ giả thuyết vẫn được báo cáo đầy đủ và trung thực.

---

## 2. Dữ liệu và thu thập

- **Cửa sổ thu thập:** 2026-10-20 đến 2026-10-31 (~11 ngày), đóng băng dữ liệu ngày 2026-11-01.
- **Tần suất:** mỗi feed thu theo tần suất cập nhật công bố, tối thiểu 1 lần/ngày.
- **Feed dự kiến:** URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar, OpenPhish, Blocklist.de, CINS Army, Emerging Threats
- **Lưu trữ:** bản thô lưu nguyên vẹn, mỗi lần thu kèm timestamp UTC và SHA-256; tổng manifest hash khi đóng băng.
- **Tập báo cáo phi cấu trúc (E1):** 60–100 báo cáo/blog công khai, chọn trước khi chạy pipeline; chỉ lưu liên kết, ngày truy cập và bản trích phục vụ nghiên cứu.
- **Gán nhãn:** 2 người gán độc lập nếu có thể; tính Cohen's kappa, mục tiêu ≥ 0,7. Nếu chỉ một người, ghi rõ là hạn chế.

**Quy tắc loại trừ (cố định từ bây giờ):**
- Loại IP thuộc dải riêng/dành riêng (RFC 1918, loopback, v.v.).
- Loại domain/URL thuộc ví dụ trong tài liệu (example.com, localhost).
- Không loại bất kỳ IoC nào sau khi đã thấy kết quả chấm điểm.

---

## 3. Ground truth (định nghĩa cố định)

- **GT-1 (VirusTotal):** IoC được coi là độc hại nếu ≥ **5** engine đánh dấu malicious (hash, URL) hoặc ≥ **3** (IP, domain). Ghi ngày truy vấn; cache kết quả.
- **GT-2 (hai nguồn độc lập):** IoC xuất hiện ở ≥ 2 feed do hai tổ chức khác nhau vận hành trong cửa sổ 7 ngày.
- **GT-3 (lab, nếu có):** IoC quan sát được trong trap/log của lab.
- **Nhãn "độc hại" cuối cùng:** thỏa GT-1 hoặc GT-2 hoặc GT-3. Báo cáo kết quả theo từng mức riêng, không chỉ mức gộp.
- **Báo động giả (FP):** IoC nằm trong Tranco top 10.000 (ghi ngày tải bản snapshot), dải IP hạ tầng/CDN công khai, hoặc bị gỡ khỏi feed gốc kèm ghi chú false positive.
- **IoC "chết" (dùng cho sống sót):** domain không resolve 3 lần kiểm tra liên tiếp (mỗi ngày); URL trả lỗi/gỡ bỏ 3 lần liên tiếp; IP/hash: biến mất khỏi mọi feed trong 7 ngày. IoC còn sống đến hết cửa sổ được tính là censored.

---

## 4. Mô hình chấm điểm độ tin cậy (đặt trước)

Điểm của feed f cho loại IoC t: **S(f,t) = 0,2·A + 0,2·T + 0,2·U + 0,2·C + 0,2·St** (mỗi chiều chuẩn hóa về 0–1).

- **A (Accuracy):** tỷ lệ IoC đúng theo nhãn độc hại cuối cùng (precision).
- **T (Timeliness):** 1 − (độ trễ trung vị so với lần đầu thấy ở bất kỳ nguồn nào, chuẩn hóa min-max giữa các feed).
- **U (Uniqueness):** UTC = số IoC độc hại chỉ feed này có / tổng IoC của feed.
- **C (Context):** tỷ lệ IoC có đủ thẻ loại mối đe dọa, malware family hoặc thời điểm.
- **St (Stability):** 1 − hệ số biến thiên của số IoC mới theo ngày (chuẩn hóa), cộng tỷ lệ ngày cập nhật đúng hạn (lấy trung bình hai phần).

**Phân tích độ nhạy:** đổi mỗi trọng số ±20% (các trọng số còn lại chia lại cho tổng = 1), báo cáo thứ hạng thay đổi bao nhiêu (Kendall tau với thứ hạng gốc).
**Ánh xạ Admiralty (cố định):** S ≥ 0,80 → A; 0,65–0,79 → B; 0,50–0,64 → C; 0,35–0,49 → D; < 0,35 → E; F = không đủ dữ liệu (< 30 IoC trong cửa sổ).

---

## 4b. Chính sách suy giảm (decay)

score(t) = score0 · 2^(−t / T½). T½ khởi đầu (giả định, sẽ ước lượng từ dữ liệu): hash 90 ngày, domain 30 ngày, IP 14 ngày, URL 7 ngày. Dữ liệu chỉ có ~11 ngày, nên T½ dài sẽ ước lượng yếu; sẽ ghi rõ là hạn chế và không suy diễn ngoài cửa sổ quan sát.
**Đối chứng:** TTL cố định 7 ngày và 30 ngày.

---

## 5. Thí nghiệm và chỉ số

| Mã | Thí nghiệm | Chỉ số chính | Tiêu chí |
|----|-----------|--------------|----------|
| E1 | Trích xuất IoC | Precision, recall, macro-F1 (bootstrap 1000 lần, CI 95%) | H1 |
| E2 | Hợp lệ STIX/TAXII | % đối tượng qua stix2-validator; round-trip không mất trường bắt buộc | 100% qua validator, 0 lỗi |
| E3 | Xếp hạng feed | S(f,t), chênh lệch độ chính xác theo loại IoC trong cùng feed, bootstrap CI, đường cong độ bao phủ biên | H2 |
| E4 | Vòng đời | Kaplan-Meier, T½, FPR và recall của decay so với TTL 7/30 ngày | H3a, H3b |
| E5 | Mất mát thông tin | % thực thể/quan hệ giữ lại so với bản chuẩn gán tay | H4 |
| E7 | Hiệu quả vận hành | Thời gian xử lý trung bình trên 30 báo cáo, tay so với tự động | H4 |
| E8 | LLM trích xuất (A1) | Tỷ lệ ảo giác sau grounding check; recall; chạy lặp 3 lần | H5 |
| E9 | ML độ tin cậy (A2, tùy chọn) | AUC, precision@k; chia train/test theo thời gian | Tùy chọn |
| E6, E10, E11 | SIEM, survival động, drift (tùy chọn) | Cắt nếu trễ tiến độ | Không bắt buộc |

**Thống kê:** báo cáo khoảng tin cậy, không chỉ giá trị trung bình; có baseline cho mọi so sánh; seed ngẫu nhiên cố định = 42.
**Với mô hình AI:** ghi tên và phiên bản mô hình, temperature, prompt đầy đủ, lưu đầu ra thô kèm hash.

---

## 6. Mối đe dọa đến tính hợp lệ (dự kiến)

- Thời gian quan sát ngắn (~11 ngày) → T½ dài, ước lượng yếu.
- Ground truth dựa vào VirusTotal có thiên lệch (IoC mới có thể chưa được engine nhận diện).
- Chọn feed theo khả năng truy cập, không ngẫu nhiên.
- Gán nhãn bởi số ít người.
- Giới hạn API (rate limit) làm giảm số mẫu được enrich.

---

## 7. Ghi chú đạo đức và pháp lý

- Chỉ dùng feed công khai, tuân thủ điều khoản sử dụng và giới hạn truy cập của từng nguồn.
- Không công bố lại toàn bộ dữ liệu feed có giấy phép hạn chế; chỉ công bố số liệu tổng hợp.
- Không tấn công, không quét chủ động ngoài phạm vi cho phép; DNS/HTTP kiểm tra IoC ở mức tối thiểu cần thiết.
- Dữ liệu gửi API bên ngoài (VirusTotal, LLM) chỉ gồm dữ liệu công khai.
