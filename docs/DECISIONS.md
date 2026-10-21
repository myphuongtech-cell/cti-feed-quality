# Các quyết định thiết kế và lý do

Viết ngày 2026-10-19, **trước lần thu thập đầu tiên**. Mỗi quyết định ghi rõ lý do và mức chắc chắn. Chỗ nào là lập luận hợp lý của người làm (không phải kết quả của một nghiên cứu cụ thể) thì ghi là "lập luận".

## 1. Chọn 7 feed (config/feeds.yaml)

**Tiêu chí chọn (cố định trước):**
1. Công khai, miễn phí cho mục đích học thuật, tải được bằng HTTP đơn giản.
2. Phủ đủ 4 loại IoC: IP, domain, URL, hash (để kiểm tra giả thuyết H2 về thứ hạng theo loại IoC).
3. Có nhiều tổ chức vận hành khác nhau (để kiểm tra "hai nguồn độc lập", GT-2).
4. Cập nhật đủ thường xuyên để đo độ kịp thời và vòng đời trong ~11 ngày.

**Kết quả:** URLhaus (url), ThreatFox (ip/domain/url/hash), MalwareBazaar (hash), OpenPhish (url), Blocklist.de (ip), CINS Army (ip), Emerging Threats compromised IPs (ip). Feodo Tracker ban đầu nằm trong danh sách nhưng bị loại sau pilot (xem phụ lục).

**Lý do khoa học:** các nghiên cứu so sánh feed (ví dụ Li et al., 2019) cho thấy các feed trùng nhau rất ít và chất lượng khác nhau nhiều, nên đa dạng nguồn mới cho bức tranh có ý nghĩa (bạn nên đọc lại bài để xác nhận cách diễn đạt trước khi trích).

**Hạn chế phải ghi vào báo cáo:** 3 trong 7 feed cùng thuộc abuse.ch, nên khi kiểm tra GT-2 phải đếm theo **operator** (chỉ có 5 operator), không đếm theo feed. Việc chọn feed theo khả năng truy cập, không ngẫu nhiên.

**Loại có chủ đích:** Spamhaus DROP. Lý do: đơn vị là dải mạng (CIDR), không phải IoC đơn lẻ; danh sách thay đổi chậm và được đánh giá lại hằng ngày nên gần như không có biến động để đo vòng đời trong 11 ngày; và không so sánh công bằng được với feed IoC đơn lẻ. AlienVault OTX cũng loại vì cần tài khoản và API key, làm chậm bắt đầu thu thập.

## 2. Tần suất thu thập: mỗi giờ

- **Lập luận:** độ kịp thời (Timeliness) và thời điểm "IoC chết" chỉ đo được với độ phân giải bằng chu kỳ lấy mẫu. Lấy mỗi giờ cho sai số tối đa ~1 giờ, đủ cho thời gian sống tính bằng ngày. Lấy mỗi ngày thì sai số 24 giờ, quá thô cho feed có vòng đời ngắn như URL.
- **Giới hạn lịch sự:** khoảng cách tối thiểu 60 phút giữa hai lần tải cùng một feed, dùng conditional GET (ETag/Last-Modified) để giảm tải cho nhà cung cấp. Nếu nhà cung cấp yêu cầu giãn hơn thì tăng `min_interval_minutes` trong cấu hình và ghi vào `DEVIATIONS.md`.
- Lấy mẫu liên tục, đều đặn, **không chọn thời điểm** để tránh thiên lệch chọn mẫu.

## 3. Lưu dữ liệu thô bất biến + manifest

- Mỗi lần tải ghi một dòng vào `data/manifest/manifest.jsonl` (thời gian UTC, status, số byte, SHA-256, đường dẫn, lỗi), kể cả khi nội dung không đổi hoặc tải lỗi.
- **Lý do:** lỗi tải (feed ngừng, bị chặn) cũng là dữ liệu cho chiều Stability (ổn định); không ghi thì mất thông tin. Hash cho phép chứng minh dữ liệu không bị sửa sau khi thu.
- Lưu nén gzip với `mtime=0` để cùng nội dung cho cùng byte (tái lập hash).
- `data/raw/` không commit (dung lượng, giấy phép); chỉ commit `manifest.jsonl`.

## 4. Mốc thời gian

- Cửa sổ phân tích chính thức (theo PREREGISTRATION): **2026-10-20 00:00 UTC đến 2026-10-31 23:59 UTC**.
- Dữ liệu thu trước 20/10 (nếu bạn chạy từ hôm nay) dùng làm **pilot** để kiểm tra pipeline và hiệu chỉnh, không đưa vào phân tích chính. Ghi việc này vào `DEVIATIONS.md`.

## 5. Ground truth và giới hạn VirusTotal

- API miễn phí của VirusTotal có giới hạn (khoảng 4 yêu cầu mỗi phút và vài trăm yêu cầu mỗi ngày; **kiểm tra lại giới hạn hiện hành** trước khi lên kế hoạch). Vì vậy không thể tra mọi IoC.
- **Quyết định:** lấy **mẫu phân tầng ngẫu nhiên** theo feed × loại IoC, tối đa khoảng 100–150 IoC mỗi tầng, seed cố định 42. Báo cáo kết quả kèm khoảng tin cậy.
- **Tra cứu muộn:** tra mỗi IoC sau ít nhất 48 giờ kể từ lần đầu thấy. *Lập luận:* các engine chống mã độc cần thời gian để nhận diện; tra quá sớm sẽ đánh giá thấp độ chính xác của feed mới. Phải ghi rõ độ trễ này là một lựa chọn và nêu trong mục hạn chế.

## 6. Mô hình chấm điểm

Giữ nguyên trong PREREGISTRATION: 5 chiều, trọng số đều 0,2 và phân tích độ nhạy ±20%. **Lập luận:** khi chưa có cơ sở để ưu tiên chiều nào, trọng số đều là điểm xuất phát ít áp đặt nhất; độ nhạy cho biết kết luận có phụ thuộc lựa chọn đó không. Không dùng AHP vì cần ý kiến chuyên gia mà đề tài không có.

## 7. Việc phải làm trước khi chạy lần đầu

1. Điền danh sách feed trong `docs/PREREGISTRATION.md` mục 2 cho khớp `config/feeds.yaml`.
2. Commit và push `config/feeds.yaml` cùng file này **trước** khi chạy collector. Commit này là mốc thời gian cho "feed đã được chọn trước khi thấy dữ liệu".
3. Đọc điều khoản sử dụng của từng nguồn và ghi vào bảng feed của báo cáo. abuse.ch hiện có cổng đăng nhập và có thể yêu cầu Auth-Key; nếu một feed trả 401/403 thì đăng ký key miễn phí và đặt `ABUSECH_AUTH_KEY` trong `.env`.


---

## Phụ lục: điều chỉnh sau lần tải pilot (2026-10-21)

Sau lần tải đầu (08:28 UTC) mình chỉ xem cấu trúc dữ liệu (số dòng, tiêu đề, ngày cập nhật) và chưa tính bất kỳ chỉ số chất lượng nào. Ba điều chỉnh:

1. **Loại Feodo Tracker.** Chỉ có 5 bản ghi, ngày cập nhật cuối 2026-03-04, nên không đủ dữ liệu để đo độ kịp thời hay vòng đời trong 10 ngày. Không thay bằng feed khác để khỏi chia mỏng hạn mức tra VirusTotal; hạn chế "ít feed IP có thời gian nguồn" ghi vào báo cáo.
2. **Viết lại H2.** Hầu hết feed chỉ có một loại IoC, nên xếp hạng feed giữa các loại IoC không có nghĩa. H2 mới so sánh độ chính xác giữa các loại IoC trong cùng một feed (chủ yếu ThreatFox).
3. **Tách "thời gian nằm trong feed" khỏi "thời gian còn hoạt động".** URLhaus, ThreatFox, MalwareBazaar là cửa sổ trượt "recent", OpenPhish chỉ ~300 dòng, CINS đúng 15.000 dòng: IoC biến mất khỏi các feed này không có nghĩa là hết độc hại. Định nghĩa "IoC chết = biến mất khỏi mọi feed" bị bỏ.
4. **Định nghĩa lại T (độ kịp thời).** Nhiều feed là danh sách trần không có dấu thời gian nguồn, nên T chỉ tính trên IoC xuất hiện ở ≥ 2 feed: feed nào quan sát thấy IoC đầu tiên.
