# Nhật ký thay đổi so với đề cương (deviations log)

Mọi thay đổi sau tag `prereg-v2` ghi tại đây: ngày, thay đổi gì, vì sao, ảnh hưởng đến kết luận.

## Sửa đổi từ v1 sang v2 (sau lần tải pilot, trước tag prereg-v2)

Bản v1 (`prereg-v1`, commit `ff52514`, 08:15 UTC) có 8 feed và các định nghĩa ban đầu, được tạo **trước** lần tải pilot. Các sửa đổi dưới đây được làm **sau lần tải pilot 2026-10-21 08:28 UTC** và **trước tag `prereg-v2`**. Căn cứ chỉ là cấu trúc dữ liệu (số dòng, tiêu đề, ngày cập nhật), chưa có phân tích chất lượng nào.

| Ngày | Thay đổi | Lý do | Ảnh hưởng |
|------|----------|-------|-----------|
| 2026-10-21 | Cửa sổ thu thập đổi từ 20/10 sang 21/10 08:00 UTC | Bắt đầu thu thập muộn một ngày | Ngắn hơn ~1 ngày, ghi trong mục hạn chế |
| 2026-10-21 | Loại Feodo Tracker (8 feed còn 7) | Chỉ 5 bản ghi, cập nhật cuối 2026-03-04 | Ít feed IP có dấu thời gian nguồn hơn |
| 2026-10-21 | Viết lại H2 (so sánh độ chính xác giữa các loại IoC trong cùng feed) | Phần lớn feed chỉ có một loại IoC nên xếp hạng chéo không có nghĩa | Kiểm tra H2 chủ yếu dựa vào ThreatFox |
| 2026-10-21 | Tách thời gian nằm trong feed và thời gian còn hoạt động; H3b chuyển thành khám phá | Feed dạng cửa sổ trượt/giới hạn trên (URLhaus, ThreatFox, MalwareBazaar, OpenPhish, CINS) | Không kết luận chính sách TTL tối ưu |
| 2026-10-21 | Định nghĩa lại T chỉ trên IoC xuất hiện ở ≥ 2 feed | Nhiều feed không có dấu thời gian nguồn | Một số feed ghi "không đủ dữ liệu" cho T |

## Sau tag prereg-v2

| Ngày | Thay đổi | Lý do | Ảnh hưởng |
|------|----------|-------|-----------|
| | | | |
