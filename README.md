# Chuẩn hóa IoC sang STIX/TAXII và đánh giá độ tin cậy của Threat Feed mở

Tiểu luận môn **Thu thập và phân tích thông tin an ninh mạng** (020100117801 – 251541), Trường Đại học Gia Định.
Hạn nộp: 2026-11-04.

## Mục tiêu
1. Trích xuất IoC từ văn bản phi cấu trúc và chuẩn hóa sang STIX 2.1, chia sẻ qua TAXII 2.1.
2. Đánh giá độ tin cậy của các Threat Feed mở theo 5 chiều (chính xác, kịp thời, độc nhất, ngữ cảnh, ổn định) và theo từng loại IoC.
3. Quản lý vòng đời IoC bằng hàm suy giảm theo thời gian.
4. (Tùy chọn) Mô-đun AI: LLM trích xuất có kiểm chứng.

Giả thuyết, chỉ số và tiêu chí quyết định được viết trước khi chạy thí nghiệm: xem [`docs/PREREGISTRATION.md`](docs/PREREGISTRATION.md).

## Cấu trúc
```
docs/        đề cương tiền đăng ký, kế hoạch, đạo đức, nhật ký thay đổi
src/         mã nguồn (thu thập, trích xuất, STIX, chấm điểm, vòng đời)
scripts/     script chạy thí nghiệm E1..E8
tests/       unit test
notebooks/   phân tích và biểu đồ
data/raw/    dữ liệu thô (KHÔNG commit; chỉ commit manifest SHA-256)
data/processed/  dữ liệu đã xử lý (KHÔNG commit nếu giấy phép hạn chế)
results/     bảng, biểu đồ, kết quả cuối
```

## Tái lập
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    |  macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # điền API key
```
Các bước chạy chi tiết sẽ được bổ sung vào mục này khi hoàn thành từng module.

## Trạng thái
Xem bảng kế hoạch trong `docs/PLAN.md` và nhật ký thay đổi `docs/DEVIATIONS.md`.
