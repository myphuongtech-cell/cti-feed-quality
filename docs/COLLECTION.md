# Hướng dẫn chạy thu thập

## 1. Chuẩn bị (một lần)
```
pip install -r requirements.txt
cp .env.example .env     # Windows: copy .env.example .env
```
Mở `.env` điền:
- `CONTACT_EMAIL`: email của bạn (đưa vào User-Agent để nhà cung cấp biết ai tải).
- `ABUSECH_AUTH_KEY`: (nếu cần) khóa miễn phí đăng ký tại abuse.ch.

## 2. Chạy một lượt để xem kết quả
```
python -m src.collector
python -m src.collector --status
```
`--status` in bảng: mỗi feed đã tải mấy lượt, bao nhiêu lượt thành công, lỗi bao nhiêu. Feed trả 401/403 thì cần Auth-Key (xem trên); feed trả 404 thì địa chỉ đã đổi, kiểm tra lại trang chủ của feed và báo mình để sửa `config/feeds.yaml`.

## 3. Cho chạy tự động mỗi giờ (chọn MỘT cách)

**A. Không cần cài gì thêm (đơn giản nhất):** mở một terminal và để chạy
```
python -m src.collector --loop 60
```
Máy phải bật và không sleep trong suốt thời gian thu thập (tắt chế độ Sleep trong Power Settings).

**B. Linux/macOS/VPS (cron):** `crontab -e` rồi thêm dòng (đổi đường dẫn):
```
5 * * * * /đường/dẫn/tới/repo/scripts/run_collect.sh
```

**C. Windows (Task Scheduler):** Create Task → Trigger: Daily, Repeat every 1 hour, for a duration of 1 day → Action: Start a program
- Program: `C:\đường\dẫn\repo\.venv\Scripts\python.exe`
- Arguments: `-m src.collector`
- Start in: `C:\đường\dẫn\repo`

## 4. Khuyến nghị
- Để thu liên tục 11 ngày mà không gián đoạn, thuê một VPS nhỏ rẻ nếu có điều kiện.
- Mỗi ngày chạy `python -m src.collector --status` một lần, thấy feed nào toàn lỗi thì xử lý ngay (khoảng trống trong dữ liệu không bù lại được).
- Sao lưu thư mục `data/` mỗi 1–2 ngày (Google Drive hoặc ổ ngoài).
- Commit `data/manifest/manifest.jsonl` mỗi ngày, nhưng **không** commit `data/raw/`.
