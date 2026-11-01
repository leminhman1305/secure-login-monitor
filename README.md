# Secure Login Monitor

Website thực hành xác thực người dùng và phát hiện dấu hiệu
brute force bằng Python/Flask.

## Chức năng

- Đăng nhập, đăng xuất và quản lý session.
- Lưu mật khẩu dưới dạng hash Argon2id.
- Bảo vệ form bằng CSRF token.
- Giới hạn đăng nhập sai theo IP và cặp IP/username.
- Ghi nhật ký IP, thời gian UTC và kết quả đăng nhập.
- Trang nhật ký dành riêng cho quản trị viên.
- Kiểm thử tự động bằng pytest.

## Công nghệ

Python 3.12, Flask, Flask-WTF, SQLite, argon2-cffi,
HTML/CSS và pytest.

## Cài đặt trên Windows

Mở PowerShell tại thư mục dự án:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Tạo tài khoản thử nghiệm:

```powershell
.\.venv\Scripts\python.exe -m flask --app app create-user
```

Chương trình yêu cầu username và mật khẩu.
Không có tài khoản hay mật khẩu mặc định.

Cấp quyền quản trị cho tài khoản đã tạo:

```powershell
.\.venv\Scripts\python.exe -m flask --app app promote-admin --username admin
```

Thay admin bằng username thực tế.

## Chạy ứng dụng

```powershell
.\.venv\Scripts\python.exe app.py
```

Mở http://127.0.0.1:5000.

- `/`: đăng nhập.
- `/dashboard`: trang yêu cầu đăng nhập.
- `/security`: nhật ký dành cho quản trị viên.
- `POST /logout`: đăng xuất.

Database được tạo tự động tại `instance/security.db`.

## Quy tắc phát hiện

| Phạm vi | Ngưỡng | Xử lý |
|---|---|---|
| Cùng IP và username | 5 lần sai trong 5 phút | Chặn cặp đó 5 phút |
| Cùng IP, bất kể username | 20 lần sai trong 5 phút | Chặn IP 5 phút |

- Lần sai chạm ngưỡng trả về HTTP 429.
- Request bị chặn có header Retry-After.
- Mật khẩu đúng không vượt qua thời gian chặn.
- Lượt thử trong thời gian bị chặn không gia hạn thời gian chặn.
- Các lần sai trong cửa sổ vẫn được đếm dù có lần thành công xen giữa.
- Trạng thái giới hạn được lưu trong SQLite.

Cảnh báo vượt ngưỡng là dấu hiệu cần kiểm tra,
không khẳng định đã xảy ra tấn công.

## Nhật ký

Các sự kiện:

- success: đăng nhập thành công.
- failure: thông tin đăng nhập sai.
- alert: vượt ngưỡng.
- blocked: thử đăng nhập khi đang bị chặn.

Mỗi sự kiện có IP, username được nhập, thời gian UTC và lý do.
Không ghi mật khẩu, session cookie hoặc CSRF token vào nhật ký.

Trang quản trị hiển thị 100 sự kiện mới nhất và thống kê
toàn bộ sự kiện đã lưu.

## Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Sáu bài kiểm thử kiểm tra:

- Đăng nhập thành công và ghi log.
- Mật khẩu sai.
- Chặn theo cặp IP/username và hết hạn chặn.
- Chặn theo IP khi thay đổi username.
- Phân quyền trang nhật ký.
- Từ chối form thiếu CSRF token.

Test dùng database tạm và đồng hồ giả cho thời gian chặn.

## Cấu hình session

Ứng dụng đọc SECRET_KEY từ biến môi trường.
Nếu chưa cấu hình, khóa được tạo ngẫu nhiên mỗi lần khởi động,
khiến session cũ mất hiệu lực.

Session mặc định của Flask được ký, không được mã hóa.
Ứng dụng chỉ lưu ID người dùng trong session.

## Hạn chế

- Dự án học tập, chạy local bằng development server.
- Chưa phát hiện brute force phân tán từ nhiều IP.
- Thiết bị chung IP có thể ảnh hưởng lẫn nhau khi bị giới hạn.
- IP localhost là 127.0.0.1 khi thử trên cùng máy.
- Không tự tin cậy X-Forwarded-For do client cung cấp.
- SQLite tuần tự hóa xử lý đăng nhập để tránh vượt ngưỡng;
  chưa phù hợp với tải đăng nhập lớn.
- Nhật ký chưa có cơ chế tự dọn hoặc thời hạn lưu.
- Trước triển khai thực tế cần HTTPS, secure cookie,
  cấu hình proxy tin cậy và quản lý secret ổn định.

Database, log cá nhân và secret không được đưa vào repository.
Chỉ dùng tài khoản giả để thử nghiệm và chụp ảnh demo.