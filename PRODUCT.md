# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Sinh viên trình diễn đồ án an toàn thông tin cho giảng viên trong buổi báo cáo hoặc bảo vệ.

## Product Purpose

Ứng dụng minh họa trọn vẹn quy trình bảo vệ thư điện tử: tạo danh tính mật mã, ký số, mã hóa lai, vận chuyển payload, giải mã, xác minh chữ ký và phát hiện dữ liệu bị chỉnh sửa.

## Positioning

Một phòng lab tương tác cho phép người trình bày vừa thực hiện thao tác thật vừa giải thích trực tiếp vai trò của AES-GCM, RSA-OAEP, RSA-PSS và SHA-256 trong cùng một luồng.

## Operating Context

Ứng dụng được chiếu trên màn hình trong buổi trình diễn. Người thuyết trình cần đi theo kịch bản Alice gửi thư cho Bob, quan sát trạng thái từng bước và chứng minh cơ chế chống sửa đổi bằng mô phỏng MITM.

## Capabilities and Constraints

- Giữ Streamlit và ba năng lực chính: quản lý khóa, mã hóa/gửi thư, giải mã/thẩm định.
- Hỗ trợ hộp thư mô phỏng cục bộ và Gmail qua SMTP/IMAP khi đã cấu hình.
- Không làm lộ khóa riêng, App Password hoặc nội dung bí mật trong log và thông báo lỗi.
- Giao diện phải phục vụ trình diễn theo trình tự nhưng vẫn cho phép tải khóa và payload tùy chỉnh.

## Evidence on Hand

- Đặc tả đồ án: `BanThao_Nhom14.docx`.
- Ứng dụng và nội dung trình diễn hiện có: `app.py`.
- Bộ kiểm thử cho mật mã, email và smoke test Streamlit: `tests/`.

## Product Principles

- Luồng trình diễn phải rõ ràng ngay cả với người lần đầu nhìn thấy ứng dụng.
- Mỗi thao tác quan trọng phải cho thấy thuật toán đang làm gì và tạo ra kết quả nào.
- Kết quả hợp lệ, lỗi và phát hiện tấn công phải khác biệt rõ ràng nhưng không phô trương.
- Chức năng nâng cao không được cản trở kịch bản demo mặc định.

## Accessibility & Inclusion

Giao diện cần sử dụng được bằng bàn phím, có tương phản rõ và thích ứng với màn hình laptop hoặc thiết bị hẹp.
