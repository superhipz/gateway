# Ad* Specification
					
I. Giới thiệu chung :
	Hệ thống được thiết kế và xây dựng dựa trên ý tưởng về tối về chất lượng cũng như báo cáo
của người dùng trên facebook.

II. Mô tả chức năng


a. Module Auth :

	-  Đăng ký/ Đăng nhập từ gmail 
	-  Kết nối tài tài khoản Ad* với tài khoản fb và các tài khoản quảng cáo
	-  Phân quyền gắn 1 tài khoản người dùng trong tổ chức được quyền access vào campain( viewer/editor/manager)

b. Module integration :

	-  Người dùng lựa chọn tài khoản  quảng cáo để đồng bộ dữ liệu
	- Thống kê trạng thái  quảng cáo + biểu đồ thống kê theo thời gian
	- Hệ thống tự động lấy dữ liệu thống kê của các tài khoản từ facebook
	

c. Module hiển thị quảng cáo: 

	- Hiển thị danh sách quảng cáo của người dùng theo 3 phân tầng chính : 			campain,ad set, ads
	- Hiển thị chi tiết thống tin các phân mục ( trạng thái chi tiết)
	
d. Module quản trị hệ thống

	- Quản lý tài khoản khách hàng ( nạp tiền, gia hạn, block)
	- Xem lượng request
	- Export báo cáo
	- Xem các quảng cáo của người dùng + gắn mác quảng cáo ( add tag)

e. Notification

	- Báo cáo ngưỡng quảng cáo ra chat bot cho người dùng
	- Mail thống kê hoạt đồng theo ngày + tháng
	
f. Kịch bản auto quảng cáo 

	- Tạo các kịch bản quảng cáo chạy theo tài khoản hoặc campain hoặc adset hay như tag của tài khoản
	- Import quảng cáo từ xls.
	- Đặt ra các rule cho việc chạy quảng cáo
