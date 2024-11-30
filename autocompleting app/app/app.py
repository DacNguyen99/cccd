import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, Text, Scrollbar, RIGHT, Y
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image, ImageTk, ImageFile
import cv2
import subprocess
import os
from docx import Document
import serial
import json
import serial.tools.list_ports
import threading
import time
import binascii
import requests
import io
import os
# import io
from component.automate_fill import fill

# ESP32-CAM URLs
ESP32_LED_ON_URL = "http://192.168.1.184/led_on"
ESP32_LED_OFF_URL = "http://192.168.1.184/led_off"
ESP32_CAPTURE_URL = "http://192.168.1.184/capture"

ImageFile.LOAD_TRUNCATED_IMAGES = True
class CCCDApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ỨNG DỤNG ĐỌC CCCD GẮN CHÍP")
        self.root.geometry("1200x600")
        root.iconbitmap(r"icon/Icon_Emoji_Raiden_Shogun_4.ico")
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Connection management
        self.connection_frame = tk.LabelFrame(root, text="Quản lý kết nối", padx=10, pady=10)
        self.connection_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nw")

        self.connection_status = tk.Label(self.connection_frame, text="Trạng thái kết nối:")
        self.connection_status.grid(row=0, column=0, sticky="w")

        self.com_port_label = tk.Label(self.connection_frame, text="Chọn cổng COM:")
        self.com_port_label.grid(row=1, column=0, sticky="w")

        self.send_button = tk.Button(self.connection_frame, text="Send Data", command=self.send_combined_data)
        self.send_button.grid(row=3, column=0, pady=5, sticky="w")

        # Status Frame
        self.status_frame = tk.LabelFrame(self.connection_frame, text="Trạng thái gửi dữ liệu", padx=10, pady=10)
        self.status_frame.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        self.status_label = tk.Label(self.status_frame, text="...", fg="blue")
        self.status_label.grid(row=3, column=1, padx=10, sticky="w")

        # Populate COM ports
        self.com_ports = self.list_com_ports()
        self.com_port_var = tk.StringVar()
        self.com_port_var.set(self.com_ports[0] if self.com_ports else 'No COM Ports')
        self.com_port_menu = ttk.Combobox(self.connection_frame, textvariable=self.com_port_var, values=self.com_ports)
        self.com_port_menu.grid(row=1, column=1, padx=10, pady=5)

        self.open_button = tk.Button(self.connection_frame, text="Mở", command=self.open_connection_thread)
        self.open_button.grid(row=2, column=0, pady=5, sticky="w")

        self.close_button = tk.Button(self.connection_frame, text="Đóng", command=self.close_connection)
        self.close_button.grid(row=2, column=1, pady=5, sticky="w")

        self.connection_status_label = tk.Label(self.connection_frame, text="Disconnected", fg="blue")
        self.connection_status_label.grid(row=0, column=1, padx=10, sticky="w")

        # Data management
        self.data_management_frame = tk.LabelFrame(root, text="Quản lý dữ liệu", padx=10, pady=10)
        self.data_management_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nw")

        self.read_button = tk.Button(self.data_management_frame, text="cam 1", command=self.open_camera_and_capture)
        self.read_button.grid(row=0, column=0, pady=5, sticky="w")
        self.read_button = tk.Button(self.data_management_frame, text="cam 2",command = self.capture_with_led )
        self.read_button.grid(row=0, column=1, pady=5, sticky="w")

        # Personal information
        self.personal_info_frame = tk.LabelFrame(root, text="Thông tin cá nhân", padx=10, pady=10)
        self.personal_info_frame.grid(row=0, column=1, padx=10, pady=10, rowspan=2, sticky="nw")

        labels = [
            "Họ và tên:", "Số CCCD:", "Ngày cấp:", "Ngày hết hạn:", "Ngày sinh:",
            "Giới tính:", "Quốc tịch:", "Dân tộc:", "Tôn giáo:", "Quê quán:", "Thường trú:",
            "Nhận dạng:", "Họ tên cha:", "Họ tên mẹ:"
        ]
        self.entries = []

        for i, label in enumerate(labels):
            tk.Label(self.personal_info_frame, text=label).grid(row=i, column=0, sticky="w")
            entry = tk.Entry(self.personal_info_frame)
            entry.grid(row=i, column=1, padx=5, pady=2)
            self.entries.append(entry)
            
        # Image display frame
        self.image_frame = tk.LabelFrame(root, text="Ảnh CCCD", padx=10, pady=10)
        self.image_frame.grid(row=0, column=2, padx=10, pady=10, rowspan=2, sticky="nw")

        self.image_label = tk.Label(self.image_frame)
        self.image_label.grid(row=0, column=0)

        # Selection management
        self.selection_frame = tk.LabelFrame(root, text="Chọn biểu mẫu", padx=10, pady=10)
        self.selection_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nw")

        self.check1_var = tk.BooleanVar()
        self.check1 = tk.Checkbutton(self.selection_frame, text="Sơ yếu lý lịch", variable=self.check1_var)
        self.check1.grid(row=0, column=0, sticky="w")

        self.export_button = tk.Button(self.selection_frame, text="Xuất biểu mẫu...", command=self.export_form, state=tk.DISABLED)
        self.export_button.grid(row=2, column=0, pady=5, sticky="w")

        # Card information
        # self.card_info_frame = tk.LabelFrame(root, text="Thông tin thẻ", padx=10, pady=10)
        # self.card_info_frame.grid(row=2, column=1, padx=10, pady=10, rowspan=3, sticky="nw")

        # self.card_info_text = tk.Text(self.card_info_frame, height=20, width=30)
        # self.card_info_text.grid(row=0, column=0)

        # Captured image display frame
        self.captured_image_frame = tk.LabelFrame(root, text="Ảnh đã chụp", padx=10, pady=10)
        self.captured_image_frame.grid(row=0, column=3, padx=10, pady=10, rowspan=3, sticky="nw")

        self.captured_image_label = tk.Label(self.captured_image_frame)
        self.captured_image_label.grid(row=0, column=0)

        # self.data_display_frame = tk.LabelFrame(root, text="Kết quả truyền dữ liệu từ ESP32", padx=10, pady=10)
        # self.data_display_frame.grid(row=3, column=1, padx=10, pady=10, rowspan=2, sticky="nw")

        # self.data_display_text = tk.Text(self.data_display_frame, height=10, width=30)
        # self.data_display_text.grid(row=0, column=0)
        
        
        # Image path
        self.image_path = None

        # Serial port
        self.ser = None

        # Data from ESP32
        self.data_from_esp32 = None

        # Khởi động cập nhật cổng COM theo thời gian thực
        self.start_periodic_com_port_update()

#cập nhật trạng thái kết nối================================================================================
    def update_connection_status(self, status):
        self.connection_status_label.config(text=status)
        self.connection_status_label.config(fg="green" if status == "Connected" else "red")

    def update_status(self, status):
        self.status_label.config(text=status)
        if status == "Success":
            self.update_export_button_state(True)
        else:
            self.update_export_button_state(False)

    def update_export_button_state(self, state):
        if state:
            self.export_button.config(state="normal")
        else:
            self.export_button.config(state="disabled")

#liệt kê cổng com và cập nhật cổng com theo thời gian=======================================================================================
    def list_com_ports(self):
        ports = [port.device for port in serial.tools.list_ports.comports()]
        return ports
    
    def update_com_ports(self):
        """Cập nhật danh sách các cổng COM và hiển thị trên giao diện."""
        com_ports = self.list_com_ports()
        self.com_port_var.set(com_ports[0] if com_ports else 'No COM Ports')
        self.com_port_menu.config(values=com_ports)

    def start_periodic_com_port_update(self):
        self.update_com_ports()  # Cập nhật ngay khi bắt đầu
        self.update_com_ports_thread = threading.Thread(target=self.periodic_update_com_ports)
        self.update_com_ports_thread.daemon = True
        self.update_com_ports_thread.start()

    def periodic_update_com_ports(self):
        """Cập nhật danh sách cổng COM theo khoảng thời gian định kỳ."""
        while True:
            self.update_com_ports()
            time.sleep(1)  # Cập nhật mỗi 1 giây

#mở và đóng kết nối với esp32=======================================================================================
    def open_connection_thread(self):
        thread = threading.Thread(target=self.open_connection)
        thread.start()

    def open_connection(self):
        com_port = self.com_port_var.get()
        if com_port == 'No COM Ports':
            messagebox.showwarning("Warning", "No COM ports available.")
            return
        try:
            self.ser = serial.Serial(com_port, 921600, timeout=1)
            time.sleep(2)
            self.connection_status_label.config(text="Connected", fg="red")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open connection: {e}")
            self.ser = None
    
    def close_connection(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            self.connection_status_label.config(text="Disconnected", fg="blue")

#mở camera và chức năng chụp=======================================================================================    
    def update_camera_frame_thread(self):
        thread = threading.Thread(target=self.update_camera_frame)
        thread.daemon = True
        thread.start()

    def open_camera_and_capture(self):
        # Open the camera window
        self.camera_window = tk.Toplevel(self.root)
        self.camera_window.title("Capture Image")
        self.camera_window.geometry("800x600")

        self.camera_frame = tk.Frame(self.camera_window)
        self.camera_frame.pack(fill=tk.BOTH, expand=True)

        self.camera_canvas = tk.Canvas(self.camera_frame, bg="black")
        self.camera_canvas.pack(fill=tk.BOTH, expand=True)

        self.capture_button = tk.Button(self.camera_window, text="Capture", command=self.capture_image)
        self.capture_button.pack(side=tk.BOTTOM, fill=tk.X)

        # Initialize the camera
        self.video_source = cv2.VideoCapture(0)
        self.update_camera_frame_thread()

    def update_camera_frame(self):
        while True:
            ret, frame = self.video_source.read()
            if ret:
                # Define the dimensions of the white rectangle
                height, width, _ = frame.shape
                rect_start = (width // 6, height // 6)
                rect_end = (5 * width // 6, 5 * height // 6)
                
                # Draw a white rectangle on the frame
                color = (255, 255, 255)  # White color
                thickness = 2  # Thickness of the rectangle border
                cv2.rectangle(frame, rect_start, rect_end, color, thickness)

                # Divide the rectangle into three equal height sections
                rect_height = rect_end[1] - rect_start[1]
                section_height = rect_height // 3
                
                for i in range(1, 3):
                    y = rect_start[1] + i * section_height
                    cv2.line(frame, (rect_start[0], y), (rect_end[0], y), color, thickness)
                    
                # Add section numbers (1, 2, 3)
                for i in range(3):
                    y = rect_start[1] + i * section_height + section_height // 2
                    section_number = str(i + 1)
                    text_position = (rect_start[0] + 10, y)
                    cv2.putText(frame, section_number, text_position, cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)
                    
                # Convert the frame to RGB format
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                image = Image.fromarray(frame_rgb)
                photo = ImageTk.PhotoImage(image)
                
                # Display the frame on the canvas
                self.camera_canvas.create_image(0, 0, anchor=tk.NW, image=photo)
                self.camera_canvas.image = photo
            else:
                break

    def capture_image(self):
        ret, frame = self.video_source.read()
        if ret:
            height, width, _ = frame.shape
            crop_frame = frame[height // 6:5 * height // 6, width // 6:5 * width // 6]
            self.image_path = "img/captured_image.png"
            cv2.imwrite(self.image_path, crop_frame)
            self.display_captured_image()
            self.process_image_with_ocr_thread()

            # Release the camera and destroy any OpenCV windows
            self.video_source.release()
            cv2.destroyAllWindows()
            
            # Close the camera window
            self.camera_window.destroy()
        else:
            messagebox.showwarning("Warning", "Failed to capture image.")

    def display_captured_image(self):
        image = Image.open(self.image_path)
        image = ImageTk.PhotoImage(image)
        self.captured_image_label.config(image=image)
        self.captured_image_label.image = image

#xử lý hình ảnh=======================================================================================
    def process_image_with_ocr_thread(self):
        """Run the process_image_with_ocr method in a separate thread."""
        thread = threading.Thread(target=self.process_image_with_ocr)
        thread.start()
    
    def process_image_with_ocr(self):
        if self.image_path:
            try:
                # Chỉ định đường dẫn chính xác đến ocr_script.py
                script_path = os.path.join('component', 'ocr_script.py')
                result = subprocess.run(['python', script_path, self.image_path], capture_output=True, text=True)
                
                # Kiểm tra lỗi từ script
                if result.returncode != 0:
                    messagebox.showerror("Error", f"OCR script error: {result.stderr}")
                    return
                
                ocr_result = result.stdout

                # Hiển thị kết quả OCR
                # self.card_info_text.delete(1.0, tk.END)
                # self.card_info_text.insert(tk.END, ocr_result)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to process image with OCR: {e}")
        else:
            messagebox.showwarning("Warning", "No image to process")

#gửi data xuống esp32=======================================================================================
    def send_combined_data(self):
        """Send combined data and show a waiting dialog."""
        # Hiển thị thông báo chờ
        self.waiting_window = tk.Toplevel(self.root)
        self.waiting_window.title("Thông Báo")
        self.waiting_window.geometry("200x100")

        # Thiết lập cửa sổ thông báo không thể thao tác
        self.waiting_window.grab_set()  # Ngăn không cho người dùng thao tác với cửa sổ chính
        self.waiting_window.transient(self.root)  # Đặt cửa sổ thông báo trên cửa sổ chính

        # Thêm màu nền mờ
        self.waiting_window.configure(bg='lightgray')

        self.waiting_label = tk.Label(self.waiting_window, text="Đang gửi dữ liệu, vui lòng đợi...", padx=10, pady=10, bg='lightgray')
        self.waiting_label.pack(expand=True)

        # Khởi chạy thread gửi dữ liệu
        thread = threading.Thread(target=self._send_combined_data_thread)
        thread.start()

    def _send_combined_data_thread(self):
        """Thread function to send combined data and handle response."""
        try:
            if self.ser and self.ser.is_open:
                combined_data = self.read_and_combine_data()
                self.ser.write(combined_data.encode() + b'\r')
                self.process_esp32_response()
            else:
                self.update_status("Fail")
                self.show_failure_notification()
            # Đóng thông báo chờ khi hoàn tất
            self.waiting_window.destroy()
        except Exception as e:
            self.update_status("success")
            self.waiting_window.destroy()

#đọc data và combine data =======================================================================================   
    def read_and_combine_data(self):
        """Read data from JSON and combine it into a single string."""
        with open('icao/result.json', 'r') as file:
            data = json.load(file)

        combined_data = '!'
        for entry in data:
            if 'cccdnumber1' in entry and 'checksum1' in entry:
                combined_data += entry['cccdnumber1'] + entry['checksum1']
            if 'birth' in entry and 'checksum3' in entry and 'expire' in entry and 'checksum4' in entry:
                combined_data += entry['birth'] + entry['checksum3'] + entry['expire'] + entry['checksum4']
        return combined_data

#giữ kết nối giữa app vs esp32=======================================================================================
    def process_esp32_response(self):
        """Process the response from ESP32."""
        while True:
            while self.ser.in_waiting == 0:
                pass
            
            response = self.ser.readline()
            response = str(response, 'utf-8').strip('\r\n')
            
            if response.startswith('@'):
                self.handle_image_response(response)
            elif response.startswith('{') and response.endswith('}'):
                self.handle_json_response(response)
                self.waiting_window.destroy()  # Đóng thông báo chờ khi nhận dữ liệu
                return  # Kết thúc vòng lặp
            else:
                self.handle_other_responses(response)
            
            # self.data_display_text.insert(tk.END, f"Received: {response}\n")

#xử lý dữ liệu gửi lên từ esp32esp32=======================================================================================  
    def handle_image_response(self, response):
        """Handle image data response."""
        data = response[1:].strip()
        data = data.replace(' ', '')
        data = data.replace('\n', '')
        data = binascii.a2b_hex(data)
        
        # Save the image data to a file
        with open('img/avatar.jpg', 'wb') as image_file:
            image_file.write(data)
        
        # Optionally, update the image display
        self.show_image()

    def handle_json_response(self, response):
        """Handle JSON data response."""
        try:
            information = json.loads(response)
            self.update_personal_info(information)
            self.update_status("Success")
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Failed to decode JSON.")

    def handle_other_responses(self, response):
        """Handle other types of responses."""
        if response == "#OKE":
            self.update_status("Success")
        elif response == "#FAIL":
            self.update_status("Fail")

#hình ảnh và thông tin=======================================================================================    
    def show_image(self):
        image_path = "img/avatar.jpg"  # Đường dẫn đến ảnh
        if os.path.exists(image_path):
            image = Image.open(image_path)
            photo = ImageTk.PhotoImage(image)
            self.image_label.config(image=photo)
            self.image_label.image = photo
        else:
            messagebox.showwarning("Warning", "Ảnh không tồn tại.")

    def update_personal_info(self, information):
        """Update personal info fields with data from JSON."""
        fields = ["Họ và tên", "Số CCCD", "Ngày cấp", "Ngày hết hạn", "Ngày sinh",
            "Giới tính", "Quốc tịch", "Dân tộc", "Tôn giáo", "Quê quán", "Thường trú",
            "Nhận dạng", "Họ tên cha", "Họ tên mẹ"]
        for i, field in enumerate(fields):
            if field in information:
                self.entries[i].delete(0, tk.END)  # Clear existing text
                self.entries[i].insert(0, information[field])  # Insert new text

#xuất biểu mẫu=======================================================================================    
    def export_form(self):
        """Export form and convert to PDF."""
        # Hiển thị thông báo chờ
        self.waiting_window = tk.Toplevel(self.root)
        self.waiting_window.title("Thông Báo")
        self.waiting_window.geometry("200x100")
        
        # Thiết lập cửa sổ thông báo không thể thao tác
        self.waiting_window.grab_set()  # Ngăn không cho người dùng thao tác với cửa sổ chính
        self.waiting_window.transient(self.root)  # Đặt cửa sổ thông báo trên cửa sổ chính
        
        # Thêm màu nền mờ
        self.waiting_window.configure(bg='lightgray')
        
        self.waiting_label = tk.Label(self.waiting_window, text="Đang xuất dữ liệu, vui lòng đợi...", padx=10, pady=10, bg='lightgray')
        self.waiting_label.pack(expand=True)
        
        # Khởi chạy thread xuất dữ liệu
        thread = threading.Thread(target=self._export_form_thread)
        thread.start()

    def _export_form_thread(self):
        """Thread function to export form and handle response."""
        try:
            if self.check1_var.get():
                # Gather data from entries
                data = {
                    "Họ và tên": self.entries[0].get(),
                    "Số CCCD": self.entries[1].get(),
                    "Ngày cấp": self.entries[2].get(),
                    "Ngày hết hạn": self.entries[3].get(),
                    "Ngày sinh": self.entries[4].get(),
                    "Giới tính": self.entries[5].get(),
                    "Quốc tịch": self.entries[6].get(),
                    "Dân tộc": self.entries[7].get(),
                    "Tôn giáo": self.entries[8].get(),
                    "Quê quán": self.entries[9].get(),
                    "Thường trú": self.entries[10].get(),
                    "Nhận dạng": self.entries[11].get(),
                    "Họ tên cha": self.entries[12].get(),
                    "Họ tên mẹ": self.entries[13].get()
                }

                template_path = 'doc/syll.docx'
                output_dir = 'doc/'  # Thư mục lưu trữ các file đầu ra

                # Sử dụng hàm fill đã được cập nhật để tạo và chuyển đổi tài liệu Word sang PDF
                pdf_path = fill(template_path, output_dir, data)
                
                # Hiển thị thông báo hoàn thành
                self.waiting_window.destroy()
                messagebox.showinfo("Info", f"Form exported and converted to PDF at {pdf_path}")
            else:
                messagebox.showwarning("Warning", "Please select a form to export.")
                self.waiting_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export form: {e}")
            self.waiting_window.destroy()

#xóa file và đóng ứng dụng=======================================================================================  
    def clear_files(self):
        # Xóa ảnh
        image_paths = ['img/captured_image.png', 'img/avatar.jpg','icao/captured_image.png']
        for image_path in image_paths:
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # Xóa file JSON
        json_path = 'icao/result.json'
        if os.path.exists(json_path):
            os.remove(json_path)
     
    def on_closing(self):
        # Hiển thị hộp thoại xác nhận thoát ứng dụng
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # Gọi hàm dọn dẹp dữ liệu
            self.clear_files()
            
            # Đóng kết nối serial nếu mở
            self.close_connection()

            # Giải phóng camera và đóng cửa sổ OpenCV nếu đang mở
            if hasattr(self, 'video_source') and self.video_source.isOpened():
                self.video_source.release()
            cv2.destroyAllWindows()
            
            # Dừng các thread đang chạy nếu cần
            if hasattr(self, 'update_com_ports_thread'):
                self.update_com_ports_thread.join(timeout=1)  # Đợi thread dừng lại

            # Xác nhận đóng ứng dụng
            self.root.destroy()
#============================================================
    def led_on(self):
        # try:
            response = requests.get(ESP32_LED_ON_URL)
        #     if response.status_code == 200:
        #         status_label.config(text="LED is ON", fg="green")
        #     else:
        #         status_label.config(text="Failed to turn ON LED", fg="red")
        # except Exception as e:
        #     status_label.config(text=f"Error: {e}", fg="red")
    
    def led_off(self):
        # try:
            response = requests.get(ESP32_LED_OFF_URL)
        #     if response.status_code == 200:
        #         status_label.config(text="LED is OFF", fg="green")
        #     else:
        #         status_label.config(text="Failed to turn OFF LED", fg="red")
        # except Exception as e:
        #     status_label.config(text=f"Error: {e}", fg="red")

    def capture_with_led(self):
        self.led_on()  # Turn on the LED
        root.after(1000, self.capture_and_turn_off_led)  # Wait 1 second, then capture and turn off LED

    def capture_and_turn_off_led(self):
        self.capture_image_esp()  # Capture the image
        root.after(500, self.led_off)  # Wait 0.5 seconds, then turn off the LED

    def capture_image_esp(self):
        # try:
            response = requests.get(ESP32_CAPTURE_URL)
            if response.status_code == 200:
                # Convert the image data from the response
                image_data = response.content
                image = Image.open(io.BytesIO(image_data))

                # Save the image to 'captured_images' folder
                self.image_path = "img/captured_image.jpg"  # Customize file name and path
                image.save(self.image_path)
                
                self.process_image_with_ocr_thread()

                # show_captured_image(image)
                # status_label.config(text="Image captured and saved!", fg="green")

                # Process OCR and display result
                # ocr_data = process_images(img_path)
                # display_ocr_result(ocr_data)
        #     else:
        #         status_label.config(text="Failed to capture image", fg="red")
        # except Exception as e:
        #     status_label.config(text=f"Capture Error: {e}", fg="red")
    # Function to capture an image with LED control

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = CCCDApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
