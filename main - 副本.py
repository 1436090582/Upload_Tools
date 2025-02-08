import sys
import os
import json
import logging
import pandas as pd
import requests
import time  # 引入time模块以实现延迟
from tkinter import Tk, Toplevel, Label, Entry, Button, OptionMenu, StringVar, Text, Scrollbar, Frame, DISABLED, NORMAL, END
from tkinter.font import Font
from tkinter import filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk
from tkinter import BOTTOM, Label, CENTER

# API配置
BASE_URL = "http://192.168.1.79:8090/emes/api"
LOGIN_URL = f"{BASE_URL}/Auth/login"
LINE_URL = f"{BASE_URL}/StationUploadAuth/GETLine"
WORK_ORDER_URL = f"{BASE_URL}/StationUploadAuth/GETPLAN_DAILY"
PROCESS_URL = f"{BASE_URL}/StationUploadAuth/FetchTechnisflow"
UPLOAD_URL = f"{BASE_URL}/StationUploadAuth/LogUpload"

# 添加两个新API接口路径
CHECK_PPID_URL = f"{BASE_URL}/fnSNInfoAuth/GetSNstationInfo"
QUERY_PPID_INFO_URL = f"{BASE_URL}/fnSNInfoAuth/GetSNAssociateInfoPRO"


# 设置日志记录
logging.basicConfig(
    filename="program_log.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.DEBUG
)
logger = logging.getLogger()

# 全局变量
log_dir = None
observer = None
processed_files = set()
debug_text = None
is_collecting = False  # 初始为True，表示正在采集


def debug_log(message, output_widget=None):
    if output_widget and isinstance(output_widget, Text):
        output_widget.config(state=NORMAL)
        output_widget.insert(END, message + "\n")
        output_widget.see(END)
        output_widget.config(state=DISABLED)
    logger.debug(message)

def save_processed_files():
    try:
        with open('processed_files.json', 'w') as f:
            json.dump(list(processed_files), f)
        debug_log("已处理文件记录已保存到 processed_files.json")
    except Exception as e:
        debug_log(f"保存已处理文件记录失败: {e}")

def load_processed_files():
    global processed_files
    try:
        if os.path.exists('processed_files.json') and os.path.getsize('processed_files.json') > 0:
            with open('processed_files.json', 'r') as f:
                processed_files = set(json.load(f))
            debug_log(f"已处理文件记录已从 processed_files.json 加载: {processed_files}")
        else:
            debug_log("processed_files.json 文件不存在或为空，初始化为空集合")
            processed_files = set()
    except Exception as e:
        debug_log(f"加载已处理文件记录失败: {e}")
        processed_files = set()



# 获取线体数据
def get_lines(token):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json;charset=UTF-8"}
    response = requests.post(LINE_URL, headers=headers, json={"WORKSHOPNAME": ""})
    if response.status_code == 200 and response.json().get("retCode") == "1":
        return [item["LINECODE"] for item in response.json().get("Data", [])]
    else:
        debug_log("获取线体数据失败")
        return []


# 获取工单数据
def get_work_orders(token, line_code, filter_text=""):
    """获取工单数据并支持过滤"""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json;charset=UTF-8"}
    response = requests.post(WORK_ORDER_URL, headers=headers, json={"LINECODE": line_code})
    if response.status_code == 200 and response.json().get("retCode") == "1":
        orders = [item["DAYPLAN_NO"] for item in response.json().get("Data", [])]
        if filter_text:
            return [order for order in orders if filter_text in order]
        return orders
    else:
        debug_log("获取工单数据失败")
        return []

# 获取工艺路线数据
def get_processes(token, work_order):
    if work_order == "请选择工单" or not work_order.strip():
        debug_log("工单号无效，无法请求工艺路线数据。")
        return []

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json;charset=UTF-8"}
    request_data = {"DAYPLAN_NO": work_order}

    try:
        debug_log(f"请求工艺路线数据: URL={PROCESS_URL}, 数据={request_data}")
        response = requests.post(PROCESS_URL, headers=headers, json=request_data)

        debug_log(f"工艺路线数据响应状态码: {response.status_code}")
        debug_log(f"工艺路线数据响应内容: {response.text}")

        if response.status_code == 200:
            response_data = response.json()
            debug_log(f"工艺路线数据解析结果: {response_data}")

            if response_data.get("retCode") == "1":
                return [item["TFNAME"] for item in response_data.get("Data", [])]
            else:
                debug_log(f"工艺路线数据返回错误: {response_data.get('Message', '未知错误')}")
                return []
        else:
            debug_log(f"请求工艺路线数据失败，HTTP状态码: {response.status_code}")
            return []
    except Exception as e:
        debug_log(f"请求工艺路线数据时发生异常: {e}")
        return []





def validate_ppid(token, ppid, work_order, process_code):
    """
    验证 PPID 是否有效
    """
    debug_log(f"验证 PPID 开始: PPID={ppid}, 工单={work_order}, 工序={process_code}")

    url = f"{BASE_URL}/fnSNInfoAuth/GetSNStationInfo"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json;charset=UTF-8"}
    request_data = {
        "OperationName": process_code,  # 用户选择的工序
        "SerialNumber": ppid,  # 文件名作为 SerialNumber（即 PPID）
        "WorkOrderNumber": work_order,  # 用户选择的工单号
        "StationName": "PPID"  # 固定值
    }

    try:
        debug_log(f"发送 PPID 校验请求到: {url}")
        debug_log(f"请求数据: {request_data}")

        response = requests.post(url, headers=headers, json=request_data)

        debug_log(f"PPID 校验响应状态码: {response.status_code}")
        debug_log(f"PPID 校验响应内容: {response.text}")

        if response.status_code == 200:
            response_data = response.json()
            debug_log(f"PPID 校验解析结果: {response_data}")

            if response_data.get("retCode") == "1":
                debug_log(f"PPID 校验通过: {ppid}")
                return True
            else:
                error_message = response_data.get("Message", "未知错误")
                debug_log(f"PPID 校验失败，错误信息: {error_message}")
                messagebox.showerror("校验失败", f"PPID {ppid} 校验失败: {error_message}")
        else:
            debug_log(f"PPID 校验请求失败，HTTP 状态码: {response.status_code}")
            messagebox.showerror("校验失败", f"PPID 校验请求失败，请检查网络连接。状态码: {response.status_code}")
    except Exception as e:
        debug_log(f"PPID 校验请求发生错误: {e}")
        messagebox.showerror("校验失败", f"PPID 校验请求发生错误: {e}")

    debug_log(f"PPID 校验结束，结果: False")
    return False

    # 查询PPID关联信息


def query_ppid_info(token, ppid):
    """
    查询 PPID 的关联信息
    """
    debug_log(f"查询 PPID 信息开始: PPID={ppid}")

    url = f"{BASE_URL}/fnSNInfoAuth/GetSNAssociateInfoPRO"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json;charset=UTF-8"}
    request_data = {"SerialNumber": ppid, "CodeType": "PPID"}

    try:
        debug_log(f"发送 PPID 信息查询请求到: {url}")
        debug_log(f"请求数据: {request_data}")

        response = requests.post(url, headers=headers, json=request_data)

        debug_log(f"PPID 信息查询响应状态码: {response.status_code}")
        debug_log(f"PPID 信息查询响应内容: {response.text}")

        if response.status_code == 200:
            response_data = response.json()
            debug_log(f"PPID 信息查询解析结果: {response_data}")

            if response_data.get("retCode") == "1":
                debug_log(f"成功获取 PPID 关联信息: {response_data.get('Data')}")
                return response_data.get("Data")
            else:
                error_message = response_data.get("Message", "未知错误")
                debug_log(f"PPID 信息查询失败，错误信息: {error_message}")
                messagebox.showerror("查询失败", f"获取 PPID {ppid} 信息失败: {error_message}")
        else:
            debug_log(f"PPID 信息查询请求失败，HTTP 状态码: {response.status_code}")
            messagebox.showerror("查询失败", f"PPID 信息查询请求失败，请检查网络连接。状态码: {response.status_code}")
    except Exception as e:
        debug_log(f"PPID 信息查询请求发生错误: {e}")
        messagebox.showerror("查询失败", f"PPID 信息查询请求发生错误: {e}")

    debug_log(f"查询 PPID 信息结束，结果: None")
    return None


# 上传日志数据
def upload_log(token, operation_name, serial_number, code_type, log_content, customer_name, operate_result):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json;charset=UTF-8"
    }

    log_data = {
        "OperationName": operation_name,
        "SerialNumber": serial_number,
        "CodeType": code_type,
        "LogData": json.dumps(log_content),
        "CustomerName": customer_name,
        "OperateResult": operate_result
    }

    debug_log(f"发送日志上传请求到 {UPLOAD_URL}，请求数据：{log_data}", debug_text)

    try:
        response = requests.post(UPLOAD_URL, headers=headers, json=log_data)
        response_data = response.json()
        if response.status_code == 200 and response_data.get("retCode") == "1":
            debug_log(f"日志上传成功：{serial_number}", debug_text)
        else:
            error_message = response_data.get("Message", "未知错误")
            debug_log(f"日志上传失败：{error_message}", debug_text)
            messagebox.showerror("上传失败", f"日志上传失败：{error_message}")
    except Exception as e:
        debug_log(f"日志上传请求失败：{e}", debug_text)
        messagebox.showerror("上传失败", f"日志上传请求失败：{e}")

# 处理日志文件
# 更新后的日志文件处理逻辑
def process_log_file(token, file_path, operation_name, process_code):
    global processed_files  # 确保访问全局变量
    if file_path in processed_files:  # 检查文件是否已处理
        debug_log(f"文件已处理，跳过: {file_path}")
        return
    """处理单个日志文件，包括校验和上传"""
    debug_log(f"开始处理文件: {file_path}")
    try:
        # 获取文件名作为 PPID
        ppid = os.path.basename(file_path).split('.')[0]
        debug_log(f"从文件名解析 PPID: {ppid}")

        if not ppid or not ppid.strip():
            debug_log(f"无效文件名，跳过文件: {file_path}")
            return

        # 尝试读取文件内容
        # 尝试读取文件内容
        try:
            data = pd.read_csv(file_path, encoding='utf-8')
        except UnicodeDecodeError:
            debug_log(f"UTF-8 解码失败，尝试 GBK 解码: {file_path}")
            try:
                data = pd.read_csv(file_path, encoding='gbk')
            except Exception as e:
                debug_log(f"读取文件失败，跳过文件: {file_path}, 错误信息: {e}")
                return  # 遇到读取错误直接跳过
        except Exception as e:
            debug_log(f"读取文件时发生未知错误: {e}")
            return

        # 判断文件是否包含失败项
        if '结果' in data.columns and data['结果'].str.upper().isin(["FAIL", "NG"]).any():
            operate_result = "NG"
            debug_log(f"文件 {file_path} 包含失败项，处理失败")
        else:
            operate_result = "OK"
            debug_log(f"文件 {file_path} 处理成功")

        # 上传日志数据
        log_content = data.to_dict(orient="records")
        upload_log(token, operation_name, ppid, process_code, log_content, "客户名", operate_result)

        # 标记文件为已处理
        processed_files.add(file_path)
        debug_log(f"文件处理完成并标记为已处理: {file_path}")
    except Exception as e:
        debug_log(f"处理文件 {file_path} 时出错: {e}")

# 扫描目录中的现有文件
def scan_directory(token, operation_name, process_code, line_code):
    global log_dir
    debug_log(f"进入 scan_directory 函数: token={token}, 工单={operation_name}, 工序={process_code}, 线体={line_code}")
    if not log_dir:
        debug_log("日志目录未选择，无法扫描。")
        return

    debug_log(f"扫描目录: {log_dir}, 已处理文件: {processed_files}")
    for filename in os.listdir(log_dir):
        file_path = os.path.join(log_dir, filename)

        # 检查是否是文件
        if os.path.isfile(file_path):
            debug_log(f"发现文件: {file_path}")
            # 检查文件是否已处理
            if file_path not in processed_files:
                debug_log(f"调用 process_log_file 处理文件: {file_path}")
                process_log_file(token, file_path, operation_name, process_code)
            else:
                debug_log(f"文件已处理，跳过: {file_path}")
        else:
            debug_log(f"非文件对象，跳过: {file_path}")


    debug_log(f"开始扫描目录：{log_dir}")
    for filename in os.listdir(log_dir):
        file_path = os.path.join(log_dir, filename)
        debug_log(f"检测到文件：{file_path}")
        if os.path.isfile(file_path) and file_path not in processed_files:
            debug_log(f"准备处理文件：{file_path}")
            process_log_file(token, file_path, operation_name, line_code, process_code)
        else:
            debug_log(f"文件 {file_path} 已处理或不是文件，跳过")




    line_code = line_var.get()

    if operation_name in ["请选择工单", None, ""] or not operation_name.strip():
        debug_log("未选择有效工单，无法启动采集。")
        messagebox.showerror("错误", "请先选择有效的工单")
        return

    if process_code in ["请选择工序", None, ""] or not process_code.strip():
        debug_log("未选择有效工序，无法启动采集。")
        messagebox.showerror("错误", "请先选择有效的工序")
        return

    debug_log(f"准备启动日志采集: 工单={operation_name}, 工序={process_code}, 线体={line_code}, 目录={log_dir}")

    try:
        # 调用 scan_directory
        debug_log("调用 scan_directory 函数前...")
        scan_directory(token, operation_name, process_code, line_code)
        debug_log("调用 scan_directory 函数后...")

        # 初始化 Observer 并启动监控
        debug_log("初始化 Observer 并启动监控")
        observer = Observer()
        event_handler = LogFileHandler(token, operation_name, process_code)
        observer.schedule(event_handler, log_dir, recursive=False)
        observer.start()

        if observer.is_alive():
            debug_log("日志目录监控已成功启动并运行")
        else:
            debug_log("日志目录监控启动失败")
    except Exception as e:
        debug_log(f"启动采集时发生异常: {e}")
        messagebox.showerror("错误", f"启动采集时发生错误: {e}")




def set_modern_style():
    """设置现代化主题和控件样式"""
    style = ttk.Style()
    style.theme_use("clam")  # 使用现代clam主题

    # 设置整体窗口背景颜色
    style.configure("TFrame", background="#F5F5F5")
    style.configure("TLabel", background="#F5F5F5", font=("Segoe UI", 12), foreground="#333333")
    style.configure("TButton", background="#0078D7", foreground="white",
                    font=("Segoe UI", 12, "bold"), padding=10, borderwidth=0, relief="flat")
    style.map("TButton", background=[("active", "#005A9E")])

    # 设置Combobox
    style.configure("TCombobox", fieldbackground="white", background="#FFFFFF",
                    borderwidth=1, relief="flat", font=("Segoe UI", 12))
    style.map("TCombobox", fieldbackground=[("readonly", "white")])

    # 设置Text和Scrollbar
    style.configure("TText", background="white", foreground="#333333", font=("Segoe UI", 12))
    style.configure("Vertical.TScrollbar", gripcount=0, troughcolor="#EDEDED",
                    background="#C0C0C0", bordercolor="#C0C0C0", arrowcolor="black")

    # 圆角按钮
    style.configure("Rounded.TButton", borderwidth=0, relief="flat", background="#0078D7",
                    foreground="white", font=("Segoe UI", 12, "bold"), padding=10)
    style.map("Rounded.TButton", background=[("active", "#005A9E")])

# 文件事件处理类
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, token, operation_name, process_code):
        self.token = token
        self.operation_name = operation_name
        self.process_code = process_code
        debug_log("LogFileHandler 初始化完成")

    def on_created(self, event):
        global is_collecting
        if not is_collecting:  # 如果采集已停止，不处理文件
            debug_log(f"采集已停止，跳过文件: {event.src_path}")
            return

        debug_log(f"检测到文件创建: {event.src_path}")
        if not event.is_directory:
            time.sleep(1)  # 延迟以避免文件未完成写入的问题
            process_log_file(self.token, event.src_path, self.operation_name, self.process_code)


# 保存配置
def save_config(line, work_order, process, log_dir):
    config = {
        "line": line,
        "work_order": work_order,
        "process": process,
        "log_dir": log_dir
    }
    try:
        with open("config.json", "w") as f:
            json.dump(config, f)
        debug_log("配置已保存到 config.json")
    except Exception as e:
        debug_log(f"[Error in save_config]: {e}")

# 加载配置
def load_config():
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                return json.load(f)
        except Exception as e:
            debug_log(f"加载配置失败: {e}")
    return None

# 禁用选择框
def disable_selection():
    global line_menu, work_order_menu, process_menu, work_order_filter
    line_menu.config(state=DISABLED)
    work_order_menu.config(state=DISABLED)
    process_menu.config(state=DISABLED)
    work_order_filter.config(state=DISABLED)

def enable_selection():
    global line_menu, work_order_menu, process_menu, work_order_filter
    line_menu.config(state=NORMAL)
    work_order_menu.config(state=NORMAL)
    process_menu.config(state=NORMAL)
    work_order_filter.config(state=NORMAL)

# 固定账号配置
USERNAME = "administrator"
PASSWORD = "hq123"

def fixed_login():
    """固定账号自动登录"""
    try:
        headers = {"Content-Type": "application/json;charset=UTF-8"}
        response = requests.post(LOGIN_URL, headers=headers, json={"UserLogin": USERNAME, "Password": PASSWORD})
        if response.status_code == 200 and response.json().get("retCode") == "1":
            debug_log("登录成功，自动登录已完成。")
            return response.json().get("Data", {}).get("token")
        else:
            raise Exception("自动登录失败，请检查账号或API服务")
    except Exception as e:
        debug_log(f"自动登录失败: {e}")
        messagebox.showerror("登录失败", f"登录失败: {e}")



# 登录功能
def login(username, password, output_widget=None):
    login_data = {"UserLogin": username, "Password": password}
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    response = requests.post(LOGIN_URL, headers=headers, json=login_data)
    if output_widget:
        output_widget.insert(END, f"请求登录...\n响应状态码: {response.status_code}\n响应内容: {response.json()}\n")
    if response.status_code == 200 and response.json().get("retCode") == "1":
        return response.json().get("Data", {}).get("token")
    return None

class LogUploadApp:
    def __init__(self, token):
        self.token = token
        self.main_win = Tk()
        self.main_win.title("Logupdate-Tools")
        self.main_win.geometry("600x500")
        self.main_win.configure(bg="#F5F5F5")

        # 设置自定义图标
        if getattr(sys, 'frozen', False):  # 检查是否在 PyInstaller 打包后的环境中
            base_path = sys._MEIPASS  # PyInstaller 临时解压路径
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        icon_path = os.path.join(base_path, "1.ico")  # 睿智 == All_In
        if os.path.exists(icon_path):
            self.main_win.iconbitmap(icon_path)
        else:
            print("警告: 图标文件未找到，使用默认图标")

        self.log_dir = None
        self.processed_files = set()
        self.is_collecting = False

        self.line_var = StringVar()
        self.work_order_var = StringVar()
        self.process_var = StringVar()
        self.debug_text = None

        self.setup_ui()
        self.load_config()  # 确保加载配置
        self.main_win.mainloop()

    def create_footer(self):
        """创建底部信息栏"""
        footer = Label(
            self.main_win,
            text="© 2024 亿强科技: 研发部 | 工具版本: 1.0.0",  # 这里是你的信息
            anchor=CENTER,  # 文本居中
            bg="#F5F5F5",  # 背景颜色
            fg="#555555",  # 字体颜色
            font=("Segoe UI", 10)  # 字体和大小
        )
        footer.pack(side=BOTTOM, fill="x", pady=5)  # 底部填满，留5像素间距

    def setup_ui(self):
        """初始化界面"""
        set_modern_style()
        self.create_title()
        self.create_config_section()
        self.create_buttons()
        self.create_log_section()
        self.bind_combobox_events()
        self.create_footer()

    def create_title(self):
        """设置标题栏"""
        title_font = Font(family="Segoe UI", size=18, weight="bold")
        title_frame = Frame(self.main_win, bg="#F5F5F5")
        title_frame.pack(pady=10)
        Label(title_frame, text="螺丝机日志上传工具", font=title_font, fg="#0078D7", bg="#F5F5F5").pack()

    def create_config_section(self):
        """创建配置信息区域"""
        config_frame = Frame(self.main_win, bg="#FFFFFF", bd=2, relief="groove")
        config_frame.pack(padx=20, pady=10, fill="x")

        self.line_menu = self.add_label_entry(config_frame, "选择线体:", self.line_var, 0)
        self.work_order_menu = self.add_label_entry(config_frame, "选择工单:", self.work_order_var, 1)
        self.process_menu = self.add_label_entry(config_frame, "选择工序:", self.process_var, 2)

        # 工单过滤输入框
        Label(config_frame, text="过滤工单:", font=("Segoe UI", 12), bg="#FFFFFF").grid(row=1, column=2, padx=10,
                                                                                        pady=10, sticky="e")
        self.work_order_filter = ttk.Entry(config_frame)
        self.work_order_filter.grid(row=1, column=3, padx=10, pady=10, sticky="w")
        self.work_order_filter.bind("<KeyRelease>", self.filter_work_orders)  # 绑定过滤事件

        # 设置下拉框的选项
        self.line_menu['values'] = get_lines(self.token)
        self.work_order_menu['values'] = []  # 初始为空，后续根据线体更新
        self.process_menu['values'] = []  # 初始为空，后续根据工单更新

    def filter_work_orders(self, event):
        """根据过滤条件动态更新工单下拉框"""
        selected_line = self.line_var.get()
        filter_text = self.work_order_filter.get()

        if not selected_line or selected_line == "请选择线体":
            self.log("请先选择线体再进行工单过滤。")
            return

        # 获取完整的工单列表
        all_work_orders = get_work_orders(self.token, selected_line)
        if filter_text:
            # 根据输入过滤工单列表
            filtered_orders = [order for order in all_work_orders if filter_text in order]
        else:
            filtered_orders = all_work_orders

        # 更新工单下拉框的内容
        self.work_order_menu['values'] = filtered_orders
        self.work_order_var.set("")  # 清空当前选择

    def bind_combobox_events(self):
        """绑定下拉框事件"""
        self.line_var.trace("w", self.update_work_orders)
        self.work_order_var.trace("w", self.update_processes)

    def update_work_orders(self, *args):
        """更新工单下拉框"""
        selected_line = self.line_var.get()
        work_orders = get_work_orders(self.token, selected_line)
        self.work_order_menu['values'] = work_orders
        self.work_order_var.set("")

    def update_processes(self, *args):
        """更新工序下拉框"""
        selected_work_order = self.work_order_var.get()
        processes = get_processes(self.token, selected_work_order)
        self.process_menu['values'] = processes
        self.process_var.set("")

    def add_label_entry(self, frame, text, variable, row):
        """添加标签和下拉选择框"""
        Label(frame, text=text, font=("Segoe UI", 12), bg="#FFFFFF").grid(row=row, column=0, padx=10, pady=10,
                                                                          sticky="e")
        combobox = ttk.Combobox(frame, textvariable=variable, state="readonly")
        combobox.grid(row=row, column=1, padx=10, pady=10, sticky="w")
        return combobox

    def create_buttons(self):
        """添加操作按钮"""
        button_frame = Frame(self.main_win, bg="#F5F5F5")
        button_frame.pack(pady=10)

        # 选择日志目录按钮
        self.select_directory_button = ttk.Button(button_frame, text="选择日志目录", command=self.choose_directory)
        self.select_directory_button.pack(side="left", padx=10)

        # 开始采集按钮
        self.start_collecting_button = ttk.Button(button_frame, text="开始采集",
                                                  command=lambda: [self.save_config(), self.start_collecting()])
        self.start_collecting_button.pack(side="left", padx=10)

        # 停止采集按钮
        self.stop_collecting_button = ttk.Button(button_frame, text="停止采集", command=self.stop_collecting)
        self.stop_collecting_button.pack(side="left", padx=10)


    def create_log_section(self):
        """日志信息区域"""
        log_frame = Frame(self.main_win, bg="#F5F5F5")
        log_frame.pack(pady=10, padx=20, fill="both", expand=True)
        Label(log_frame, text="日志信息:", font=("Segoe UI", 12), bg="#F5F5F5").pack(anchor="w", padx=10, pady=5)

        self.debug_text = Text(log_frame, wrap="none", height=20, bg="white", fg="#333333")
        self.debug_text.pack(fill="both", expand=True, padx=10, pady=5)
        scroll_y = Scrollbar(self.debug_text, orient="vertical", command=self.debug_text.yview)
        self.debug_text.config(yscrollcommand=scroll_y.set)
        scroll_y.pack(side="right", fill="y")

    def choose_directory(self):
        """选择日志目录"""
        self.log_dir = filedialog.askdirectory()
        self.log("选择的日志目录: " + self.log_dir)

    def start_collecting(self):
        """开始采集日志"""
        if not self.log_dir:
            messagebox.showerror("错误", "请先选择日志目录")
            return

        if not self.line_var.get() or not self.work_order_var.get() or not self.process_var.get():
            messagebox.showerror("错误", "请确保选择了线体、工单和工序")
            return

        self.log("日志采集开始...")
        self.save_config()  # 保存当前配置
        self.lock_config()  # 锁定配置区域
        self.is_collecting = True  # 标记为采集中

        # 在这里调用实际的采集逻辑，例如扫描目录或启动监听器
        self.log("日志采集功能已启动...")

    def stop_collecting(self):
        """停止采集日志"""
        self.log("日志采集已停止。")
        self.unlock_config()  # 解锁配置区域
        self.is_collecting = False  # 标记为未采集

    def save_config(self):
        """保存当前选择配置到 config.json"""
        config = {
            "line": self.line_var.get(),
            "work_order": self.work_order_var.get(),
            "process": self.process_var.get(),
            "log_dir": self.log_dir
        }
        try:
            with open("config.json", "w") as f:
                json.dump(config, f)
            self.log("配置已保存到 config.json")
        except Exception as e:
            self.log(f"保存配置失败: {e}")

    def lock_config(self):
        """锁定配置区域，禁止选择和修改"""
        self.line_menu.config(state=DISABLED)
        self.work_order_menu.config(state=DISABLED)
        self.process_menu.config(state=DISABLED)
        self.work_order_filter.config(state=DISABLED)

    def unlock_config(self):
        """解锁配置区域，允许重新选择和修改"""
        self.line_menu.config(state="readonly")
        self.work_order_menu.config(state="readonly")
        self.process_menu.config(state="readonly")
        self.work_order_filter.config(state=NORMAL)

    def load_config(self):
        """加载上次保存的配置"""
        try:
            if os.path.exists("config.json"):
                with open("config.json", "r") as f:
                    config = json.load(f)
                # 加载线体
                self.log_dir = config.get("log_dir", "")
                saved_line = config.get("line", "")
                saved_work_order = config.get("work_order", "")
                saved_process = config.get("process", "")

                # 加载线体列表
                lines = get_lines(self.token)
                self.line_menu['values'] = lines
                if saved_line in lines:
                    self.line_var.set(saved_line)  # 设置选中的线体
                    self.update_work_orders()  # 更新工单列表

                    # 加载工单
                    work_orders = get_work_orders(self.token, saved_line)
                    self.work_order_menu['values'] = work_orders
                    if saved_work_order in work_orders:
                        self.work_order_var.set(saved_work_order)  # 设置选中的工单
                        self.update_processes()  # 更新工序列表

                        # 加载工序
                        processes = get_processes(self.token, saved_work_order)
                        self.process_menu['values'] = processes
                        if saved_process in processes:
                            self.process_var.set(saved_process)  # 设置选中的工序
                else:
                    self.log("配置中的线体无效，未能正确加载工单和工序。")
            else:
                self.log("配置文件不存在，跳过加载。")
        except Exception as e:
            self.log(f"加载配置失败: {e}")

    def log(self, message):
        """日志输出到文本框和文件"""
        if self.debug_text:
            self.debug_text.config(state=NORMAL)
            self.debug_text.insert(END, message + "\n")
            self.debug_text.see(END)
            self.debug_text.config(state=DISABLED)
        logger.debug(message)


if __name__ == "__main__":
    try:
        token = fixed_login()
        if token:
            LogUploadApp(token)  # 直接调用类
        else:
            messagebox.showerror("登录失败", "无法获取登录Token，请检查API服务。")
    except Exception as e:
        logger.error(f"程序运行出错: {e}")
    finally:
        save_processed_files()






