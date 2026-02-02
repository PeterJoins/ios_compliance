import frida
import os
import time
import logging
from pathlib import Path  # 修正这里，删除 lib
from app import socketio

# 日志
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class MonitorService:
    # 类属性存储状态
    session = None
    script = None
    pid = None
    bundle_id = None
    _is_spawned = False  # 标记是否是spawn启动的进程

    @staticmethod
    def _load_js_source():
        """读取并拼接所有的 JS 模块文件，并注入 SDK 规则"""
        # [修改] 在文件列表中添加 sensor.js
        files_order = ['bypass.js', 'network.js', 'file.js', 'privacy.js', 'sensor.js', 'antilock.js', 'sdk.js',
                       'loader.js']

        # 获取 frida_scripts 目录路径
        base_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frida_scripts')
        full_source = ""

        try:
            # 拼接所有 JS 文件
            for filename in files_order:
                file_path = os.path.join(base_path, filename)
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        full_source += f"\n// --- FILE: {filename} ---\n"
                        full_source += f.read() + "\n"
                else:
                    print(f"[!] Warning: JS Module not found: {filename}")

            # 读取 SDK 规则 JSON 文件
            rules_path = os.path.join(base_path, 'ios_sdk_rules.json')
            rules_content = "[]"  # 默认空数组，防止文件不存在导致 JS 语法错误

            if os.path.exists(rules_path):
                with open(rules_path, 'r', encoding='utf-8') as f:
                    # 读取内容，去掉可能的换行符，保证是合法的 JSON 字符串
                    rules_content = f.read().strip()
            else:
                print("[!] Warning: ios_sdk_rules.json not found")

            # 使用SDK特征规则替换 JS 中的占位符
            full_source = full_source.replace('__SDK_RULES_JSON__', rules_content)

        except Exception as e:
            print(f"[!] JS Loading Error: {e}")
            return None

        return full_source

    @classmethod
    def _get_process(cls, device, bundle_id):
        """获取目标进程PID，优先Spawn，失败则查找现有进程"""
        # 1) 优先尝试 spawn
        try:
            pid = device.spawn([bundle_id])
            logger.info(f"应用已启动 (Spawn)，PID: {pid}")
            # 不要在这里 resume：应该等脚本 load 完成后再 resume，避免 Hook 时机不对导致卡死
            cls._is_spawned = True
            return pid
        except (frida.NotSupportedError, frida.ServerNotRunningError) as e:
            logger.info(f"Spawn不支持或失败: {e}，尝试查找运行中的进程...")
        except Exception as e:
            # 关键：把 spawn 的真实错误原因打印出来，否则前端只看到“无法定位应用”
            logger.warning(f"Spawn尝试失败(将回退到attach): {type(e).__name__}: {e}")

        # 2) spawn 失败则回退：枚举应用，若目标正在运行则 attach
        try:
            apps = device.enumerate_applications()
            target = next((a for a in apps if a.identifier == bundle_id), None)
            if not target:
                raise Exception(f"未找到应用 {bundle_id}（可能未安装或bundle id不正确）")
            if target.pid and target.pid != 0:
                logger.info(f"找到运行中应用: {target.name} (PID: {target.pid})，将使用 attach")
                cls._is_spawned = False
                return target.pid

            # 已安装但未运行：给出更明确的引导（也可在这里做一次重试spawn）
            raise Exception(f"应用 {bundle_id} 已安装但未运行，且spawn失败；请先手动打开应用后再尝试（将走attach）")
        except Exception as e:
            raise Exception(f"无法定位/启动应用 {bundle_id}：{e}")

    @classmethod
    def _attach_with_retry(cls, device, target, max_retries=3):
        """带重试机制的附加进程"""
        for i in range(max_retries):
            try:
                session = device.attach(target)
                logger.info(f"成功附加到进程: {target}")
                return session
            except Exception as e:
                if i == max_retries - 1: raise e
                logger.warning(f"附加失败 ({i + 1}/{max_retries})，1秒后重试: {e}")
                time.sleep(1)

    @classmethod
    def _on_message(cls, message, data):
        """Frida消息回调处理"""
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type')

            # [修改] 扩展消息类型映射
            event_map = {
                'network': 'network_log',
                'file': 'file_log',
                'info': 'info_log',
                'sdk': 'sdk_log',
                'heart': 'heart_log',
                'sys_log': 'sys_log',
                'sensor': 'sensor_event',  # 新增：传感器事件
                'privacy': 'privacy_event'  # 新增：扩展隐私事件
            }

            if msg_type in event_map:
                # [修改] 对于传感器和扩展隐私事件，直接发送
                if msg_type in ['sensor', 'privacy']:
                    # 检查是否是新增的隐私类别
                    if msg_type == 'privacy':
                        new_categories = ['Health', 'HomeKit', 'Microphone', 'Calendar']
                        if payload.get('category') in new_categories:
                            # 直接发送privacy_event到前端
                            socketio.emit(event_map[msg_type], payload)
                            logger.info(f"[Monitor] 发送扩展隐私事件: {payload.get('category')}")
                            return
                        else:
                            # 传统隐私类别，转发为info_log
                            socketio.emit('info_log', payload)
                            return
                    else:
                        # 传感器事件直接发送
                        socketio.emit(event_map[msg_type], payload)
                        logger.info(f"[Monitor] 发送传感器事件: {payload.get('category')}")
                else:
                    # 其他原有事件类型
                    socketio.emit(event_map[msg_type], payload)

        elif message['type'] == 'error':
            # [增强] 输出更完整的 JS 错误信息，便于定位到具体脚本/行号
            err_msg = message.get('description', str(message))
            stack = message.get('stack', '')
            file_name = message.get('fileName', '') or message.get('filename', '')
            line_number = message.get('lineNumber', '') or message.get('line', '')
            col_number = message.get('columnNumber', '') or message.get('column', '')
            if 'destroyed' not in str(err_msg):
                loc = ""
                if file_name or line_number or col_number:
                    loc = f" @ {file_name}:{line_number}:{col_number}"
                logger.error(f"Script Error: {err_msg}{loc}")
                if stack:
                    logger.error(f"Script Stack:\n{stack}")
                socketio.emit('sys_log', {
                    'msg': f"脚本错误: {err_msg}{loc}" + (f"\n\nStack:\n{stack}" if stack else "")
                })

    @classmethod
    def start_monitoring(cls, bundle_id):
        """启动监控流程"""
        cls.stop_monitoring()  # 先清理旧会话
        cls.bundle_id = bundle_id

        try:
            device = frida.get_usb_device()
            logger.info(f"准备监控: {bundle_id}")

            # 获取PID (Spawn 或 Attach)
            cls.pid = cls._get_process(device, bundle_id)

            # 附加进程
            cls.session = cls._attach_with_retry(device, cls.pid)

            # 加载脚本
            js_source = cls._load_js_source()
            if not js_source: raise Exception("JS脚本加载为空")

            # [修改] 添加加载日志
            logger.info("JS脚本加载成功，包含传感器监控模块")

            cls.script = cls.session.create_script(js_source)
            cls.script.on('message', cls._on_message)
            cls.script.load()

            # [修复] 只有在spawn启动的应用才需要resume，且必须在脚本加载完成后resume
            # 这样可以确保Hook在应用运行前就位，避免卡死
            if cls._is_spawned:
                logger.info("脚本加载完成，正在恢复应用运行...")
                device.resume(cls.pid)
                cls._is_spawned = False  # 重置标记

            msg = f"监控已成功启动 (PID: {cls.pid})，包含传感器监控功能"
            socketio.emit('sys_log', {'msg': msg})
            return True, "监控已启动"

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Start Error: {error_msg}")

            # 简化的错误提示逻辑
            tips = "未知错误"
            if "PermissionDenied" in error_msg:
                tips = "权限拒绝：请检查证书签名或设备信任设置"
            elif "process not found" in error_msg.lower():
                tips = "未找到进程：请手动启动应用"
            elif "server" in error_msg.lower():
                tips = "连接失败：请检查Frida-server版本"

            socketio.emit('sys_log', {'msg': f"启动失败: {tips}\nDetails: {error_msg}"})
            return False, error_msg

    @classmethod
    def stop_monitoring(cls):
        """停止监控并清理资源"""
        msg = "无运行任务"
        try:
            if cls.script:
                try:
                    cls.script.unload()
                except:
                    pass

            if cls.session:
                try:
                    cls.session.detach()
                except:
                    pass

            # 杀掉进程，
            if cls.pid:
                try:
                    frida.get_usb_device().kill(cls.pid)
                    msg = f"监控停止，进程已结束: {cls.bundle_id}"
                except:
                    msg = "监控停止 (进程已结束或无法访问)"

            socketio.emit('sys_log', {'msg': msg})

        except Exception as e:
            msg = f"停止时发生错误: {e}"
            logger.error(msg)
        finally:
            cls.session = None
            cls.script = None
            cls.pid = None
            cls.bundle_id = None
            cls._is_spawned = False

        return True, msg