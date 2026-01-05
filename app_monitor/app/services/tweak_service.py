import paramiko
import frida
import time
import os
import json
import plistlib
from config import Config

class TweakService:
    @staticmethod
    def _get_usb_device():
        """
        获取 USB 连接的 iOS 设备
        timeout 参数确保在未检测到设备时不会永久阻塞
        """
        try:
            # 等待并获取 USB 设备
            device = frida.get_usb_device(timeout=5)
            return device
        except Exception as e:
            raise Exception(f"未检测到 USB 连接的 iOS 设备，请检查数据线连接: {e}")

    @staticmethod
    def _remove_tweak_files(ssh_client):
        """
        独立封装：物理删除 iOS 设备上的插件文件和配置
        """
        commands = [
            "rm -f /Library/MobileSubstrate/DynamicLibraries/MonitorTweak.dylib",
            "rm -f /Library/MobileSubstrate/DynamicLibraries/MonitorTweak.plist",
        ]
        for cmd in commands:
            ssh_client.exec_command(cmd)
        print("[*] 远程插件文件已清理")

    @staticmethod
    def deploy_tweak(device_ip, bundle_id, server_ip):
        ssh = paramiko.SSHClient()
        try:
            # 初始化 Frida USB 连接
            device = TweakService._get_usb_device()
            
            # 检查目标应用状态并强杀
            apps = device.enumerate_applications()
            target_app = next((app for app in apps if app.identifier == bundle_id), None)
            if target_app and target_app.pid != 0:
                print(f"[*] 检测到 {bundle_id} 正在运行 (PID: {target_app.pid})，正在强制退出...")
                device.kill(target_app.pid)
                time.sleep(1.0) # 给系统一点缓冲时间

            # SSH 连接上传Tweak插件文件 (文件传输需通过网络或 USB 映射端口)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # 通过 USB 映射（如 iproxy 2222 22）
            ssh.connect(device_ip, Config.SSH_PORT, Config.SSH_USER, Config.SSH_PASS)
            # 清理历史插件文件
            TweakService._remove_tweak_files(ssh)
            sftp = ssh.open_sftp()
            
            remote_base = "/Library/MobileSubstrate/DynamicLibraries"
            
            # --- 部署 Dylib ---
            local_dylib = os.path.join(os.getcwd(), 'app/tweak_libs/MonitorTweak.dylib')
            sftp.put(local_dylib, f"{remote_base}/MonitorTweak.dylib")
            
            # --- 部署 Plist 过滤器 ---
            plist_data = {"Filter": {"Bundles": [bundle_id]}}
            with open('temp.plist', 'wb') as f:
                plistlib.dump(plist_data, f)
            sftp.put('temp.plist', f"{remote_base}/MonitorTweak.plist")
            
            # --- 部署 配置文件 ---
            config_data = {"server_url": f"http://{server_ip}:{Config.SERVER_PORT}/api/report_log"}
            with open('temp_config.json', 'w') as f:
                json.dump(config_data, f)
            sftp.put('temp_config.json', "/var/mobile/monitor_config.json")
            sftp.close()

            # 通过 Frida 启动应用，使注入的dylib文件生效
            pid = device.spawn([bundle_id])
            device.resume(pid)
            
            return True, f"USB 部署成功，应用已拉起 (PID: {pid})"

        except Exception as e:
            return False, f"USB 部署失败: {str(e)}"
        finally:
            ssh.close()
            # 清理临时文件
            for f in ['temp.plist', 'temp_config.json']:
                if os.path.exists(f): os.remove(f)

    @staticmethod
    def cleanup_tweak(device_ip, bundle_id):
        """清除注入并强杀进程"""
        print(f"[*] 正在杀死... {bundle_id} ")
        try:
            # 连接SSH 删除文件
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(device_ip, Config.SSH_PORT, Config.SSH_USER, Config.SSH_PASS)
            ssh.exec_command("rm /Library/MobileSubstrate/DynamicLibraries/MonitorTweak.*")
            ssh.close()

            # 通过Frida USB 强杀目标应用
            device = TweakService._get_usb_device()
            apps = device.enumerate_applications()
            target = next((app for app in apps if app.identifier == bundle_id), None)
            if target and target.pid != 0:
                device.kill(target.pid)
            return True, f"插件已移除，应用 {bundle_id} 已关闭"
        except Exception as e:
            return False, f"清理失败: {str(e)}"