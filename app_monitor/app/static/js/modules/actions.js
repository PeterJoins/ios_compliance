import { state } from './state.js';
import { API } from './api.js';
import { UI } from './ui.js';
import { Dashboard } from './dashboard.js';

export const Actions = {
    // 点击“开启监控”
    handleMonitor: async (appName, bundleId) => {
        if (!state.socket) return UI.alert("错误", "Socket 未连接", "❌", "danger");

        // 切换或重启判断
        if (state.currentMonitoredApp) {
            if (state.currentMonitoredApp.bundleId !== bundleId) {
                if (!(await UI.confirm("切换应用", `停止 [${state.currentMonitoredApp.name}] 并启动 [${appName}]？`, "🔀", "primary", "切换"))) return;
            } else {
                if (!(await UI.confirm("重启监控", `是否重启 [${appName}]？`, "🔄", "warning", "重启"))) return;
            }
        }

        // 暂存并打开配置
        state.pendingApp = { name: appName, bundleId: bundleId };
        UI.showConfigModal();
    },

    // 确认配置并启动
    confirmConfig: async () => {
        const mode = document.getElementById('modeTweak').checked ? 'tweak' : 'frida';
        const deviceIp = document.getElementById('deviceIp').value;
        const serverIp = document.getElementById('serverIp').value;

        if (mode === 'tweak' && (!deviceIp || !serverIp)) {
            alert("Tweak 模式下必须填写 IP 地址");
            return;
        }

        UI.hideConfigModal();
        await Actions.startProcess(mode, state.pendingApp.name, state.pendingApp.bundleId, deviceIp, serverIp);
    },

    // 执行启动流程
    startProcess: async (mode, appName, bundleId, deviceIp, serverIp) => {
        UI.activateTab('#info-collection');
        UI.updateGlobalBar(true, appName, '启动中...');
        UI.clearAllLogs();
        Dashboard.clear();

        try {
            let res;
            if (mode === 'tweak') {
                res = await API.startTweakMonitor(bundleId, deviceIp, serverIp);
            } else {
                res = await API.startMonitor(bundleId);
            }

            if (res.status === 'success') {
                UI.updateGlobalBar(true, appName, mode === 'tweak' ? 'Tweak' : 'Frida');
                state.currentMonitoredApp = { name: appName, bundleId, mode, deviceIp };
                
                if (mode === 'tweak') {
                    UI.alert("插件已部署", "如应用未重新启动，可手动重启使生效！", "✅", "success");
                }
            } else {
                UI.alert("启动失败", res.message, "❌", "danger");
                UI.updateGlobalBar(false);
                state.currentMonitoredApp = null;
            }
        } catch (e) {
            UI.alert("异常", e.message, "🔌", "danger");
            UI.updateGlobalBar(false);
            state.currentMonitoredApp = null;
        }
    },

    // 停止监控
    stopMonitor: async () => {

        if (!state.currentMonitoredApp) return;
        if (!(await UI.confirm("停止监控", "确定停止当前监控任务吗？", "🛑", "danger", "停止"))) return;
        
        try {
            if (state.currentMonitoredApp.mode === 'tweak') {
                await API.stopTweakMonitor(state.currentMonitoredApp.deviceIp, state.currentMonitoredApp.bundleId);
            } else {
                await API.stopMonitor();
            }
            state.currentMonitoredApp = null;
            UI.updateGlobalBar(false);
        } catch (e) {
            console.error("[stopMonitor] 发生错误:", e.message);
            UI.alert("失败", e.message, "❌", "danger");
        }
    },

    // 刷新应用列表
    refreshApps: async () => {
        const btn = document.getElementById('refreshBtn');
        if (!btn) return;
        
        btn.disabled = true;
        //btn.innerHTML = '<span class="spinner-border spinner-border-sm text-success"></span> <span class="text-secondary">读取中...</span>';
        
        // 显示加载占位
        const tbody = document.getElementById('appTableBody');
        tbody.innerHTML = `<tr><td colspan="5" class="p-0 border-0"><div class="d-flex flex-column align-items-center justify-content-center text-muted" style="height: calc(100vh - 200px);"><div class="spinner-border text-primary mb-3"></div><p>正在读取设备数据...</p></div></td></tr>`;

        try {
            const res = await API.fetchApps();
            if (res.status === 'error') throw new Error(res.message);
            UI.renderAppList(res.data);
        } catch (e) {
            UI.alert("获取应用失败", e.message, "❌", "danger");
            tbody.innerHTML = `<tr><td colspan="5" class="text-center py-5 text-danger">数据获取失败</td></tr>`;
        } finally {
            btn.disabled = false;
            //btn.innerHTML = '<i class="bi bi-arrow-clockwise fs-5 align-middle"></i> <span class="align-middle ms-1">刷新列表</span>';
            //btn.innerHTML = '<span class="align-middle ms-1">🔄 刷新列表</span>';
        }
    }
};