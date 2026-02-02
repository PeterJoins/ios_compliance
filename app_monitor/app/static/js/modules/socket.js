import { state } from './state.js';
import { UI } from './ui.js';
import { Dashboard } from './dashboard.js';

export const SocketClient = {
    init: () => {
        if (typeof io === 'undefined') {
            console.error("Socket.io library not found.");
            return;
        }

        try {
            const socket = io();
            state.socket = socket;

            socket.on('connect', () => UI.updateSocketStatus('🟢 在线', 'text-success'));
            socket.on('disconnect', () => {
                UI.updateSocketStatus('🔴 离线', 'text-danger');
                UI.updateGlobalBar(false);
                state.currentMonitoredApp = null;
            });

            // [核心修复] 使用箭头函数包裹，防止 UI 方法未定义导致报错
            socket.on('network_log', (data) => {
                console.log("[Debug] Network Data:", data); // 方便调试
                if (UI && UI.renderNetworkLog) UI.renderNetworkLog(data);
                // 更新仪表盘
                Dashboard.updateNetwork(data.url);
            });

            socket.on('file_log', (data) => {
                console.log("[Debug] File Data:", data);
                if (UI && UI.renderFileLog) UI.renderFileLog(data);
                // 更新计数
                Dashboard.updateFile()
            });

            socket.on('info_log', (data) => {
                console.log("[Debug] Info Data:", data);
                if (UI && UI.renderInfoLog) UI.renderInfoLog(data);
                // 更新仪表盘
                Dashboard.updatePrivacy(data.category);
            });

            socket.on('sdk_log', (payload) => {
                console.log("[Debug] SDK Data received:", payload);
                const list = payload.data || [];
                if (UI && UI.renderSDKList) UI.renderSDKList(list);
            });

            socket.on('sys_log', (data) => console.log("[System]", data.msg));

            // ========== 新增：传感器事件处理 ==========
            socket.on('sensor_event', (data) => {
                console.log("[Sensor] Sensor Data:", data);

                // 1. 更新Dashboard统计
                if (Dashboard && Dashboard.updateSensor) {
                    Dashboard.updateSensor(data.category);
                }

                // 2. 在信息采集页面显示传感器日志（可选）
                if (UI && UI.renderInfoLog) {
                    // 转换传感器数据为info_log格式以便在信息采集页面显示
                    const sensorLog = {
                        type: 'sensor',
                        category: 'Sensor',
                        subcategory: data.category,
                        method: data.method || 'sensor_access',
                        details: data.details || {},
                        timestamp: new Date().toLocaleTimeString(),
                        stack: data.stack || ''
                    };
                    UI.renderInfoLog(sensorLog);
                }

                // 3. 在控制台输出详细信息
                console.log(`[Sensor] ${data.category} 被调用 - ${data.method || 'unknown method'}`);
            });

            // ========== 新增：扩展隐私事件处理 ==========
            socket.on('privacy_event', (data) => {
                console.log("[Privacy] Extended Privacy Data:", data);

                // 定义新增的隐私类别
                const newPrivacyCategories = ['Health', 'HomeKit', 'Microphone', 'Calendar'];

                // 检查是否是新增的隐私类别
                if (newPrivacyCategories.includes(data.category)) {
                    console.log(`[Privacy] 新增隐私类别: ${data.category}`);

                    // 1. 更新Dashboard计数器
                    if (Dashboard && Dashboard.updatePrivacyCounter) {
                        Dashboard.updatePrivacyCounter(data.category);
                    }

                    // 2. 在信息采集页面显示
                    if (UI && UI.renderInfoLog) {
                        // 转换数据格式以保持一致性
                        const privacyLog = {
                            type: 'privacy',
                            category: data.category,
                            method: data.method || 'privacy_access',
                            details: data.details || {},
                            timestamp: new Date().toLocaleTimeString(),
                            stack: data.stack || ''
                        };
                        UI.renderInfoLog(privacyLog);
                    }

                    // 3. 更新总隐私计数（通过现有接口）
                    if (Dashboard && Dashboard.updatePrivacy) {
                        Dashboard.updatePrivacy(data.category);
                    }
                } else {
                    // 原有的隐私类别，使用现有处理逻辑
                    console.log("[Privacy] 传统隐私类别，转发为info_log");
                    socket.emit('info_log', data);
                }
            });

            // ========== 新增：网络信息监控事件 ==========
            socket.on('network_info', (data) => {
                console.log("[NetworkInfo] Network Info Data:", data);

                // 在信息采集页面显示网络信息获取
                if (UI && UI.renderInfoLog) {
                    const networkInfoLog = {
                        type: 'network_info',
                        category: 'NetworkInfo',
                        subcategory: data.subcategory || 'General',
                        method: data.method || 'network_info_access',
                        details: {
                            action: data.details?.action || '获取网络信息',
                            type: data.category || 'unknown',
                            timestamp: new Date().toLocaleTimeString()
                        },
                        timestamp: new Date().toLocaleTimeString(),
                        stack: data.stack || ''
                    };
                    UI.renderInfoLog(networkInfoLog);
                }

                console.log(`[NetworkInfo] ${data.category} - ${data.details?.action || '网络信息访问'}`);
            });

            console.log("[Socket] 所有事件监听器已设置完成，包括新增的传感器和隐私事件");

        } catch (e) {
            console.error("Socket init failed:", e);
        }
    },

    // ========== 新增：手动触发事件测试（开发用） ==========
    testSensorEvent: (category = 'Accelerometer') => {
        if (state.socket && state.socket.connected) {
            const testData = {
                category: category,
                method: 'startUpdates',
                details: {
                    action: '开始传感器数据采集',
                    timestamp: new Date().toISOString()
                },
                stack: '测试堆栈信息\n[模拟调用链]'
            };

            // 模拟后端发送传感器事件
            console.log(`[Test] 发送测试传感器事件: ${category}`);
            state.socket.emit('sensor_event', testData);
            return true;
        }
        console.warn("[Test] Socket未连接，无法发送测试事件");
        return false;
    },

    testPrivacyEvent: (category = 'Health') => {
        if (state.socket && state.socket.connected) {
            const testData = {
                category: category,
                method: 'requestAuthorization',
                details: {
                    action: `请求${category}权限`,
                    timestamp: new Date().toISOString()
                },
                stack: '测试堆栈信息\n[模拟调用链]'
            };

            console.log(`[Test] 发送测试隐私事件: ${category}`);
            state.socket.emit('privacy_event', testData);
            return true;
        }
        console.warn("[Test] Socket未连接，无法发送测试事件");
        return false;
    },

    // ========== 新增：检查特定事件监听器 ==========
    checkListeners: () => {
        if (!state.socket) {
            console.log("[Socket] Socket未初始化");
            return [];
        }

        const listeners = state.socket._callbacks || {};
        const eventNames = Object.keys(listeners);

        console.log("[Socket] 当前监听的事件:", eventNames);

        // 检查关键事件监听器是否存在
        const requiredEvents = ['sensor_event', 'privacy_event', 'network_info'];
        const missingEvents = requiredEvents.filter(event => !eventNames.includes(event));

        if (missingEvents.length > 0) {
            console.warn("[Socket] 缺少事件监听器:", missingEvents);
        } else {
            console.log("[Socket] 所有必需事件监听器都已设置");
        }

        return eventNames;
    }
};