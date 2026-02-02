/**
 * Dashboard Module - 数据统计与图表渲染
 */

const stats = {
    privacy: {},
    domains: {},
    sensor: {},      // 新增：传感器统计
    total: { privacy: 0, network: 0, file: 0, sensor: 0 }
};

let charts = {
    privacy: null,
    network: null
};

// 初始化图表
function init() {
    const ctxPrivacy = document.getElementById('privacyChart');
    const ctxNetwork = document.getElementById('networkChart');

    // [新增] 注册数据标签插件
    if (typeof ChartDataLabels !== 'undefined') {
        Chart.register(ChartDataLabels);
    }

    // 1. 隐私合规环形图
    if (ctxPrivacy) {
        charts.privacy = new Chart(ctxPrivacy, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#0d6efd', '#6610f2', '#6f42c1', '#d63384', '#dc3545',
                        '#fd7e14', '#ffc107', '#198754', '#20c997', '#0dcaf0'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    // [新增] 数据标签配置 (显示百分比)
                    datalabels: {
                        color: '#fff', // 文字颜色
                        font: { weight: 'bold', size: 12 },
                        formatter: (value, ctx) => {
                            let sum = 0;
                            let dataArr = ctx.chart.data.datasets[0].data;
                            dataArr.map(data => { sum += data; });
                            // 计算百分比
                            let percentage = (value * 100 / sum).toFixed(1) + "%";
                            return percentage;
                        },
                        // 数值太小或为0时不显示
                        display: function(context) {
                            return context.dataset.data[context.dataIndex] > 0;
                        }
                    },
                    // [新增] 图例配置 (显示次数)
                    legend: {
                        position: 'right',
                        labels: {
                            // 自定义生成图例标签
                            generateLabels: function(chart) {
                                const data = chart.data;
                                if (data.labels.length && data.datasets.length) {
                                    return data.labels.map((label, i) => {
                                        const meta = chart.getDatasetMeta(0);
                                        const ds = data.datasets[0];
                                        const value = ds.data[i]; // 获取次数
                                        const hidden = meta.data[i].hidden;

                                        // 返回自定义对象
                                        return {
                                            text: `${label}: ${value}次`, // [核心修改] 拼接次数
                                            fillStyle: ds.backgroundColor[i],
                                            strokeStyle: ds.backgroundColor[i],
                                            lineWidth: 1,
                                            hidden: isNaN(value) || hidden,
                                            index: i
                                        };
                                    });
                                }
                                return [];
                            }
                        }
                    }
                }
            }
        });
    }

    // 2. 网络请求柱状图 (不需要百分比插件，这里禁用掉)
    if (ctxNetwork) {
        charts.network = new Chart(ctxNetwork, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: '请求次数',
                    data: [],
                    backgroundColor: 'rgba(25, 135, 84, 0.6)',
                    borderColor: 'rgba(25, 135, 84, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true } },
                plugins: {
                    // 在柱状图中禁用 datalabels 插件，保持界面整洁
                    datalabels: { display: false }
                }
            }
        });
    }

    // [新增] 初始化传感器监控
    initSensorMonitoring();
    console.log('[Dashboard] 传感器监控模块已初始化');
}

// ========== 新增：传感器监控功能 ==========

/**
 * 初始化传感器监控
 */
function initSensorMonitoring() {
    console.log('[Dashboard] 初始化传感器监控模块');

    // 确保在socket连接建立后才设置监听
    if (window.socket && window.socket.connected) {
        setupSensorListeners();
    } else {
        console.warn('[Dashboard] Socket未就绪，等待连接...');
        // 延迟重试
        setTimeout(() => {
            if (window.socket && window.socket.connected) {
                setupSensorListeners();
            } else {
                console.error('[Dashboard] Socket连接失败，传感器监控可能无法工作');
            }
        }, 2000);
    }
}

/**
 * 设置传感器事件监听器
 */
function setupSensorListeners() {
    if (!window.socket) {
        console.error('[Dashboard] Socket对象不存在');
        return;
    }

    // 监听传感器事件
    window.socket.on('sensor_event', function(data) {
        console.log('[Dashboard] 收到传感器事件:', data.category);
        updateSensorCounter(data.category, data.details);
    });

    // 监听扩展的隐私事件
    window.socket.on('privacy_event', function(data) {
        const newCategories = ['Health', 'HomeKit', 'Microphone', 'Calendar'];
        if (newCategories.includes(data.category)) {
            console.log('[Dashboard] 收到新增隐私事件:', data.category);
            updatePrivacyCounter(data.category);
        }
    });

    console.log('[Dashboard] 传感器监听器已设置');
}

/**
 * 更新传感器计数器
 * @param {string} category - 传感器类别
 * @param {object} details - 详细信息
 */
function updateSensorCounter(category, details) {
    // 更新统计数据
    stats.total.sensor++;
    stats.sensor[category] = (stats.sensor[category] || 0) + 1;

    // 更新UI显示
    const counterMap = {
        'Accelerometer': 'accelerometerCount',
        'Gyroscope': 'gyroscopeCount',
        'Magnetometer': 'magnetometerCount',
        'Proximity': 'proximityCount'
    };

    const counterId = counterMap[category];
    if (counterId) {
        const element = document.getElementById(counterId);
        if (element) {
            const current = parseInt(element.textContent) || 0;
            element.textContent = current + 1;

            // 添加高亮动画
            element.classList.add('count-up');
            setTimeout(() => {
                element.classList.remove('count-up');
            }, 500);
        }
    }

    // 更新传感器总数显示
    updateSensorTotalCount();
}

/**
 * 更新新增隐私权限计数器
 * @param {string} category - 隐私类别
 */
function updatePrivacyCounter(category) {
    const counterMap = {
        'Health': 'healthCount',
        'HomeKit': 'homekitCount',
        'Microphone': 'microphoneCount',
        'Calendar': 'calendarCount'
    };

    const counterId = counterMap[category];
    if (counterId) {
        const element = document.getElementById(counterId);
        if (element) {
            const current = parseInt(element.textContent) || 0;
            element.textContent = current + 1;

            // 添加高亮动画
            element.classList.add('count-up');
            setTimeout(() => {
                element.classList.remove('count-up');
            }, 500);
        }
    }
}

/**
 * 更新传感器总数显示
 */
function updateSensorTotalCount() {
    // 更新总数统计
    const totalElement = document.getElementById('count-sensor');
    if (totalElement) {
        totalElement.textContent = stats.total.sensor;

        // 添加动画效果
        totalElement.classList.add('text-info', 'fw-bold');
        setTimeout(() => {
            totalElement.classList.remove('text-info', 'fw-bold');
        }, 300);
    }
}

// 更新隐私统计
function updatePrivacy(category) {
    stats.total.privacy++;
    const el = document.getElementById('count-privacy');
    if(el) el.innerText = stats.total.privacy;

    stats.privacy[category] = (stats.privacy[category] || 0) + 1;

    if (charts.privacy) {
        charts.privacy.data.labels = Object.keys(stats.privacy);
        charts.privacy.data.datasets[0].data = Object.values(stats.privacy);
        charts.privacy.update('none');
    }
}

// 更新网络统计
function updateNetwork(url) {
    stats.total.network++;
    const el = document.getElementById('count-network');
    if(el) el.innerText = stats.total.network;

    let domain = 'Unknown';
    try {
        const urlObj = new URL(url);
        domain = urlObj.hostname;
    } catch (e) {}

    // 如果解析失败(Unknown)，直接丢弃，不计入域名统计
    if (domain === 'Unknown') {
        return;
    }

    stats.domains[domain] = (stats.domains[domain] || 0) + 1;

    if (charts.network) {
        const sortedDomains = Object.entries(stats.domains)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10);

        charts.network.data.labels = sortedDomains.map(([k]) => k);
        charts.network.data.datasets[0].data = sortedDomains.map(([,v]) => v);
        charts.network.update('none');
    }
}

// 更新文件统计
function updateFile() {
    stats.total.file++;
    const el = document.getElementById('count-file');
    if(el) el.innerText = stats.total.file;
}

// [新增] 更新传感器统计（公开接口，供其他模块调用）
function updateSensor(category) {
    updateSensorCounter(category, {});
}

// 清空统计
function clear() {
    stats.privacy = {};
    stats.domains = {};
    stats.sensor = {};  // [新增] 清空传感器统计
    stats.total = { privacy: 0, network: 0, file: 0, sensor: 0 };

    // [修改] 增加传感器计数器的清空
    ['count-privacy', 'count-network', 'count-file', 'count-sensor'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.innerText = '0';
    });

    // [新增] 清空传感器子计数器
    ['accelerometerCount', 'gyroscopeCount', 'magnetometerCount', 'proximityCount',
     'healthCount', 'homekitCount', 'microphoneCount', 'calendarCount'].forEach(id => {
        const el = document.getElementById(id);
        if(el) el.innerText = '0';
    });

    if(charts.privacy) {
        charts.privacy.data.labels = [];
        charts.privacy.data.datasets[0].data = [];
        charts.privacy.update();
    }
    if(charts.network) {
        charts.network.data.labels = [];
        charts.network.data.datasets[0].data = [];
        charts.network.update();
    }

    console.log('[Dashboard] 所有统计已清空');
}

// [新增] 获取传感器统计数据
function getSensorStats() {
    return {
        total: stats.total.sensor,
        byCategory: { ...stats.sensor }
    };
}

// [新增] 手动触发传感器监听器设置（供外部调用）
function setupSensorMonitoring() {
    if (window.socket && window.socket.connected) {
        setupSensorListeners();
        return true;
    }
    return false;
}

export const Dashboard = {
    init,
    updatePrivacy,
    updateNetwork,
    updateFile,
    updateSensor,  // [新增] 导出传感器更新接口
    updatePrivacyCounter,  // [新增] 导出隐私计数器更新接口
    clear,
    getSensorStats, // [新增] 导出获取传感器统计接口
    setupSensorMonitoring // [新增] 导出手动设置监听器接口
};