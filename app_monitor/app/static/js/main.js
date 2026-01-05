/**
 * Main Entry Point
 */
import { UI } from './modules/ui.js';
import { SocketClient } from './modules/socket.js';
import { Actions } from './modules/actions.js';
import { Dashboard } from './modules/dashboard.js';

let stackModalInstance = null; 

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    UI.initModals();
    Dashboard.init();
    SocketClient.init();

    // 绑定刷新按钮
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', Actions.refreshApps);
    }

    // 绑定配置框切换逻辑
    document.querySelectorAll('input[name="monitorMode"]').forEach(el => {
        el.addEventListener('change', (e) => {
            const tweakDiv = document.getElementById('tweakSettings');
            if (e.target.id === 'modeTweak') tweakDiv.classList.remove('d-none');
            else tweakDiv.classList.add('d-none');
        });
    });

    // 初始化搜索过滤器 (Helper)
    setupFilters();
});

// === 暴露全局函数 (供 HTML onclick 调用) ===
window.handleMonitor = Actions.handleMonitor;
window.confirmConfig = Actions.confirmConfig;
window.stopMonitor = Actions.stopMonitor;

// UI 辅助函数暴露
window.showNetworkDetail = UI.showNetworkDetail || function(encodedData) {
    // 简单的 Raw Request 展示逻辑 (为了节省模块代码量，这里简化保留或从 UI 导入)
    // 建议在 UI.js 中实现完整逻辑，这里直接引用：
    // 由于 UI 模块是对象，我们需要把这个具体逻辑放进 UI.js 并导出
    // 这里为了兼容之前的逻辑，临时重新定义或从 UI 调用
    import('./modules/ui.js').then(m => m.UI.showNetworkDetail(encodedData));
};
// 注意：上面的 import 是异步的。更好的做法是在 UI.js 中实现 showNetworkDetail 等方法，
// 并在 main.js 中挂载。
// 下面是手动挂载 UI 辅助方法：
window.toggleStackCell = (uid) => {
    const btn = document.getElementById(`stack-btn-${uid}`);
    const content = document.getElementById(`stack-content-${uid}`);
    if (btn && content) {
        const isHidden = content.classList.contains('d-none');
        content.classList.toggle('d-none', !isHidden);
        btn.classList.toggle('d-none', isHidden);
    }
};

// 显示堆栈详情 (Modal)
window.showStackTrace = function(encodedStack) {
    if (!stackModalInstance) {
        const el = document.getElementById('stackModal');
        // 使用 Bootstrap 的 Modal 类
        if(el) stackModalInstance = new bootstrap.Modal(el);
    }
    
    // 解码
    const stackStr = decodeURIComponent(encodedStack);
    
    const contentEl = document.getElementById('stackContent');
    const titleEl = document.querySelector('#stackModal .modal-title');
    
    if (titleEl) titleEl.innerText = "📜 调用堆栈详情";
    
    if (contentEl) {
        // [重要] 使用 innerHTML 以解析 <br> 标签
        contentEl.innerHTML = stackStr;
        
        // 显示 Modal
        if (stackModalInstance) stackModalInstance.show();
    }
};

// showNetworkDetail 
window.showNetworkDetail = (encodedData) => {
    let data;
    try { data = JSON.parse(decodeURIComponent(encodedData)); } catch(e) { return alert("Parse Error"); }
    let rawText = `${data.method} ${data.url}\n`;
    if (data.headers) Object.entries(data.headers).forEach(([k,v]) => rawText += `${k}: ${v}\n`);
    rawText += `\n${data.body || '(No Body)'}`;

    // 修改弹框标题
    const titleEl = document.querySelector('#stackModal .modal-title');
    if (titleEl) {
        titleEl.innerText = "🌐 网络请求详情"; 
    }

    
    const contentEl = document.getElementById('stackContent');
    if(contentEl) {
        contentEl.innerText = rawText;
        const el = document.getElementById('stackModal');
        const modal = bootstrap.Modal.getOrCreateInstance(el);
        modal.show();
    } 
};

window.clearNetLogs = UI.clearAllLogs; 
window.clearFileLogs = UI.clearAllLogs;
window.clearInfoLogs = UI.clearAllLogs;

// 搜索过滤器初始化辅助函数
function setupFilters() {
    function setup(inputId, tbodyId, indices) {
        const input = document.getElementById(inputId);
        const tbody = document.getElementById(tbodyId);
        if(!input || !tbody) return;
        input.addEventListener('input', function() {
            const term = this.value.toLowerCase().trim();
            for(let row of tbody.getElementsByTagName('tr')) {
                if(!term) { row.style.display = ''; continue; }
                let match = false;
                const cells = row.getElementsByTagName('td');
                for(let idx of indices) {
                    if(cells[idx] && cells[idx].innerText.toLowerCase().includes(term)) { match = true; break; }
                }
                row.style.display = match ? '' : 'none';
            }
        });
    }
    setup('netSearch', 'netLogBody', [1, 2]);
    setup('fileSearch', 'fileLogBody', [1, 2, 3]);
    setup('infoSearch', 'infoLogBody', [1, 2, 3]);
}
