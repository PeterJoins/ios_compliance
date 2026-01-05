import { state } from './state.js';

/**
 * UI 渲染与交互工具
 */
export const UI = {
    // === Modal 相关 ===
    initModals: () => {
        const globalEl = document.getElementById('globalModal');
        const stackEl = document.getElementById('stackModal');
        const configEl = document.getElementById('configModal');
        
        if (globalEl) state.modals.global = new bootstrap.Modal(globalEl);
        if (stackEl) state.modals.stack = new bootstrap.Modal(stackEl);
        if (configEl) state.modals.config = new bootstrap.Modal(configEl);
    },

    confirm: (title, message, icon = '🤔', btnType = 'primary', confirmText = '确定') => {
        return new Promise((resolve) => {
            if (!state.modals.global) { resolve(window.confirm(`${title}\n\n${message}`)); return; }
            
            document.getElementById('modalTitle').innerText = title;
            document.getElementById('modalBody').innerText = message;
            document.getElementById('modalIcon').innerText = icon;
            
            const confirmBtn = document.getElementById('modalBtnConfirm');
            confirmBtn.className = `btn btn-${btnType} rounded-pill px-4`;
            confirmBtn.innerText = confirmText;
            document.getElementById('modalBtnCancel').classList.remove('d-none');
            
            const handleConfirm = () => { cleanup(); state.modals.global.hide(); resolve(true); };
            const onHidden = () => { cleanup(); resolve(false); };
            const el = document.getElementById('globalModal');
            
            confirmBtn.addEventListener('click', handleConfirm);
            el.addEventListener('hidden.bs.modal', onHidden, { once: true });
            
            function cleanup() { confirmBtn.removeEventListener('click', handleConfirm); }
            state.modals.global.show();
        });
    },

    alert: (title, message, icon = 'ℹ️', btnType = 'primary') => {
        if (!state.modals.global) { window.alert(`${title}\n\n${message}`); return; }
        document.getElementById('modalTitle').innerText = title;
        document.getElementById('modalBody').innerText = message;
        document.getElementById('modalIcon').innerText = icon;
        
        const confirmBtn = document.getElementById('modalBtnConfirm');
        confirmBtn.className = `btn btn-${btnType} rounded-pill px-4`;
        confirmBtn.innerText = "知道了";
        document.getElementById('modalBtnCancel').classList.add('d-none');
        
        confirmBtn.onclick = () => state.modals.global.hide();
        state.modals.global.show();
    },

    showConfigModal: () => {
        if (state.modals.config) state.modals.config.show();
    },

    hideConfigModal: () => {
        if (state.modals.config) state.modals.config.hide();
    },

    // === 状态条更新 ===
    updateSocketStatus: (text, colorClass) => {
        const el = document.getElementById('socket-status');
        if (el) {
            el.innerText = text;
            el.className = `badge bg-secondary ${colorClass}`;
            if (colorClass === 'text-success') el.classList.replace('bg-secondary', 'bg-dark');
        }
    },

    updateGlobalBar: (visible, appName = '', mode = '') => {
        const bar = document.getElementById('global-monitor-bar');
        const nameEl = document.getElementById('global-app-name');
        
        if (visible) {
            if(appName) nameEl.innerText = `${appName} ${mode ? '('+mode+')' : ''}`;
            bar.classList.remove('d-none'); 
            bar.classList.add('d-flex');
        } else {
            bar.classList.remove('d-flex'); 
            bar.classList.add('d-none');
        }
    },

    activateTab: (targetSelector) => {
        const tabEl = document.querySelector(`button[data-bs-target="${targetSelector}"]`);
        if (tabEl) new bootstrap.Tab(tabEl).show();
    },

    // === 日志渲染 ===
    renderNetworkLog: (data) => {
        const tbody = document.getElementById('netLogBody');
        if (!tbody) return;
        
        const tr = document.createElement('tr');
        let methodColor = data.method === 'GET' ? 'text-success' : 'text-primary';
        if (data.method === 'POST') methodColor = 'text-warning fw-bold';
        
        const safeData = encodeURIComponent(JSON.stringify(data));
        
        tr.innerHTML = `
            <td class="text-muted font-monospace align-middle">${data.timestamp}</td>
            <td class="fw-bold ${methodColor} align-middle">${data.method}</td>
            <td class="text-break font-monospace small align-middle">${data.url}</td>
            <td class="text-center align-middle">
                <button class="btn btn-xs btn-outline-secondary py-0" style="font-size: 11px;" 
                        onclick="window.showNetworkDetail('${safeData}')">查看详情</button>
            </td>
        `;
        tbody.prepend(tr);
        if (tbody.children.length > 500) tbody.lastElementChild.remove();
    },

    // 渲染信息采集日志 (隐私合规)
    renderInfoLog: (data) => {
        const tbody = document.getElementById('infoLogBody');
        if (!tbody) return;

        const tr = document.createElement('tr');
        
        // 1. 数据容错处理 (防止字段缺失导致 undefined)
        //const timestamp = data.timestamp || new Date().toLocaleTimeString();
        const timestamp = data.timestamp || new Date().toLocaleTimeString('zh-CN', { hour12: false });
        const category = data.category || 'Info';
        const func = data.func || '-';
        const method = data.method || '';
        const content = data.content || '';
        const stack = data.stack || '无堆栈信息';

        // 2. 根据类型设置徽章颜色
        let badgeClass = 'bg-secondary text-secondary'; // 默认灰色
        const catLower = category.toLowerCase();
        
        if (catLower.includes('idfa')) {
            // 蓝色
            badgeClass = 'bg-primary bg-opacity-10 text-primary border border-primary';
        } else if (catLower.includes('idfv')) {
            // 青色
            badgeClass = 'bg-info bg-opacity-10 text-info border border-info';
        } else if (catLower.includes('pasteboard') || catLower.includes('剪贴板')) {
            // 红色 (高危)
            badgeClass = 'bg-danger bg-opacity-10 text-danger border border-danger';
        } else if (catLower.includes('location')) {
            // 黄色
            badgeClass = 'bg-warning bg-opacity-10 text-warning border border-warning';
        } else if (catLower.includes('photolibrary')) {
            // 绿色
            badgeClass = 'bg-success bg-opacity-10 text-success border border-success';
        } else if (catLower.includes('contacts')) {
            // 深色
            badgeClass = 'bg-dark bg-opacity-10 text-dark border border-dark';
        }else{
            badgeClass = 'bg-dark bg-opacity-10 text-dark border border-dark';
        }

        // 3. 编码堆栈信息 (防止 HTML 注入破坏页面)
        const safeStack = encodeURIComponent(stack);

        // 4. 构建 HTML
        tr.innerHTML = `
            <td class="text-muted font-monospace align-middle py-2">${timestamp}</td>
            <td class="align-middle py-2">
                <span class="badge ${badgeClass}">${category}</span>
            </td>
            <td class="fw-bold text-dark font-monospace align-middle text-break py-2">${func}</td>
            <td class="text-secondary small align-middle py-2">${method}</td>
            <td class="font-monospace text-dark align-middle text-break fw-bold py-2" style="font-size: 11px;">
                ${content}
            </td>
            <td class="text-center align-middle py-2">
                <button class="btn btn-sm btn-outline-secondary py-0" 
                        style="font-size: 12px;" 
                        onclick="window.showStackTrace('${safeStack}')">
                    查看
                </button>
            </td>
        `;

        // 5. 插入并限制行数
        tbody.prepend(tr);
        if (tbody.children.length > 500) {
            tbody.lastElementChild.remove();
        }
    },

    renderFileLog: (data) => {
        const tbody = document.getElementById('fileLogBody');
        if (!tbody) return;
        
        const tr = document.createElement('tr');
        
        // // 1. 操作类型徽章
        // let opBadge = data.op.includes('创建') 
        //     ? '<span class="badge bg-success bg-opacity-10 text-success border border-success">创建</span>'
        //     : '<span class="badge bg-danger bg-opacity-10 text-danger border border-danger">删除</span>';
       // 1. 操作类型徽章
        let opBadge = data.op.includes('删除') 
            ? '<span class="badge bg-danger bg-opacity-10 text-danger border border-danger">删除</span>'
            : `<span class="badge bg-success bg-opacity-10 text-success border border-success">${data.op}</span>`;

        
        // 2. 编码堆栈信息
        const safeStack = encodeURIComponent(data.stack);
        
        // 3. 构建 HTML (生成按钮，调用 main.js 中的 window.showStackTrace)
        tr.innerHTML = `
            <td class="text-muted font-monospace align-middle py-2">${data.timestamp}</td>
            <td class="fw-bold text-primary font-monospace align-middle py-2">${data.func}</td>
            <td class="align-middle py-2">${opBadge}</td>
            <td class="text-break font-monospace small align-middle py-2" style="word-break: break-all;">${data.method}</td>
            <td class="text-center align-middle py-2">
                <button class="btn btn-sm btn-outline-secondary py-0" 
                        style="font-size: 12px;" 
                        onclick="window.showStackTrace('${safeStack}')">
                    查看详情
                </button>
            </td>
        `;
        
        tbody.prepend(tr);
        if (tbody.children.length > 500) tbody.lastElementChild.remove();
    },

    renderAppList: (apps) => {
        const tbody = document.getElementById('appTableBody');
        if (!apps || apps.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="p-0 border-0"><div class="d-flex flex-column align-items-center justify-content-center text-muted" style="height: calc(100vh - 200px);"><h5 class="fw-light">无应用</h5></div></td></tr>';
            return;
        }
        tbody.innerHTML = apps.map(app => {
            const icon = app.icon 
                ? `<img src="data:image/png;base64,${app.icon}" class="app-icon shadow-sm" style="width:40px;height:40px;border-radius:10px;">` 
                : `<div style="width:40px;height:40px;background:#eee;border-radius:10px;"></div>`;
            const safeName = app.name.replace(/'/g, "\\'");
            return `<tr>
                <td class="text-center">${icon}</td>
                <td class="fw-bold">${app.name}</td>
                <td class="font-monospace small text-muted">${app.bundle_id}</td>
                <td><span class="badge bg-light text-dark border">${app.version}</span></td>
                <td class="text-end pe-4">
                    <button class="btn btn-sm btn-outline-primary rounded-pill px-3" onclick="window.handleMonitor('${safeName}', '${app.bundle_id}')">📡 开启监控</button>
                </td>
            </tr>`;
        }).join('');
    },

    clearAllLogs: () => {
        ['netLogBody', 'fileLogBody', 'infoLogBody'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = '';
        });
    }
};