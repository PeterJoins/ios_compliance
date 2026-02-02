// =================================================================
// 反调试绕过模块 (Anti-Anti-Debug)
// =================================================================

function bypassAntiDebug() {
    console.log("[Anti-Anti-Debug] 加载模块: Anti-Debug Bypass");
    // 绕过 ptrace PT_DENY_ATTACH
    var ptracePtr = Module.findExportByName(null, "ptrace");
    if (ptracePtr) {
        // [修复] 正确保存原始函数指针，不能用 Function(ptracePtr)
        var orig_ptrace = new NativeFunction(ptracePtr, 'int', ['int', 'int', 'pointer', 'pointer']);
        Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
            try {
                // PT_DENY_ATTACH 的值通常是 31
                if (request == 31) {
                    console.log("[Anti-Anti-Debug] 拦截到 ptrace(PT_DENY_ATTACH)，已屏蔽！");
                    return 0; // 返回成功，实际上什么都没做
                }
                // 其他 ptrace 调用放行
                return orig_ptrace(request, pid, addr, data);
            } catch (e) {
                // [兜底] 绝不能让这里抛异常，否则会导致整个脚本 Script Error 后不再记录日志
                console.log("[Anti-Anti-Debug] ptrace 处理异常(已吞掉): " + e);
                return 0;
            }
        }, 'int', ['int', 'int', 'pointer', 'pointer']));
    }

    // 绕过 sysctl 检测 P_TRACED
    var sysctlPtr = Module.findExportByName(null, "sysctl");
    if (sysctlPtr) {
        Interceptor.attach(sysctlPtr, {
            onEnter: function(args) {
                this.info = args[1]; 
                this.count = args[2].toInt32();
            },
            onLeave: function(retval) {
    
                // 这里可以实现更复杂的逻辑
            }
        });
    }
    
    console.log("[Anti-Anti-Debug] 反调试防护已激活");
}

// 立即执行
bypassAntiDebug();