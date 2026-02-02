// =================================================================
// 传感器监控模块 (Sensor Monitor)
// - 关键修复：改为由 loader 在 ObjC 就绪后调用 startSensorHook()
// - 关键修复：对类/selector 做存在性判断 + 延迟重试，避免"注入时类未加载导致永远Hook不上"
// =================================================================

function startSensorHook() {
    console.log('[Sensor] ========== 传感器监控模块启动 ==========');
    console.log('[Sensor] iOS 版本:', Process.version);
    console.log('[Sensor] 当前进程:', Process.id);

    const CFG = {
        maxRetries: 100,
        pollInterval: 200,

        // 堆栈跟踪配置：
        // - true: 启用堆栈跟踪（传感器启动时获取一次堆栈）
        // - false: 禁用堆栈（传感器操作可能非常频繁，启用可能导致性能问题）
        enableStack: false
    };

    function isReady() {
        return ObjC.available && ObjC.classes && ObjC.classes.CMMotionManager;
    }

    // 获取堆栈信息的辅助函数
    function getStackTrace(context) {
        if (!CFG.enableStack) return "Disabled";
        try {
            return Thread.backtrace(context, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress)
                .join('\n');
        } catch (e) {
            return "获取堆栈失败";
        }
    }

    function safeAttach(clazz, sel, onEnter) {
        try {
            if (!clazz || !clazz[sel]) return false;
            Interceptor.attach(clazz[sel].implementation, { onEnter });
            return true;
        } catch (e) {
            console.log('[Sensor] Hook失败:', sel, e.message);
            return false;
        }
    }

    function installHooks() {
        if (!ObjC.available) {
            console.log('[Sensor] ❌ ObjC 不可用，跳过');
            return false;
        }

        const CMMotionManager = ObjC.classes.CMMotionManager;
        if (!CMMotionManager) {
            console.log('[Sensor] ⚠️ CMMotionManager 类未找到，等待重试');
            return false;
        }

        let ok = 0;

        // 覆盖更多常见selector：很多App用的是 ToQueue:withHandler: 版本
        // 注意：传感器操作通常非常频繁，启用堆栈可能导致性能问题
        // 如需启用堆栈，请将 CFG.enableStack 改为 true

        ok += safeAttach(CMMotionManager, '- startAccelerometerUpdates', function() {
            send({ type: 'sensor', category: 'Accelerometer', method: 'startAccelerometerUpdates', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        ok += safeAttach(CMMotionManager, '- startAccelerometerUpdatesToQueue:withHandler:', function() {
            send({ type: 'sensor', category: 'Accelerometer', method: 'startAccelerometerUpdatesToQueue', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        ok += safeAttach(CMMotionManager, '- startGyroUpdates', function() {
            send({ type: 'sensor', category: 'Gyroscope', method: 'startGyroUpdates', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        ok += safeAttach(CMMotionManager, '- startGyroUpdatesToQueue:withHandler:', function() {
            send({ type: 'sensor', category: 'Gyroscope', method: 'startGyroUpdatesToQueue', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        ok += safeAttach(CMMotionManager, '- startMagnetometerUpdates', function() {
            send({ type: 'sensor', category: 'Magnetometer', method: 'startMagnetometerUpdates', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        ok += safeAttach(CMMotionManager, '- startMagnetometerUpdatesToQueue:withHandler:', function() {
            send({ type: 'sensor', category: 'Magnetometer', method: 'startMagnetometerUpdatesToQueue', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        ok += safeAttach(CMMotionManager, '- startDeviceMotionUpdates', function() {
            send({ type: 'sensor', category: 'DeviceMotion', method: 'startDeviceMotionUpdates', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        ok += safeAttach(CMMotionManager, '- startDeviceMotionUpdatesToQueue:withHandler:', function() {
            send({ type: 'sensor', category: 'DeviceMotion', method: 'startDeviceMotionUpdatesToQueue', details: { timestamp: new Date().toISOString() }, stack: getStackTrace(this.context) });
        }) ? 1 : 0;

        console.log('[Sensor] Hook安装完成，成功数量:', ok);
        return ok > 0;
    }

    // 等待 ObjC/类就绪再安装（与 loader 的策略一致，双保险）
    let retries = 0;
    function loop() {
        if (installHooks()) return;
        if (retries++ > CFG.maxRetries) {
            console.log('[Sensor] 超时：仍未能安装Hook（可能目标App未使用CoreMotion，或类未加载）');
            return;
        }
        setTimeout(loop, CFG.pollInterval);
    }

    loop();
}

// 导出到全局，供 loader.js 调用
// [修复] 避免与 loader.js 等文件拼接后重复声明 const _global 导致语法错误
var _global = typeof globalThis !== 'undefined' ? globalThis : (0, eval)("this");
_global.startSensorHook = startSensorHook;
