# 📋 CHANGELOG - iOS App 隐私合规检测系统

## 📌 版本信息

- **项目名称**: iOS App 隐私合规检测系统
- **基于**: [https://github.com/aylhex/ios_compliance)
- **许可证**: LGPL-2.1

---

## 🚀 更新日志

### 📅 2026-01-30 - v1.1.0 扩展隐私监控能力

#### ✨ 新增功能

##### 🔐 健康数据监控 (HealthKit)
- **新增文件**: 无（集成于 `privacy.js`）
- **监控范围**:
  - `HKHealthStore.requestAuthorizationToShareTypes:readTypes:completion:`
    - 监控健康数据权限申请
    - 记录分享类型 (shareTypes) 和读取类型 (readTypes)
  - `HKSampleQuery.initWithSampleType:predicate:limit:sortDescriptors:resultsHandler:`
    - 监控健康样本数据查询
    - 记录样本类型 (sampleType)

##### 🏠 家庭数据监控 (HomeKit)
- **新增文件**: 无（集成于 `privacy.js`）
- **监控范围**:
  - `HMHomeManager.init` - 监控 HomeManager 初始化
  - `HMHomeManager.homes` - 监控访问家庭列表

##### 📅 日历数据监控 (Calendar/EventKit)
- **新增文件**: 无（集成于 `privacy.js`）
- **监控范围**:
  - `EKEventStore.requestAccessToEntityType:completion:`
    - 监控日历权限申请
  - `EKEventStore.eventsMatchingPredicate:`
    - 监控日历事件查询

##### 🎤 麦克风权限监控 (Microphone)
- **新增文件**: 无（集成于 `privacy.js`）
- **监控范围**:
  - `AVAudioSession.requestRecordPermission:`
    - 监控麦克风录音权限申请
  - `AVAudioSession.setActive:error:`
    - 监控音频会话激活状态

##### 📱 传感器数据监控 (CoreMotion) - 独立模块
- **新增文件**: `app/frida_scripts/sensor.js`
- **监控范围**:
  - 加速度计 (Accelerometer)
    - `startAccelerometerUpdates`
    - `startAccelerometerUpdatesToQueue:withHandler:`
  - 陀螺仪 (Gyroscope)
    - `startGyroUpdates`
    - `startGyroUpdatesToQueue:withHandler:`
  - 磁力计 (Magnetometer)
    - `startMagnetometerUpdates`
    - `startMagnetometerUpdatesToQueue:withHandler:`
  - 设备运动 (DeviceMotion)
    - `startDeviceMotionUpdates`
    - `startDeviceMotionUpdatesToQueue:withHandler:`

#### 🛠️ 优化与修复

##### 🔧 堆栈跟踪配置优化
- 新增全局 `CONFIG.enableStack` 配置项
- **隐私模块** (`privacy.js`):
  - 默认禁用堆栈（`enableStack: false`）
  - 可按需开启敏感操作的堆栈跟踪
- **传感器模块** (`sensor.js`):
  - 默认禁用堆栈（`enableStack: false`）
  - 传感器操作可能非常频繁，禁用堆栈以保证性能

##### ⏱️ 延迟加载机制优化
- 新增 `whenClassAvailable()` 辅助函数
- 支持类加载重试机制（默认最多 150 次，每次间隔 200ms）
- 解决"注入时类未加载导致永远 Hook 不上"的问题

##### 🔄 模块化重构
- 传感器模块独立为 `sensor.js`
- 所有模块通过 `loader.js` 统一加载
- `startSensorHook()` 函数导出到全局供 loader 调用

##### 🚫 高频操作性能优化
- 定义高频操作白名单：`['Pasteboard', 'Keychain']`
- 高频操作自动禁用堆栈获取，防止性能问题

---

### 📅 2025-xx-xx - v1.0.0 基础版本 (Fork 自 PeterJoins/ios_compliance)

#### 📦 核心功能

- 📊 **数据总览** - 环形图展示敏感行为分布
- 📱 **应用管理** - 自动列出设备上已安装的用户应用
- 📝 **隐私监控** - IDFA/IDFV、剪贴板、Keychain、定位、相册、通讯录
- 📂 **文件监控** - 监控文件创建/删除/读取/复制操作
- 🌐 **网络监控** - 全面 Hook NSURLSession
- 🛡️ **双模式支持** - Frida (USB) + Tweak (越狱插件)

---

## 📂 项目结构

```
ios_compliance/
├── app_monitor/
│   ├── run.py                    # 项目启动入口
│   ├── config.py                 # 配置文件 (SSH 账号等)
│   ├── requirements.txt          # Python 依赖
│   ├── app/
│   │   ├── __init__.py           # Flask App 初始化
│   │   ├── api/                  # 后端 API 路由
│   │   ├── services/             # 核心服务 (Frida管理, Tweak部署)
│   │   ├── frida_scripts/        # Frida JS 注入脚本
│   │   │   ├── loader.js         # 脚本加载器
│   │   │   ├── privacy.js        # 隐私监控模块
│   │   │   ├── sensor.js         # 传感器监控模块 (新增)
│   │   │   ├── file.js           # 文件监控模块
│   │   │   ├── network.js        # 网络监控模块
│   │   │   ├── sdk.js            # SDK检测模块
│   │   │   ├── antilock.js       # 防锁屏模块
│   │   │   └── bypass.js         # 反反调试模块
│   │   ├── tweak_libs/           # 存放编译好的 MonitorTweak.dylib
│   │   ├── utils/                # 工具函数
│   │   ├── web/                  # Web页面入口点
│   │   ├── static/               # 前端静态资源 (CSS, JS, Images)
│   │   └── templates/            # HTML 模板
│   └── README.md                 # 主 README
├── tweak_monitor/                # Theos Tweak 源码
│   ├── Tweak.x                   # 主Tweak文件
│   ├── MonitorFiles.x            # 文件监控模块
│   ├── MonitorHooks.x            # 隐私监控模块
│   ├── MonitorUtils.h/m          # 监控工具
│   ├── SDKDetector.h/m           # SDK检测
│   └── Makefile                  # 编译配置
├── .gitignore                    # Git 忽略配置
├── LICENSE.txt                   # 许可证
└── README.md                     # 项目说明文档
```

---

## 🔧 快速开始

```bash
# 1. 克隆项目
git clone https://github.com/你的用户名/ios_compliance.git
cd ios_compliance

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或
.\venv\Scripts\activate   # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 启动服务
python run.py

# 5. 访问 Web 界面
# http://127.0.0.1:8080
```

---

## 📝 注意事项

1. **堆栈跟踪**: 默认禁用以保证性能，如需调试可手动开启
2. **传感器监控**: 传感器操作频率可能很高，建议保持堆栈禁用
3. **高频操作**: 剪贴板和 Keychain 操作已加入白名单，禁用堆栈
4. **延迟加载**: 部分类可能需要等待 App 加载完成后才能 Hook

---

## 🤝 致谢

- 感谢 [aylhex]https://github.com/aylhex/ios_compliance 创建的原项目
- 感谢 [Frida](https://frida.re/) 提供的动态注入框架
- 感谢 [Theos](https://theos.dev/) 提供的越狱开发工具链

---

## 📄 许可证

本项目基于 LGPL-2.1 许可证开源，详情请查看 [LICENSE.txt](LICENSE.txt)

