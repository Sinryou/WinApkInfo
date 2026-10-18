# WinApkInfo
在Windows上查看APK文件信息

一个图形化小工具，用于快速查看解析 Android APK 的基本信息，预览、导出应用图标，并根据APK名称及版本号快速重命名文件，功能以简洁简单为主。

[APK-Info](https://github.com/Enyby/APK-Info "跳转仓库")目前有一些带混淆的APK包貌似无法解析，故有了此软件，本软件是APK-Info的PyQT6实现。

## 界面

<img src="https://github.com/Sinryou/WinApkInfo/blob/main/example/WinApkInfo_UI.png" width="500" alt="界面图片"/><br/>
<img src="https://github.com/Sinryou/WinApkInfo/blob/main/example/WinApkInfo_UI_11.png" width="500" alt="界面图片"/><br/>

## 功能

- **APK 拖放/选择**  
  - 支持直接将 APK 拖入窗口，或通过文件选择器加载。

- **信息解析（调用 aapt2）**  
  - 包名、版本号（versionName / versionCode）  
  - SDK 要求（minSdk / targetSdk / compileSdk）  
  - 启动 Activity  
  - 支持的 CPU 架构、屏幕、密度、语言  
  - 权限、功能特性（uses-feature / implied-feature）  
  - 多语言应用名（优先显示中文）

- **应用图标提取**  
  - 自动识别并提取 APK 内的图标（支持 PNG / adaptive icon XML / VectorDrawable 矢量）  
  - 合成前景/背景图层（含混淆资源、<scale> 包装、渐变填充），统一导出 512×512 PNG

- **APK 文件重命名**  
  - 根据应用名 + 版本号自动生成新文件名  
  - 一键重命名原始 APK 文件  

- **aapt2 原始输出**  
  - 提供完整文本输出，方便进一步分析  

## 运行环境

- Windows 10/11（x64）
- Python 3.10+
- `aapt2`（解析 APK 时必需）

## 从源码运行

```powershell
python -m pip install -r requirements.txt
python main.py
```

`aapt2` 的查找顺序：程序目录 → 程序目录下 `tools/aapt2.exe` → 系统 `PATH`。开发时也可以直接把 `aapt2.exe` 放到仓库的 `tools/` 目录。

## 构建与打包

构建脚本基于 PyInstaller，产出免安装的 Windows 目录版和单文件版：

```powershell
# 安装构建依赖（包含运行依赖）
python -m pip install -r requirements-dev.txt

# 目录版（启动快，推荐）
.\build.ps1 -Clean

# 单文件版
.\build.ps1 -Clean -Mode onefile
```

如果 `aapt2.exe` 不在 `tools/`、不在 `PATH`、也不在 Android SDK 的 `build-tools` 中，显式传入：

```powershell
.\build.ps1 -Clean -Aapt2Path "D:\Android\Sdk\build-tools\35.0.0\aapt2.exe"
```

构建完成后：

```text
dist/WinApkInfo-<version>-windows-x64-onedir.zip
dist/WinApkInfo-<version>-windows-x64-onefile.zip
dist/WinApkInfo-<version>-windows-x64-<mode>.zip.sha256
```

脚本会依次执行：检查依赖 → 运行回归检查（`verify_fixes.py --quick`）→ 生成 Windows 文件版本信息 → 打包 `resources/` 与 `aapt2.exe` → 运行 `WinApkInfo.exe --self-test` → 生成 zip 与 SHA256。

常用参数：

| 参数 | 说明 |
|---|---|
| `-Mode onedir\|onefile` | 目录版或单文件版，默认 `onedir` |
| `-Aapt2Path <file>` | 指定要随包携带的 `aapt2.exe` |
| `-Version <x.y.z>` | 覆盖 `version.py` 中的版本号 |
| `-SkipTests` | 跳过构建前回归检查 |
| `-FullTests` | 运行需要 `testSample/` 的完整回归；不传则只跑合成用例 |
| `-AllowMissingAapt2` | 允许构建不含 `aapt2.exe` 的包（仅排障用） |
| `-NoZip` | 只生成 `dist/`，不创建 zip |
| `-Clean` | 构建前删除 `build/` 与 `dist/` |
| `-Python <exe>` | 指定 Python 解释器 |

版本号统一在 [`version.py`](version.py) 中维护，构建脚本、Windows 文件属性与“关于”对话框共用该值。

### 自检与回归

```powershell
python verify_fixes.py --quick   # 不依赖 testSample，适合 CI
python verify_fixes.py           # 含真实 APK 端到端，需要 testSample/
python main.py --version         # 打印版本
python main.py --self-test       # 检查 aapt2 与随包资源
```

`testSample/` 不入库。没有真实样本时（例如 CI），`build.ps1` 会用仓库内置的
`tests/fixtures/mini.apk` 作为 `--self-test` 样本，保证打包产物的图标提取链路
（badging → 自适应图标 → 矢量栅格化）也会被验证。该固件由
`python scripts/make_mini_apk.py` 生成（只需 aapt2 + Pillow，不依赖 Android SDK
或 `android.jar`），需要时重新生成并提交即可。

### 持续集成

[`.github/workflows/build.yml`](.github/workflows/build.yml) 会在 Windows runner 上构建 `onedir` 与 `onefile` 两种产物并上传 artifact；推送 `v*` 标签时会自动创建 GitHub Release 并附带 zip 与校验文件。

```powershell
git tag v1.1.2
git push origin v1.1.2
```
