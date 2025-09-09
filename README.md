# WinApkInfo
在Windows上查看APK文件信息

一个图形化小工具，用于快速查看解析 Android APK 的基本信息，预览、导出应用图标，并根据APK名称及版本号快速重命名文件，功能以简洁简单为主。

APK-Info目前有一些带混淆的APK包貌似无法解析，故有了此软件，本软件是APK-Info的PyQT5实现。

## 界面

<img src="https://github.com/Sinryou/WinApkInfo/blob/master/example/WinApkInfo_UI.png" width="500" alt="界面图片"/><br/>

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
  - 自动识别并提取 APK 内的图标（支持 PNG / adaptive icon XML）  
  - 合成前景/背景图层，展示最终应用图标（如果APK文件的res文件夹被混淆或者前景/背景文件是xml矢量文件则不支持）

- **APK 文件重命名**  
  - 根据应用名 + 版本号自动生成新文件名  
  - 一键重命名原始 APK 文件  

- **aapt2 原始输出**  
  - 提供完整文本输出，方便进一步分析  
