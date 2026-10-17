# tools/

`build.ps1` 会优先使用这里的 `aapt2.exe`：

```text
tools/aapt2.exe
```

也可以不放在这里，改用：

```powershell
.\build.ps1 -Aapt2Path "D:\Android\Sdk\build-tools\35.0.0\aapt2.exe"
```

或把 aapt2 加入 `PATH`。`tools/aapt2.exe` 是本地二进制，不纳入版本控制。
