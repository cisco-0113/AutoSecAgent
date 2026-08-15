# Mobile 工具链引导 — AutoSecAgent P2
# 分层安装：纯 Python 兜底（必装）→ jadx 自带 JRE（推荐）→ apktool（需系统 java）→ frida/adb（动态可选）
param(
    [string]$VenvPython = "d:\Trae work zone\CTF\AutoSecAgent\.venv\Scripts\python.exe",
    [string]$ToolRoot   = "d:\Trae work zone\CTF\AutoSecAgent\tools\mobile\bin"
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $ToolRoot | Out-Null

Write-Host "== [1/4] androguard（纯 Python 静态解析兜底，必装）==" -ForegroundColor Cyan
& $VenvPython -m pip install -q androguard
& $VenvPython -c "import androguard; print('  androguard', androguard.__version__)"

Write-Host "== [2/4] jadx（自带 JRE 版本，无需系统 java，推荐）==" -ForegroundColor Cyan
$jadxDir = Get-ChildItem $ToolRoot -Directory -Filter "jadx*" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($jadxDir) {
    Write-Host "  已存在: $($jadxDir.FullName)"
} else {
    Write-Host "  未安装。手动下载: https://github.com/skylot/jadx/releases 选择 jadx-*-with-jre-win.zip"
    Write-Host "  解压到 $ToolRoot\jadx 后，$ToolRoot\jadx\bin\jadx.bat 即可用（自带运行时）"
}

Write-Host "== [3/4] apktool（需系统 java，可选）==" -ForegroundColor Cyan
$java = Get-Command java -ErrorAction SilentlyContinue
if ($java) {
    Write-Host "  java 可用: $($java.Source)。下载 apktool.bat + apktool.jar 到 $ToolRoot"
    Write-Host "  https://ibotpeaches.github.io/Apktool/install/"
} else {
    Write-Host "  系统无 java — 跳过（jadx-with-jre 已覆盖反编译需求）"
}

Write-Host "== [4/4] frida-tools（动态插桩，可选；需配合 adb + 设备）==" -ForegroundColor Cyan
& $VenvPython -m pip install -q frida-tools
& $VenvPython -c "import frida; print('  frida', frida.__version__)" 2>$null
$adb = Get-Command adb -ErrorAction SilentlyContinue
if ($adb) { Write-Host "  adb 可用: $($adb.Source)" } else {
    Write-Host "  adb 缺失 — 动态分析需 Android SDK platform-tools（https://developer.android.com/tools/releases/platform-tools）"
}

Write-Host "`n引导完成。最低可用链: androguard（静态三件套）；推荐链: + jadx-with-jre；完整链: + apktool + frida + adb" -ForegroundColor Green
