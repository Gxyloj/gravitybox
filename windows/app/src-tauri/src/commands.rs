use crate::antigravity::{
    get_antigravity_info, is_antigravity_running, launch_antigravity, quit_antigravity_detailed,
    safe_relaunch_antigravity, AntigravityInfo, GracefulCloseOutcome, SafeRelaunchResult,
};
use crate::autostart;
use crate::backend::BackendManager;
use crate::config::{atomic_replace_file, load_config, save_config, UiConfig};
use crate::ipc_pipe::{normalize_windows_path, strip_verbatim_prefix};
use crate::tray::{
    hide_tray_window, set_tray_autohide_suppressed as set_tray_autohide_flag,
    show_main_window_and_focus, update_tray_menu_language,
};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub state_dir: String,
    pub pipe_name: String,
    pub os_label: String,
    pub antigravity: AntigravityInfo,
}

#[tauri::command]
pub async fn backend_request(
    backend: State<'_, Arc<BackendManager>>,
    payload: Value,
) -> Result<Value, String> {
    let mgr = Arc::clone(backend.inner());
    tokio::task::spawn_blocking(move || mgr.request(payload))
        .await
        .map_err(|e| format!("后台任务调度失败: {}", e))?
}

#[tauri::command]
pub async fn restart_backend(backend: State<'_, Arc<BackendManager>>) -> Result<(), String> {
    let mgr = Arc::clone(backend.inner());
    tokio::task::spawn_blocking(move || mgr.restart())
        .await
        .map_err(|e| format!("重启后端任务失败: {}", e))?
}

#[tauri::command]
pub async fn get_app_info(backend: State<'_, Arc<BackendManager>>) -> Result<AppInfo, String> {
    let mgr = Arc::clone(backend.inner());
    tokio::task::spawn_blocking(move || {
        let ag = get_antigravity_info(mgr.resource_dir());
        let os_label = format!("Windows {}", std::env::consts::ARCH);
        AppInfo {
            version: option_env!("GRAVITYBOX_WINDOWS_RELEASE_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            state_dir: mgr.state_dir.to_string_lossy().to_string(),
            pipe_name: mgr.current_pipe_name(),
            os_label,
            antigravity: ag,
        }
    })
    .await
    .map_err(|e| format!("读取环境信息失败: {}", e))
}

#[tauri::command]
pub async fn launch_antigravity_cmd(
    backend: State<'_, Arc<BackendManager>>,
) -> Result<(), String> {
    let state_dir = backend.state_dir.clone();
    tokio::task::spawn_blocking(move || launch_antigravity(Some(state_dir.as_path())))
        .await
        .map_err(|e| format!("启动失败: {}", e))?
}

#[tauri::command]
pub async fn safe_relaunch_antigravity_cmd(
    backend: State<'_, Arc<BackendManager>>,
    confirm_background_exit: Option<bool>,
) -> Result<SafeRelaunchResult, String> {
    let res_dir = backend.resource_dir().map(|p| p.to_path_buf());
    let state_dir = backend.state_dir.clone();
    let confirmed = confirm_background_exit.unwrap_or(false);
    tokio::task::spawn_blocking(move || {
        safe_relaunch_antigravity(res_dir.as_deref(), Some(state_dir.as_path()), confirmed)
    })
    .await
    .map_err(|e| format!("安全重启失败: {}", e))?
}

#[tauri::command]
pub async fn quit_antigravity_and_wait_cmd(
    backend: State<'_, Arc<BackendManager>>,
    timeout_ms: Option<u64>,
    confirm_background_exit: Option<bool>,
) -> Result<GracefulCloseOutcome, String> {
    let res_dir = backend.resource_dir().map(|p| p.to_path_buf());
    let timeout = timeout_ms.unwrap_or(18_000).clamp(1_000, 35_000);
    let confirmed = confirm_background_exit.unwrap_or(false);
    tokio::task::spawn_blocking(move || {
        quit_antigravity_detailed(res_dir.as_deref(), timeout, confirmed)
    })
    .await
    .map_err(|e| format!("等待 Antigravity 退出失败: {}", e))?
}

#[tauri::command]
pub async fn get_antigravity_running(
    backend: State<'_, Arc<BackendManager>>,
) -> Result<bool, String> {
    let res_dir = backend.resource_dir().map(|p| p.to_path_buf());
    tokio::task::spawn_blocking(move || is_antigravity_running(res_dir.as_deref()))
        .await
        .map_err(|e| format!("检测运行状态失败: {}", e))
}

const ALLOWED_EXTERNAL_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "cdn.jsdelivr.net",
    "accounts.google.com",
    "cloud.google.com",
    "platform.claude.com",
    "developers.openai.com",
];

fn validate_external_url(raw: &str) -> Result<String, String> {
    if raw.is_empty()
        || raw.len() > 4096
        || raw.bytes().any(|b| b < 0x20 || b == 0x7f)
        || raw
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == '\\')
    {
        return Err("链接格式无效或包含非法字符".to_string());
    }
    let rest = raw
        .strip_prefix("https://")
        .ok_or_else(|| "仅允许打开白名单内的 https:// 链接".to_string())?;
    if rest.is_empty() {
        return Err("链接格式无效".to_string());
    }
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() || authority.contains('@') || authority.contains(':') {
        return Err("链接主机格式无效".to_string());
    }
    let host = authority.to_ascii_lowercase();
    if !ALLOWED_EXTERNAL_HOSTS.contains(&host.as_str()) {
        return Err(format!("目标域名不在安全白名单中: {}", host));
    }
    Ok(raw.to_string())
}

#[tauri::command]
pub fn open_external_url(url: String) -> Result<(), String> {
    let validated = validate_external_url(&url)?;
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let verb: Vec<u16> = OsStr::new("open").encode_wide().chain(Some(0)).collect();
        let target: Vec<u16> = OsStr::new(&validated).encode_wide().chain(Some(0)).collect();
        let res = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                target.as_ptr(),
                null(),
                null(),
                SW_SHOWNORMAL,
            )
        };
        if (res as isize) <= 32 {
            return Err("无法打开默认浏览器".to_string());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = validated;
        Err("Unsupported platform".to_string())
    }
}

fn resolve_explorer_exe() -> PathBuf {
    let win_dir = std::env::var("SystemRoot")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("WINDIR").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| r"C:\Windows".to_string());
    strip_verbatim_prefix(Path::new(win_dir.trim())).join("explorer.exe")
}

fn normalized_path_is_within(candidate_norm: &str, base_norm: &str) -> bool {
    let cand = candidate_norm.to_lowercase();
    let base = base_norm.to_lowercase();
    if base.is_empty() {
        return false;
    }
    if cand == base {
        return true;
    }
    let prefix = if base.ends_with('\\') {
        base
    } else {
        format!("{}\\", base)
    };
    cand.starts_with(&prefix)
}

fn is_path_within_state_dir(target: &Path, state_dir: &Path) -> bool {
    let target_norm = normalize_windows_path(target);
    let state_norm = normalize_windows_path(state_dir);
    if normalized_path_is_within(&target_norm, &state_norm) {
        return true;
    }
    // Also walk existing ancestors + canonicalize state_dir to defeat junctions/symlinks/8.3 short paths,
    // even when multiple trailing subdirectories of `target` do not exist yet.
    if let Ok(canon_state) = std::fs::canonicalize(state_dir) {
        let canon_state_norm = normalize_windows_path(&canon_state);
        if normalized_path_is_within(&target_norm, &canon_state_norm) {
            return true;
        }
        let mut trailing: Vec<std::ffi::OsString> = Vec::new();
        let mut cursor = Some(target);
        while let Some(cur) = cursor {
            if let Ok(canon_anc) = std::fs::canonicalize(cur) {
                let mut rebuilt = canon_anc;
                for seg in trailing.iter().rev() {
                    rebuilt.push(seg);
                }
                let canon_target_norm = normalize_windows_path(&rebuilt);
                if normalized_path_is_within(&canon_target_norm, &canon_state_norm)
                    || normalized_path_is_within(&canon_target_norm, &state_norm)
                {
                    return true;
                }
                break;
            }
            if let Some(name) = cur.file_name() {
                trailing.push(name.to_os_string());
            } else {
                break;
            }
            cursor = cur.parent();
        }
    }
    false
}

fn is_safe_local_windows_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    // Reject UNC/device prefixes (including case-insensitive `\\?\UNC\`) to avoid SMB NTLM leaks
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with(r"\\?\unc\") || lower.starts_with(r"\\.\") || lower.starts_with("//") {
        return None;
    }
    let stripped = strip_verbatim_prefix(std::path::Path::new(trimmed));
    let s = stripped.to_string_lossy();
    if s.starts_with(r"\\") || s.starts_with('/') {
        return None;
    }
    // Require explicit local drive root `X:\` or `X:/`, reject NTFS Alternate Data Streams (`:`), and reject `..`
    let bytes = s.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || (bytes[2] != b'\\' && bytes[2] != b'/')
    {
        return None;
    }
    if s[2..].contains(':') {
        return None;
    }
    if stripped
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    Some(stripped)
}

fn validate_dir_path(raw: &str) -> Result<PathBuf, String> {
    let p = is_safe_local_windows_path(raw).ok_or_else(|| "无效的目录路径".to_string())?;
    if !p.is_dir() {
        return Err(format!("目标不是有效目录: {}", p.display()));
    }
    Ok(p)
}

fn validate_json_save_path(raw: &str, state_dir: &Path) -> Result<PathBuf, String> {
    let p = is_safe_local_windows_path(raw).ok_or_else(|| "保存路径无效".to_string())?;
    if is_path_within_state_dir(&p, state_dir) {
        return Err("不允许将导出文件覆盖写入 GravityBox 数据目录内部".to_string());
    }
    let is_json = p
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if !is_json {
        return Err("仅允许保存为 .json 文件".to_string());
    }
    if let Ok(meta) = std::fs::symlink_metadata(&p) {
        if meta.file_type().is_symlink() || meta.is_dir() {
            return Err("目标路径不允许覆盖目录或符号链接".to_string());
        }
    }
    Ok(p)
}

#[tauri::command]
pub fn open_folder(path: String) -> Result<(), String> {
    let p = validate_dir_path(&path)?;
    #[cfg(windows)]
    {
        Command::new(resolve_explorer_exe())
            .arg(&p)
            .spawn()
            .map_err(|e| format!("无法打开资源管理器: {}", e))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = p;
        Err("Unsupported platform".to_string())
    }
}

#[tauri::command]
pub fn reveal_in_explorer(path: String) -> Result<(), String> {
    let p = is_safe_local_windows_path(&path).ok_or_else(|| "无效的文件或目录路径".to_string())?;
    if !p.exists() {
        if let Some(parent) = p.parent() {
            if parent.is_dir() {
                return open_folder(parent.to_string_lossy().to_string());
            }
        }
        return Err(format!("路径不存在: {}", p.display()));
    }
    #[cfg(windows)]
    {
        let explorer = resolve_explorer_exe();
        if p.is_file() {
            Command::new(&explorer)
                .arg("/select,")
                .arg(&p)
                .spawn()
                .map_err(|e| format!("无法在资源管理器中定位文件: {}", e))?;
            Ok(())
        } else if p.is_dir() {
            Command::new(&explorer)
                .arg(&p)
                .spawn()
                .map_err(|e| format!("无法打开目录: {}", e))?;
            Ok(())
        } else {
            Err(format!("路径不是有效文件或目录: {}", p.display()))
        }
    }
    #[cfg(not(windows))]
    {
        Err("Unsupported platform".to_string())
    }
}

#[tauri::command]
pub fn open_recycle_bin() -> Result<(), String> {
    #[cfg(windows)]
    {
        Command::new(resolve_explorer_exe())
            .arg("shell:RecycleBinFolder")
            .spawn()
            .map_err(|e| format!("无法打开回收站: {}", e))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("Unsupported platform".to_string())
    }
}

#[tauri::command]
pub fn set_tray_autohide_suppressed(suppressed: bool) {
    set_tray_autohide_flag(suppressed);
}

#[tauri::command]
pub fn get_autostart() -> Result<bool, String> {
    autostart::get_autostart()
}

#[tauri::command]
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    autostart::set_autostart(enabled)
}

#[tauri::command]
pub fn load_ui_config(backend: State<'_, Arc<BackendManager>>) -> UiConfig {
    load_config(&backend.state_dir)
}

#[tauri::command]
pub fn save_ui_config(
    app: AppHandle,
    backend: State<'_, Arc<BackendManager>>,
    config: UiConfig,
) -> Result<(), String> {
    save_config(&backend.state_dir, &config)?;
    let _ = app.emit("ui-config-changed", &config);
    Ok(())
}

#[tauri::command]
pub fn show_main_window(app: AppHandle, page: Option<String>) {
    hide_tray_window(&app);
    show_main_window_and_focus(&app, page.as_deref());
}

#[tauri::command]
pub fn hide_tray_window_cmd(app: AppHandle) {
    hide_tray_window(&app);
}

#[tauri::command]
pub fn sync_tray_language(app: AppHandle, is_english: bool) {
    update_tray_menu_language(&app, is_english);
}

#[tauri::command]
pub fn set_window_dark_mode(app: AppHandle, is_dark: bool) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
        const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
        let value: i32 = if is_dark { 1 } else { 0 };
        for label in ["main", "tray"] {
            if let Some(win) = app.get_webview_window(label) {
                if let Ok(hwnd) = win.hwnd() {
                    unsafe {
                        DwmSetWindowAttribute(
                            hwnd.0 as _,
                            DWMWA_USE_IMMERSIVE_DARK_MODE,
                            &value as *const i32 as *const _,
                            std::mem::size_of::<i32>() as u32,
                        );
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (app, is_dark);
    }
}

fn save_json_file_checked(path: &str, content: Value, state_dir: &Path) -> Result<(), String> {
    use std::io::Write;
    let target = validate_json_save_path(path, state_dir)?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "保存路径缺少有效父目录".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("无法创建目标目录: {}", e))?;

    let mut pretty = serde_json::to_string_pretty(&content)
        .map_err(|e| format!("JSON 序列化失败: {}", e))?;
    pretty.push('\n');

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("export.json");
    let tmp = parent.join(format!(".{}.tmp.{}.{}", file_name, std::process::id(), stamp));

    let write_res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(pretty.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("文件写入失败: {}", err));
    }

    if let Err(err) = atomic_replace_file(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("文件保存失败: {}", err));
    }
    Ok(())
}

#[tauri::command]
pub fn save_json_file(
    backend: State<'_, Arc<BackendManager>>,
    path: String,
    content: Value,
) -> Result<(), String> {
    save_json_file_checked(&path, content, &backend.state_dir)
}

#[tauri::command]
pub fn quit_app(app: AppHandle, backend: State<'_, Arc<BackendManager>>) {
    let mgr = Arc::clone(backend.inner());
    std::thread::spawn(move || {
        mgr.graceful_stop();
        app.exit(0);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_url_whitelist_enforces_https_and_rejects_spoofing() {
        // Allowed HTTPS whitelist domains
        assert!(validate_external_url("https://github.com/Enzoo404/gravitybox/releases").is_ok());
        assert!(validate_external_url("https://GITHUB.COM/Enzoo404/gravitybox").is_ok());
        assert!(
            validate_external_url("https://raw.githubusercontent.com/Enzoo404/gravitybox/main/pricing.json").is_ok()
        );
        assert!(validate_external_url("https://cdn.jsdelivr.net/gh/Enzoo404/gravitybox/pricing.json").is_ok());
        assert!(
            validate_external_url("https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&scope=openid").is_ok()
        );
        assert!(validate_external_url("https://cloud.google.com/vertex-ai/pricing").is_ok());
        assert!(validate_external_url("https://platform.claude.com/docs/en/about-claude/pricing").is_ok());
        assert!(validate_external_url("https://developers.openai.com/api/docs/pricing").is_ok());

        // Must reject HTTP, non-whitelisted hosts, prefix/suffix tricks, userinfo, quotes, spaces, control chars, ports
        assert!(validate_external_url("http://github.com/Enzoo404/gravitybox").is_err());
        assert!(validate_external_url("https://attacker.example.invalid/phish").is_err());
        assert!(validate_external_url("https://github.com.example.invalid/phish").is_err());
        assert!(validate_external_url("https://evil-github.com/phish").is_err());
        assert!(validate_external_url("https://github.com@example.invalid/phish").is_err());
        assert!(validate_external_url("https://github.com:8443/Enzoo404").is_err());
        assert!(validate_external_url("https://github.com/Enzoo404 \"--evil\"").is_err());
        assert!(validate_external_url("https://github.com/Enzoo404'bad").is_err());
        assert!(validate_external_url("https://github.com/Enzoo404\r\n").is_err());
        assert!(validate_external_url("https://github.com/Enzoo404\r\nX-Inject:1").is_err());
        assert!(validate_external_url("https://github.com/Enzoo404\0").is_err());
        assert!(validate_external_url(r"https://github.com\example.invalid").is_err());
        assert!(validate_external_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn explorer_exe_resolves_absolute_system_path() {
        let exe = resolve_explorer_exe();
        let s = exe.to_string_lossy();
        assert!(!s.starts_with(r"\\?\"), "must not have verbatim prefix: {}", s);
        assert!(
            s.to_ascii_lowercase().ends_with(r"\explorer.exe"),
            "must resolve to explorer.exe: {}",
            s
        );
        assert!(exe.is_absolute(), "must be absolute: {}", s);
    }

    #[test]
    fn dir_and_json_path_validation_enforces_security_boundaries() {
        let root_tmp = strip_verbatim_prefix(&std::env::temp_dir())
            .join(format!("gb-cmd-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root_tmp);
        let state_dir = root_tmp.join("GravityBox");
        let export_dir = root_tmp.join("GravityBoxBackup");
        std::fs::create_dir_all(state_dir.join("sub")).unwrap();
        std::fs::create_dir_all(&export_dir).unwrap();

        let fake_exe = export_dir.join("calc.exe");
        std::fs::write(&fake_exe, b"stub").unwrap();

        // open_folder validator accepts local directories and rejects files, UNC, traversal, leading '/', and control chars
        assert!(validate_dir_path(&export_dir.to_string_lossy()).is_ok());
        assert!(validate_dir_path(&fake_exe.to_string_lossy()).is_err());
        assert!(validate_dir_path("/select,C:\\Windows").is_err());
        assert!(validate_dir_path("C:\\Temp\0evil").is_err());
        assert!(validate_dir_path(r"\\attacker\share").is_err());
        assert!(validate_dir_path(r"\\?\UNC\attacker\share").is_err());
        assert!(validate_dir_path(r"C:\Temp\..\Windows").is_err());

        // save_json_file validator accepts external sibling .json/.JSON and rejects state_dir + subdirs + bad paths
        let ok_json = export_dir.join("backup.JSON");
        assert!(validate_json_save_path(&ok_json.to_string_lossy(), &state_dir).is_ok());
        assert!(validate_json_save_path(&fake_exe.to_string_lossy(), &state_dir).is_err());
        assert!(validate_json_save_path(&export_dir.join("run.bat").to_string_lossy(), &state_dir).is_err());
        assert!(validate_json_save_path("C:\\Temp\\bad\0.json", &state_dir).is_err());
        assert!(validate_json_save_path("/weird.json", &state_dir).is_err());
        assert!(validate_json_save_path(r"\\attacker\share\leak.json", &state_dir).is_err());
        assert!(validate_json_save_path(r"C:\Temp\..\leak.json", &state_dir).is_err());
        assert!(validate_json_save_path(r"C:\Temp\leak.json:evil_stream", &state_dir).is_err());

        // Must refuse overwriting files inside state_dir or any subdirectory (case-insensitive & verbatim)
        assert!(validate_json_save_path(&state_dir.join("config.json").to_string_lossy(), &state_dir).is_err());
        assert!(validate_json_save_path(&state_dir.join("accounts.json").to_string_lossy(), &state_dir).is_err());
        assert!(validate_json_save_path(&state_dir.join("ipc-session.json").to_string_lossy(), &state_dir).is_err());
        assert!(validate_json_save_path(&state_dir.join("sub").join("nested.json").to_string_lossy(), &state_dir).is_err());
        let upper_inside = state_dir
            .join("CONFIG.JSON")
            .to_string_lossy()
            .to_ascii_uppercase();
        assert!(validate_json_save_path(&upper_inside, &state_dir).is_err());

        // Atomic JSON save roundtrip outside state_dir succeeds; inside state_dir fails
        let out_file = export_dir.join("accounts-export.json");
        save_json_file_checked(
            &out_file.to_string_lossy(),
            serde_json::json!({ "version": 1, "accounts": [] }),
            &state_dir,
        )
        .unwrap();
        let saved = std::fs::read_to_string(&out_file).unwrap();
        assert!(saved.contains("\"version\": 1"));

        assert!(save_json_file_checked(
            &state_dir.join("config.json").to_string_lossy(),
            serde_json::json!({ "pwn": true }),
            &state_dir,
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&root_tmp);
    }
}
