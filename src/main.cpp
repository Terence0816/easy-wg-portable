#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <winsvc.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "resource.h"
#include "version.h"
#include "embedded_scripts.h"
#include "easywg_request_protocol.hpp"
#include "x25519_fallback.hpp"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

namespace
{
constexpr wchar_t kAppName[] = L"EasyWG Portable";
constexpr wchar_t kTunnelDownloadUrl[] =
    L"https://github.com/Terence0816/easy-wg-portable/releases/download/core-v1/tunnel.dll";
constexpr wchar_t kWireGuardFallbackDownloadUrl[] =
    L"https://github.com/Terence0816/easy-wg-portable/releases/download/core-v1/wireguard.dll";

constexpr wchar_t kLegacyTunnelWin7DownloadUrl[] =
    L"https://github.com/Terence0816/easy-wg-portable/releases/download/core-v1/tunnel-win7.dll";
constexpr wchar_t kWintunDownloadUrl[] =
    L"https://www.wintun.net/builds/wintun-0.13.zip";
constexpr wchar_t kProjectUrl[] = L"https://github.com/Terence0816/easy-wg-portable";
constexpr wchar_t kAppVersion[] = EASYWG_VERSION_STRING_W;
constexpr wchar_t kWindowClass[] = L"EasyWGPortableWindow";
constexpr wchar_t kOptionsClass[] = L"EasyWGPortableOptionsWindow";
constexpr wchar_t kBootstrapClass[] = L"EasyWGPortableBootstrapWindow";
constexpr wchar_t kAboutClass[] = L"EasyWGPortableAboutWindow";
constexpr wchar_t kRequestClass[] = L"EasyWGPortableRequestWindow";
constexpr wchar_t kTemporaryConfigDisplay[] = L"(臨時連接)";
constexpr wchar_t kRunValueName[] = L"EasyWG Portable";
constexpr wchar_t kSingleInstanceName[] = L"Local\\EasyWGPortableMainInstance";
constexpr UINT_PTR kStatusTimerId = 1;
constexpr UINT WM_TRAYICON = WM_APP + 1;
constexpr UINT WM_UPDATE_DONE = WM_APP + 2;
constexpr UINT WM_AUTO_CONNECT = WM_APP + 3;
constexpr UINT WM_REQUEST_DONE = WM_APP + 4;

enum ControlId : int
{
    IDC_CONFIG = 1001,
    IDC_BROWSE = 1002,
    IDC_CONNECT = 1003,
    IDC_DISCONNECT = 1004,
    IDC_STATUS = 1005,
    IDC_LOG = 1006,
    IDC_HEADER = 1007,
    IDC_CONFIG_LABEL = 1008,
    IDC_INFO_LABEL = 1009,
    IDC_INFO = 1010,
    IDC_LOG_LABEL = 1011,
    IDC_EDIT_CONFIG = 1012,

    IDC_OPT_AUTOSTART = 1101,
    IDC_OPT_STAYTRAY = 1102,
    IDC_OPT_LANGUAGE = 1103,
    IDC_OPT_UPDATE = 1104,
    IDC_OPT_SAVE = 1105,
    IDC_OPT_CANCEL = 1106,
    IDC_OPT_LANGUAGE_LABEL = 1107,
    IDC_OPT_HINT = 1108,
    IDC_OPT_AUTOCONNECT = 1109,
    IDC_ABOUT_GITHUB = 1201,
    IDC_ABOUT_CLOSE = 1202,

    IDC_REQ_SERVER = 1301,
    IDC_REQ_NAME = 1310,
    IDC_REQ_PORT = 1302,
    IDC_REQ_PASSWORD = 1303,
    IDC_REQ_FULL_TUNNEL = 1304,
    IDC_REQ_TEMPORARY = 1305,
    IDC_REQ_SUBMIT = 1306,
    IDC_REQ_CANCEL = 1307,
    IDC_REQ_STATUS = 1308,
    IDC_REQ_DOWNLOAD = 1309
};

enum MenuId : int
{
    IDM_OPTIONS = 2001,
    IDM_QUICK_REQUEST = 2002,
    IDM_ABOUT = 2003,
    IDM_TRAY_SHOW = 2101,
    IDM_TRAY_EXIT = 2102
};

enum class Language
{
    ZhTW,
    English
};

struct Settings
{
    bool autostart = false;
    bool stayTray = true;
    bool autoConnect = false;
    Language language = Language::ZhTW;
    std::wstring lastConfig;
    std::wstring requestServer;
    int requestPort = 51820;
    std::wstring requestName = L"New Device";
};

struct ConfigInfo
{
    std::wstring address;
    std::wstring dns;
    std::wstring endpoint;
    std::wstring allowedIps;
};

HWND g_mainWindow = nullptr;
HWND g_optionsWindow = nullptr;
HWND g_aboutWindow = nullptr;
HWND g_requestWindow = nullptr;
HWND g_headerLabel = nullptr;
HWND g_configLabel = nullptr;
HWND g_configEdit = nullptr;
HWND g_browseButton = nullptr;
HWND g_editConfigButton = nullptr;
HWND g_connectButton = nullptr;
HWND g_disconnectButton = nullptr;
HWND g_statusLabel = nullptr;
HWND g_infoLabel = nullptr;
HWND g_infoEdit = nullptr;
HWND g_logLabel = nullptr;
HWND g_logEdit = nullptr;

HWND g_reqName = nullptr;
HWND g_reqServer = nullptr;
HWND g_reqPort = nullptr;
HWND g_reqPassword = nullptr;
HWND g_reqFullTunnel = nullptr;
HWND g_reqTemporary = nullptr;
HWND g_reqSubmit = nullptr;
HWND g_reqCancel = nullptr;
HWND g_reqStatus = nullptr;
HWND g_reqDownload = nullptr;

HWND g_optAutostart = nullptr;
HWND g_optStayTray = nullptr;
HWND g_optAutoConnect = nullptr;
HWND g_optLanguage = nullptr;
HWND g_optUpdate = nullptr;
HWND g_optSave = nullptr;
HWND g_optCancel = nullptr;
HWND g_optLanguageLabel = nullptr;
HWND g_optHint = nullptr;

HINSTANCE g_instance = nullptr;
HICON g_appIcon = nullptr;
HMENU g_mainMenu = nullptr;
HANDLE g_singleInstance = nullptr;

Settings g_settings;
std::wstring g_initialConfig;
std::wstring g_activeServiceName;
std::wstring g_activeConfigPath;
std::wstring g_temporaryConfigPath;
std::atomic_bool g_closing{ false };
std::atomic_bool g_forceExit{ false };
std::atomic_bool g_updateRunning{ false };
std::mutex g_updateMutex;
std::wstring g_updateResult;
std::atomic_bool g_requestRunning{ false };
std::mutex g_requestMutex;
struct QuickRequestCompletion
{
    bool ok = false;
    bool temporary = false;
    std::wstring error;
    std::wstring configText;
    std::wstring suggestedFileName;
    std::wstring requestHost;
};
QuickRequestCompletion g_requestCompletion;
SYSTEMTIME g_connectedLocalTime{};
std::chrono::steady_clock::time_point g_connectedAt{};
bool g_hasConnectedTime = false;
bool g_autoConnectDisabledMissing = false;
std::wstring g_missingAutoConnectConfig;
DWORD g_lastServiceState = SERVICE_STOPPED;

COLORREF g_backgroundColor = RGB(244, 247, 250);
COLORREF g_cardColor = RGB(255, 255, 255);
COLORREF g_borderColor = RGB(218, 224, 231);
COLORREF g_textColor = RGB(35, 43, 54);
COLORREF g_mutedTextColor = RGB(92, 103, 116);
COLORREF g_statusOnlineColor = RGB(25, 135, 84);
COLORREF g_statusPendingColor = RGB(196, 118, 0);
COLORREF g_statusOfflineColor = RGB(80, 89, 100);

std::wstring FormatWin32Error(DWORD error);
std::wstring Trim(const std::wstring& value);
bool DownloadOfficialWireGuardNtComponent(HWND bootstrap, const std::wstring& appDir, std::wstring& error);
HFONT CreateUiFont(int pointSize = 9, bool bold = false);
void ApplyFont(HWND control, HFONT font);
void ShowMainWindow();
void ShowQuickRequest();

const wchar_t* Tr(const wchar_t* zh, const wchar_t* en)
{
    return g_settings.language == Language::ZhTW ? zh : en;
}

void SecureClearWideString(std::wstring& value)
{
    if (!value.empty())
        SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    value.clear();
}

std::wstring GetModulePath()
{
    std::vector<wchar_t> buffer(32768);
    const DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (len == 0 || len >= buffer.size())
        return {};
    return std::wstring(buffer.data(), len);
}

std::wstring GetModuleDirectory()
{
    const std::wstring module = GetModulePath();
    if (module.empty())
        return {};
    return fs::path(module).parent_path().wstring();
}

std::wstring GetIniPath()
{
    return (fs::path(GetModuleDirectory()) / L"EasyWG.ini").wstring();
}

bool FileExists(const std::wstring& path)
{
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}


bool FileExistsNonEmpty(const std::wstring& path)
{
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
        return false;

    if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return false;

    ULARGE_INTEGER size{};
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return size.QuadPart > 0;
}

void PumpBootstrapMessages()
{
    MSG msg{};
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}


LRESULT CALLBACK BootstrapWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_ERASEBKGND:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        RECT rect{};
        GetClientRect(hwnd, &rect);
        FillRect(dc, &rect, GetSysColorBrush(COLOR_BTNFACE));
        return 1;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
        SetBkColor(dc, GetSysColor(COLOR_BTNFACE));
        SetBkMode(dc, OPAQUE);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE));
    }

    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

HWND CreateBootstrapWindow()
{
    const int width = 430;
    const int height = 150;
    const int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    const int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    const int x = (screenWidth - width) / 2;
    const int y = (screenHeight - height) / 2;

    HWND window = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        kBootstrapClass,
        kAppName,
        WS_POPUP | WS_CAPTION,
        x, y, width, height,
        nullptr, nullptr, g_instance, nullptr);

    if (!window)
        return nullptr;

    HWND label = CreateWindowExW(
        0,
        L"STATIC",
        Tr(L"正在下載必要元件，請稍候…",
           L"Downloading required components, please wait..."),
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        24, 38, width - 48, 46,
        window,
        nullptr,
        g_instance,
        nullptr);

    if (label)
    {
        HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    PumpBootstrapMessages();
    return window;
}

void SetBootstrapText(HWND bootstrap, const std::wstring& text)
{
    if (!bootstrap)
        return;

    HWND label = FindWindowExW(bootstrap, nullptr, L"STATIC", nullptr);
    if (label)
        SetWindowTextW(label, text.c_str());

    UpdateWindow(bootstrap);
    PumpBootstrapMessages();
}

std::wstring GetTunnelDownloadUrl()
{
    wchar_t buffer[4096]{};
    GetPrivateProfileStringW(
        L"Bootstrap",
        L"TunnelUrl",
        kTunnelDownloadUrl,
        buffer,
        static_cast<DWORD>(std::size(buffer)),
        GetIniPath().c_str());

    std::wstring url = Trim(buffer);
    if (url.empty())
        url = kTunnelDownloadUrl;

    return url;
}

bool DownloadUrlToFile(
    const std::wstring& url,
    const std::wstring& targetPath,
    std::wstring& error)
{
    URL_COMPONENTSW parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts))
    {
        error = Tr(L"下載網址無效：", L"Invalid download URL: ") +
            FormatWin32Error(GetLastError());
        return false;
    }

    const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);

    std::wstring path;
    if (parts.lpszUrlPath && parts.dwUrlPathLength > 0)
        path.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (parts.lpszExtraInfo && parts.dwExtraInfoLength > 0)
        path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    if (path.empty())
        path = L"/";

    const std::wstring userAgent =
        std::wstring(L"EasyWG Portable/") + kAppVersion;

    HINTERNET session = WinHttpOpen(
        userAgent.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!session)
    {
        error = Tr(L"無法初始化網路下載：", L"Unable to initialize network download: ") +
            FormatWin32Error(GetLastError());
        return false;
    }

    WinHttpSetTimeouts(session, 15000, 15000, 30000, 60000);

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
    DWORD secureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(
        session,
        WINHTTP_OPTION_SECURE_PROTOCOLS,
        &secureProtocols,
        sizeof(secureProtocols));

    HINTERNET connection = WinHttpConnect(
        session,
        host.c_str(),
        parts.nPort,
        0);

    if (!connection)
    {
        const DWORD e = GetLastError();
        WinHttpCloseHandle(session);
        error = Tr(L"無法連線下載伺服器：", L"Unable to connect to the download server: ") +
            FormatWin32Error(e);
        return false;
    }

    const DWORD flags =
        parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET request = WinHttpOpenRequest(
        connection,
        L"GET",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!request)
    {
        const DWORD e = GetLastError();
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        error = Tr(L"無法建立下載要求：", L"Unable to create the download request: ") +
            FormatWin32Error(e);
        return false;
    }

    // GitHub Release asset links redirect to an object-storage host.
    // WinHTTP follows standard redirects by default.
    const BOOL sent = WinHttpSendRequest(
        request,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    if (!sent || !WinHttpReceiveResponse(request, nullptr))
    {
        const DWORD e = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        error = Tr(L"下載要求失敗：", L"Download request failed: ") +
            FormatWin32Error(e);
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusSize,
            WINHTTP_NO_HEADER_INDEX))
    {
        statusCode = 0;
    }

    if (statusCode < 200 || statusCode >= 300)
    {
        std::wstringstream ss;
        ss << Tr(L"下載伺服器回傳 HTTP ", L"Download server returned HTTP ")
           << statusCode << L".";
        error = ss.str();

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    const std::wstring tempPath =
        targetPath + L".easywg.download." + std::to_wstring(GetCurrentProcessId());

    HANDLE file = CreateFileW(
        tempPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
    {
        const DWORD e = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        error = Tr(L"無法建立下載檔案：", L"Unable to create the downloaded file: ") +
            FormatWin32Error(e);
        return false;
    }

    bool ok = true;
    std::vector<unsigned char> buffer(64 * 1024);

    while (true)
    {
        DWORD bytesRead = 0;
        if (!WinHttpReadData(
                request,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesRead))
        {
            error = Tr(L"讀取下載資料失敗：", L"Failed to read downloaded data: ") +
                FormatWin32Error(GetLastError());
            ok = false;
            break;
        }

        if (bytesRead == 0)
            break;

        DWORD totalWritten = 0;
        while (totalWritten < bytesRead)
        {
            DWORD written = 0;
            if (!WriteFile(
                    file,
                    buffer.data() + totalWritten,
                    bytesRead - totalWritten,
                    &written,
                    nullptr) ||
                written == 0)
            {
                error = Tr(L"寫入下載檔案失敗：", L"Failed to write the downloaded file: ") +
                    FormatWin32Error(GetLastError());
                ok = false;
                break;
            }
            totalWritten += written;
        }

        if (!ok)
            break;

        PumpBootstrapMessages();
    }

    if (ok)
        FlushFileBuffers(file);

    CloseHandle(file);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    if (!ok)
    {
        DeleteFileW(tempPath.c_str());
        return false;
    }

    if (!FileExistsNonEmpty(tempPath))
    {
        DeleteFileW(tempPath.c_str());
        error = Tr(
            L"下載完成，但檔案內容為空。",
            L"The download completed, but the file is empty.");
        return false;
    }

    if (!MoveFileExW(
            tempPath.c_str(),
            targetPath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        const DWORD e = GetLastError();
        DeleteFileW(tempPath.c_str());
        error = Tr(L"安裝下載元件失敗：", L"Failed to install the downloaded component: ") +
            FormatWin32Error(e);
        return false;
    }

    return FileExistsNonEmpty(targetPath);
}


bool IsWindows7OrEarlier();

bool DownloadOfficialWintunComponent(
    HWND bootstrap,
    const std::wstring& appDir,
    std::wstring& error);

bool EnsureCoreComponentsAtStartup(std::wstring& error)
{
    const std::wstring appDir = GetModuleDirectory();
    if (appDir.empty())
    {
        error = Tr(
            L"無法取得 EasyWG.exe 所在目錄。",
            L"Unable to determine the EasyWG.exe directory.");
        return false;
    }

    const bool legacyWin7 = IsWindows7OrEarlier();

    const std::wstring tunnelPath =
        (fs::path(appDir) / L"tunnel.dll").wstring();
    const std::wstring legacyTunnelPath =
        (fs::path(appDir) / L"tunnel-win7.dll").wstring();
    const std::wstring wireguardPath =
        (fs::path(appDir) / L"wireguard.dll").wstring();
    const std::wstring wintunPath =
        (fs::path(appDir) / L"wintun.dll").wstring();

    const std::wstring legacyNtVersionFile =
        (fs::path(appDir) / L"wireguard-nt-version.txt").wstring();
    DeleteFileW(legacyNtVersionFile.c_str());

    HWND bootstrap = nullptr;
    bool ok = true;

    if (legacyWin7)
    {
        const bool missingLegacyTunnel = !FileExistsNonEmpty(legacyTunnelPath);
        const bool missingWintun = !FileExistsNonEmpty(wintunPath);

        if (!missingLegacyTunnel && !missingWintun)
            return true;

        bootstrap = CreateBootstrapWindow();

        if (missingLegacyTunnel)
        {
            SetBootstrapText(
                bootstrap,
                Tr(L"正在下載 Windows 7 相容 tunnel 元件，請稍候…",
                   L"Downloading the Windows 7 compatible tunnel component, please wait..."));

            ok = DownloadUrlToFile(
                kLegacyTunnelWin7DownloadUrl,
                legacyTunnelPath,
                error);

            if (!ok)
            {
                error += L"\r\n\r\n";
                error += Tr(
                    L"請確認 GitHub core-v1 Release 已上傳 tunnel-win7.dll。",
                    L"Make sure tunnel-win7.dll has been uploaded to the GitHub core-v1 release.");
            }
        }

        if (ok && missingWintun)
            ok = DownloadOfficialWintunComponent(bootstrap, appDir, error);
    }
    else
    {
        const bool missingTunnel = !FileExistsNonEmpty(tunnelPath);
        const bool missingWireGuard = !FileExistsNonEmpty(wireguardPath);

        if (!missingTunnel && !missingWireGuard)
            return true;

        bootstrap = CreateBootstrapWindow();

        if (missingTunnel)
        {
            SetBootstrapText(
                bootstrap,
                Tr(L"正在從 EasyWG GitHub 下載 tunnel.dll，請稍候…",
                   L"Downloading tunnel.dll from EasyWG GitHub, please wait..."));

            const std::wstring tunnelUrl = GetTunnelDownloadUrl();
            ok = DownloadUrlToFile(tunnelUrl, tunnelPath, error);

            if (!ok)
            {
                error += L"\r\n\r\n";
                error += Tr(L"下載來源：", L"Download source: ");
                error += tunnelUrl;
            }
        }

        if (ok && missingWireGuard)
        {
            SetBootstrapText(
                bootstrap,
                Tr(L"正在從 WireGuard 官方下載 wireguard.dll，請稍候…",
                   L"Downloading wireguard.dll from the official WireGuard source, please wait..."));

            ok = DownloadOfficialWireGuardNtComponent(
                bootstrap,
                appDir,
                error);
        }
    }

    if (bootstrap)
    {
        if (ok)
        {
            SetBootstrapText(
                bootstrap,
                Tr(L"必要元件下載完成。",
                   L"Required components downloaded successfully."));
            Sleep(300);
        }

        DestroyWindow(bootstrap);
        PumpBootstrapMessages();
    }

    if (!ok)
        return false;

    if (legacyWin7)
    {
        return FileExistsNonEmpty(legacyTunnelPath) &&
               FileExistsNonEmpty(wintunPath);
    }

    return FileExistsNonEmpty(tunnelPath) &&
           FileExistsNonEmpty(wireguardPath);
}

std::wstring FormatWin32Error(DWORD error)
{
    if (error == ERROR_SUCCESS)
        return Tr(L"成功", L"Success");

    wchar_t* message = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD len = FormatMessageW(
        flags, nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<wchar_t*>(&message), 0, nullptr);

    std::wstring result = len && message ? std::wstring(message, len) : Tr(L"未知錯誤", L"Unknown error");
    if (message)
        LocalFree(message);

    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' '))
        result.pop_back();

    std::wstringstream ss;
    ss << result << L" (" << Tr(L"錯誤碼", L"error") << L" " << error << L")";
    return ss.str();
}

std::wstring GetControlText(HWND control)
{
    if (!control)
        return {};

    const int len = GetWindowTextLengthW(control);
    if (len <= 0)
        return {};

    std::wstring value(static_cast<size_t>(len) + 1, L'\0');
    const int written = GetWindowTextW(control, value.data(), len + 1);
    if (written <= 0)
        return {};

    value.resize(static_cast<size_t>(written));
    return value;
}

std::wstring ToLower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

std::wstring Trim(const std::wstring& value)
{
    const auto first = std::find_if_not(value.begin(), value.end(),
        [](wchar_t c) { return std::iswspace(c) != 0; });
    if (first == value.end())
        return {};

    const auto last = std::find_if_not(value.rbegin(), value.rend(),
        [](wchar_t c) { return std::iswspace(c) != 0; }).base();

    return std::wstring(first, last);
}


bool IsWindows7OrEarlier()
{
    using RtlGetVersionProc = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

    auto rtlGetVersion = reinterpret_cast<RtlGetVersionProc>(
        GetProcAddress(ntdll, "RtlGetVersion"));

    if (!rtlGetVersion)
        return false;

    RTL_OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);

    if (rtlGetVersion(&version) != 0)
        return false;

    return version.dwMajorVersion < 6 ||
           (version.dwMajorVersion == 6 && version.dwMinorVersion <= 1);
}

std::wstring FullPath(const std::wstring& input)
{
    if (input.empty())
        return {};

    DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (needed == 0)
        return input;

    std::wstring output(needed, L'\0');
    DWORD written = GetFullPathNameW(input.c_str(), needed, output.data(), nullptr);
    if (written == 0 || written >= needed)
        return input;

    output.resize(written);
    return output;
}


std::wstring ResolveConfigPath(const std::wstring& value)
{
    const std::wstring trimmed = Trim(value);
    if (trimmed.empty())
        return {};

    if (_wcsicmp(trimmed.c_str(), kTemporaryConfigDisplay) == 0 &&
        !g_temporaryConfigPath.empty())
        return FullPath(g_temporaryConfigPath);

    const fs::path input(trimmed);
    if (input.is_absolute())
        return FullPath(trimmed);

    return FullPath((fs::path(GetModuleDirectory()) / input).wstring());
}

bool IsTemporaryConfigPath(const std::wstring& path)
{
    return !g_temporaryConfigPath.empty() &&
           _wcsicmp(FullPath(path).c_str(), FullPath(g_temporaryConfigPath).c_str()) == 0;
}

bool IsTemporarySelection()
{
    return g_configEdit &&
           _wcsicmp(Trim(GetControlText(g_configEdit)).c_str(), kTemporaryConfigDisplay) == 0;
}

bool IsPathInModuleDirectory(const std::wstring& path)
{
    const std::wstring full = FullPath(path);
    if (full.empty())
        return false;

    const std::wstring parent = FullPath(fs::path(full).parent_path().wstring());
    const std::wstring moduleDir = FullPath(GetModuleDirectory());

    return !parent.empty() &&
           !moduleDir.empty() &&
           _wcsicmp(parent.c_str(), moduleDir.c_str()) == 0;
}

std::wstring ConfigPathForDisplay(const std::wstring& path)
{
    const std::wstring full = ResolveConfigPath(path);
    if (full.empty())
        return {};

    if (IsPathInModuleDirectory(full))
        return fs::path(full).filename().wstring();

    return full;
}

std::wstring ConfigPathForStorage(const std::wstring& path)
{
    // Storing only the filename for configs next to EasyWG.exe makes a
    // packaged folder portable when moved to another PC or directory.
    return ConfigPathForDisplay(path);
}

bool IsUsableConfPath(const std::wstring& path)
{
    const std::wstring full = ResolveConfigPath(path);
    return !full.empty() &&
           FileExists(full) &&
           ToLower(fs::path(full).extension().wstring()) == L".conf";
}

std::wstring QuoteArg(const std::wstring& value)
{
    return L"\"" + value + L"\"";
}

std::wstring Utf8ToWide(const std::string& text)
{
    if (text.empty())
        return {};

    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0);
    if (needed > 0)
    {
        std::wstring result(static_cast<size_t>(needed), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), result.data(), needed);
        return result;
    }

    const int acpNeeded = MultiByteToWideChar(CP_ACP, 0, text.data(),
        static_cast<int>(text.size()), nullptr, 0);
    if (acpNeeded <= 0)
        return {};

    std::wstring result(static_cast<size_t>(acpNeeded), L'\0');
    MultiByteToWideChar(CP_ACP, 0, text.data(),
        static_cast<int>(text.size()), result.data(), acpNeeded);
    return result;
}

std::string ReadFileBytes(const std::wstring& path)
{
    std::ifstream file(fs::path(path), std::ios::binary);
    if (!file)
        return {};
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

std::wstring ReadTextFile(const std::wstring& path)
{
    std::string bytes = ReadFileBytes(path);
    if (bytes.empty())
        return {};

    if (bytes.size() >= 3 &&
        static_cast<unsigned char>(bytes[0]) == 0xEF &&
        static_cast<unsigned char>(bytes[1]) == 0xBB &&
        static_cast<unsigned char>(bytes[2]) == 0xBF)
    {
        bytes.erase(0, 3);
    }

    return Utf8ToWide(bytes);
}

std::wstring ReadFirstLine(const std::wstring& path)
{
    std::wstring text = ReadTextFile(path);
    if (text.empty())
        return {};

    const size_t pos = text.find_first_of(L"\r\n");
    if (pos != std::wstring::npos)
        text.resize(pos);
    return Trim(text);
}

void AppendLog(const std::wstring& text)
{
    if (!g_logEdit)
        return;

    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t prefix[64]{};
    swprintf_s(prefix, L"[%02u:%02u:%02u] ", st.wHour, st.wMinute, st.wSecond);

    std::wstring line = prefix + text + L"\r\n";
    const int length = GetWindowTextLengthW(g_logEdit);
    SendMessageW(g_logEdit, EM_SETSEL, length, length);
    SendMessageW(g_logEdit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
    SendMessageW(g_logEdit, EM_SCROLLCARET, 0, 0);
}

void LoadSettings()
{
    const std::wstring ini = GetIniPath();

    g_settings.autostart = GetPrivateProfileIntW(L"General", L"AutoStart", 0, ini.c_str()) != 0;
    g_settings.stayTray = GetPrivateProfileIntW(L"General", L"StayTray", 1, ini.c_str()) != 0;
    g_settings.autoConnect = GetPrivateProfileIntW(L"General", L"AutoConnect", 0, ini.c_str()) != 0;

    wchar_t language[32]{};
    GetPrivateProfileStringW(L"General", L"Language", L"zh-TW", language,
        static_cast<DWORD>(std::size(language)), ini.c_str());
    g_settings.language = _wcsicmp(language, L"en") == 0 ? Language::English : Language::ZhTW;

    wchar_t config[32768]{};
    GetPrivateProfileStringW(L"General", L"LastConfig", L"", config,
        static_cast<DWORD>(std::size(config)), ini.c_str());
    g_settings.lastConfig = config;

    wchar_t requestServer[512]{};
    GetPrivateProfileStringW(L"QuickRequest", L"Server", L"", requestServer,
        static_cast<DWORD>(std::size(requestServer)), ini.c_str());
    g_settings.requestServer = requestServer;
    g_settings.requestPort = GetPrivateProfileIntW(L"QuickRequest", L"Port", 51820, ini.c_str());
    if (g_settings.requestPort < 1 || g_settings.requestPort > 65535)
        g_settings.requestPort = 51820;
    wchar_t requestName[256]{};
    GetPrivateProfileStringW(L"QuickRequest", L"Name", L"New Device", requestName,
        static_cast<DWORD>(std::size(requestName)), ini.c_str());
    g_settings.requestName = Trim(requestName);
    if (g_settings.requestName.empty()) g_settings.requestName = L"New Device";

    if (g_settings.autostart)
        g_settings.stayTray = true;
}

bool SaveSettings()
{
    const std::wstring ini = GetIniPath();

    const bool ok1 = WritePrivateProfileStringW(
        L"General", L"AutoStart", g_settings.autostart ? L"1" : L"0", ini.c_str()) != FALSE;
    const bool ok2 = WritePrivateProfileStringW(
        L"General", L"StayTray", g_settings.stayTray ? L"1" : L"0", ini.c_str()) != FALSE;
    const bool ok3 = WritePrivateProfileStringW(
        L"General", L"Language",
        g_settings.language == Language::English ? L"en" : L"zh-TW", ini.c_str()) != FALSE;
    const bool ok4 = WritePrivateProfileStringW(
        L"General", L"LastConfig", g_settings.lastConfig.c_str(), ini.c_str()) != FALSE;
    const bool ok5 = WritePrivateProfileStringW(
        L"General", L"AutoConnect", g_settings.autoConnect ? L"1" : L"0", ini.c_str()) != FALSE;
    const bool ok6 = WritePrivateProfileStringW(
        L"QuickRequest", L"Server", g_settings.requestServer.c_str(), ini.c_str()) != FALSE;
    const bool ok7 = WritePrivateProfileStringW(
        L"QuickRequest", L"Port", std::to_wstring(g_settings.requestPort).c_str(), ini.c_str()) != FALSE;
    const bool ok8 = WritePrivateProfileStringW(
        L"QuickRequest", L"Name", g_settings.requestName.c_str(), ini.c_str()) != FALSE;

    return ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8;
}

bool SetAutostartRegistry(bool enabled, std::wstring& error)
{
    HKEY key = nullptr;
    const LONG openResult = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr);

    if (openResult != ERROR_SUCCESS)
    {
        error = Tr(L"無法開啟開機啟動登錄位置：", L"Unable to open startup registry key: ");
        error += FormatWin32Error(static_cast<DWORD>(openResult));
        return false;
    }

    LONG result = ERROR_SUCCESS;
    if (enabled)
    {
        const std::wstring command = QuoteArg(GetModulePath()) + L" /autostart";
        result = RegSetValueExW(
            key, kRunValueName, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(command.c_str()),
            static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    }
    else
    {
        result = RegDeleteValueW(key, kRunValueName);
        if (result == ERROR_FILE_NOT_FOUND)
            result = ERROR_SUCCESS;
    }

    RegCloseKey(key);

    if (result != ERROR_SUCCESS)
    {
        error = Tr(L"更新開機啟動設定失敗：", L"Failed to update startup setting: ");
        error += FormatWin32Error(static_cast<DWORD>(result));
        return false;
    }

    return true;
}

ConfigInfo ParseConfigInfo(const std::wstring& configPath)
{
    ConfigInfo info;
    const std::wstring text = ReadTextFile(configPath);
    if (text.empty())
        return info;

    std::wistringstream input(text);
    std::wstring line;
    std::wstring section;

    while (std::getline(input, line))
    {
        line = Trim(line);
        if (line.empty() || line[0] == L'#' || line[0] == L';')
            continue;

        if (line.front() == L'[' && line.back() == L']')
        {
            section = ToLower(Trim(line.substr(1, line.size() - 2)));
            continue;
        }

        const size_t equals = line.find(L'=');
        if (equals == std::wstring::npos)
            continue;

        const std::wstring key = ToLower(Trim(line.substr(0, equals)));
        const std::wstring value = Trim(line.substr(equals + 1));

        if (section == L"interface")
        {
            if (key == L"address" && info.address.empty())
                info.address = value;
            else if (key == L"dns" && info.dns.empty())
                info.dns = value;
        }
        else if (section == L"peer")
        {
            if (key == L"endpoint" && info.endpoint.empty())
                info.endpoint = value;
            else if (key == L"allowedips" && info.allowedIps.empty())
                info.allowedIps = value;
        }
    }

    return info;
}

std::wstring TunnelNameFromConfig(const std::wstring& configPath)
{
    return fs::path(configPath).stem().wstring();
}

bool ValidateConfigPath(const std::wstring& configPath, std::wstring& error)
{
    if (configPath.empty())
    {
        error = Tr(L"請先選擇 .conf 設定檔。", L"Please select a .conf configuration file.");
        return false;
    }

    if (!FileExists(configPath))
    {
        error = Tr(L"找不到設定檔：", L"Configuration file not found: ") + configPath;
        return false;
    }

    const std::wstring ext = ToLower(fs::path(configPath).extension().wstring());
    if (ext != L".conf")
    {
        error = Tr(L"請選擇標準 WireGuard .conf 設定檔。", L"Please select a standard WireGuard .conf file.");
        return false;
    }

    const std::wstring name = TunnelNameFromConfig(configPath);
    if (name.empty())
    {
        error = Tr(L"設定檔名稱無效。", L"Invalid configuration file name.");
        return false;
    }

    if (name.size() > 32)
    {
        error = Tr(L"設定檔主檔名請控制在 32 個字元內。", L"Keep the configuration base name within 32 characters.");
        return false;
    }

    for (wchar_t c : name)
    {
        const bool asciiAlpha =
            (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
        const bool asciiDigit = c >= L'0' && c <= L'9';

        if (!(asciiAlpha || asciiDigit || c == L'_' || c == L'-' || c == L'.'))
        {
            error = Tr(
                L"設定檔主檔名請只使用英數、底線、減號或點，例如 office.conf。",
                L"Use only letters, numbers, underscore, hyphen, or dot in the base name, for example office.conf.");
            return false;
        }
    }

    return true;
}

std::wstring GetProgramDataEasyWGDirectory()
{
    wchar_t buffer[MAX_PATH * 4]{};
    const DWORD length = GetEnvironmentVariableW(
        L"ProgramData",
        buffer,
        static_cast<DWORD>(std::size(buffer)));

    if (length == 0 || length >= std::size(buffer))
        return {};

    return (fs::path(buffer) / L"EasyWG").wstring();
}

bool EnsureDirectoryTree(const std::wstring& path)
{
    try
    {
        fs::create_directories(fs::path(path));
        return fs::exists(fs::path(path));
    }
    catch (...)
    {
        return false;
    }
}

bool StageConfigForWindows7Service(
    const std::wstring& sourceConfig,
    std::wstring& stagedConfig,
    std::wstring& error)
{
    const std::wstring baseDir = GetProgramDataEasyWGDirectory();
    if (baseDir.empty())
    {
        error = Tr(
            L"無法取得 ProgramData 路徑。",
            L"Unable to resolve the ProgramData directory.");
        return false;
    }

    const std::wstring runtimeDir =
        (fs::path(baseDir) / L"Runtime").wstring();

    if (!EnsureDirectoryTree(runtimeDir))
    {
        error = Tr(
            L"無法建立 Win7 服務執行目錄：",
            L"Unable to create the Windows 7 service runtime directory: ") +
            runtimeDir;
        return false;
    }

    stagedConfig =
        (fs::path(runtimeDir) / fs::path(sourceConfig).filename()).wstring();

    if (!CopyFileW(
            sourceConfig.c_str(),
            stagedConfig.c_str(),
            FALSE))
    {
        error = Tr(
            L"無法將設定檔複製到 Win7 服務執行目錄：",
            L"Unable to copy the configuration into the Windows 7 service runtime directory: ") +
            FormatWin32Error(GetLastError());
        return false;
    }

    return FileExistsNonEmpty(stagedConfig);
}

void AppendWindows7ServiceDebug(const std::wstring& message)
{
    const std::wstring baseDir = GetProgramDataEasyWGDirectory();
    if (baseDir.empty())
        return;

    EnsureDirectoryTree(baseDir);

    const std::wstring logPath =
        (fs::path(baseDir) / L"win7-service-debug.log").wstring();

    SYSTEMTIME st{};
    GetLocalTime(&st);

    std::wstringstream ss;
    ss << L"["
       << std::setfill(L'0')
       << std::setw(4) << st.wYear << L"-"
       << std::setw(2) << st.wMonth << L"-"
       << std::setw(2) << st.wDay << L" "
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond << L"] "
       << message << L"\r\n";

    const std::wstring line = ss.str();

    HANDLE file = CreateFileW(
        logPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return;

    DWORD written = 0;
    WriteFile(
        file,
        line.data(),
        static_cast<DWORD>(line.size() * sizeof(wchar_t)),
        &written,
        nullptr);

    CloseHandle(file);
}

std::wstring ServiceNameFromConfig(const std::wstring& configPath)
{
    return L"WireGuardTunnel$" + TunnelNameFromConfig(configPath);
}

std::wstring StopEventName(const std::wstring& serviceName)
{
    std::wstring safe;
    safe.reserve(serviceName.size());
    for (wchar_t c : serviceName)
    {
        if ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
            (c >= L'0' && c <= L'9') || c == L'_' || c == L'-')
        {
            safe.push_back(c);
        }
        else
        {
            safe.push_back(L'_');
        }
    }
    return L"Global\\EasyWG_Stop_" + safe;
}

bool QueryServiceStatusByName(const std::wstring& serviceName, DWORD& state, DWORD* win32Exit = nullptr)
{
    state = SERVICE_STOPPED;
    if (win32Exit)
        *win32Exit = ERROR_SUCCESS;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return false;

    SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    const BOOL ok = QueryServiceStatusEx(
        service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded);

    if (ok)
    {
        state = status.dwCurrentState;
        if (win32Exit)
            *win32Exit = status.dwWin32ExitCode;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

bool WaitForServiceState(SC_HANDLE service, DWORD desiredState, DWORD timeoutMs, DWORD& lastState)
{
    const ULONGLONG start = GetTickCount64();
    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;

    while (GetTickCount64() - start < timeoutMs)
    {
        if (!QueryServiceStatusEx(
                service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded))
        {
            return false;
        }

        lastState = status.dwCurrentState;
        if (status.dwCurrentState == desiredState)
            return true;

        if (desiredState == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED)
            return false;

        Sleep(200);
    }

    return false;
}

bool WaitForServiceGone(const std::wstring& serviceName, DWORD timeoutMs)
{
    const ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < timeoutMs)
    {
        DWORD state = SERVICE_STOPPED;
        if (!QueryServiceStatusByName(serviceName, state))
            return true;
        if (state == SERVICE_STOPPED)
            return true;
        Sleep(200);
    }
    return false;
}

bool StopAndDeleteService(const std::wstring& serviceName, bool waitForStop, std::wstring* error)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
    {
        if (error)
            *error = L"OpenSCManager: " + FormatWin32Error(GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        scm, serviceName.c_str(),
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);

    if (!service)
    {
        const DWORD e = GetLastError();
        CloseServiceHandle(scm);

        if (e == ERROR_SERVICE_DOES_NOT_EXIST || e == ERROR_SERVICE_MARKED_FOR_DELETE)
            return true;

        if (error)
            *error = L"OpenService: " + FormatWin32Error(e);
        return false;
    }

    SERVICE_STATUS_PROCESS current{};
    DWORD needed = 0;
    QueryServiceStatusEx(
        service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&current), sizeof(current), &needed);

    if (current.dwCurrentState != SERVICE_STOPPED)
    {
        SERVICE_STATUS status{};
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
        {
            const DWORD e = GetLastError();
            if (e != ERROR_SERVICE_NOT_ACTIVE && e != ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
            {
                if (error)
                    *error = Tr(L"停止服務失敗：", L"Failed to stop service: ") + FormatWin32Error(e);
            }
        }

        if (waitForStop)
        {
            DWORD lastState = current.dwCurrentState;
            WaitForServiceState(service, SERVICE_STOPPED, 15000, lastState);
        }
    }

    bool ok = true;
    if (!DeleteService(service))
    {
        const DWORD e = GetLastError();
        if (e != ERROR_SERVICE_MARKED_FOR_DELETE && e != ERROR_SERVICE_DOES_NOT_EXIST)
        {
            ok = false;
            if (error)
                *error = Tr(L"刪除臨時服務失敗：", L"Failed to delete temporary service: ") + FormatWin32Error(e);
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok;
}

void MarkDeleteThenStopFromWatcher(const std::wstring& serviceName)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return;

    SC_HANDLE service = OpenServiceW(
        scm, serviceName.c_str(),
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);

    if (!service)
    {
        CloseServiceHandle(scm);
        return;
    }

    DeleteService(service);

    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

bool SameExecutable(HANDLE process)
{
    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size))
        return false;

    const std::wstring other(buffer.data(), size);
    const std::wstring current = GetModulePath();
    return !current.empty() && _wcsicmp(other.c_str(), current.c_str()) == 0;
}

void WatchParentAndCleanup(DWORD parentPid, std::wstring serviceName)
{
    if (parentPid == 0)
        return;

    HANDLE parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!parent)
        return;

    if (!SameExecutable(parent))
    {
        CloseHandle(parent);
        return;
    }

    WaitForSingleObject(parent, INFINITE);
    CloseHandle(parent);

    MarkDeleteThenStopFromWatcher(serviceName);
}

void WatchStopEventAndCleanup(std::wstring serviceName)
{
    SECURITY_DESCRIPTOR sd{};
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        return;
    if (!SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE))
        return;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    const std::wstring eventName = StopEventName(serviceName);
    HANDLE eventHandle = CreateEventW(&sa, TRUE, FALSE, eventName.c_str());
    if (!eventHandle)
        return;

    ResetEvent(eventHandle);
    WaitForSingleObject(eventHandle, INFINITE);
    CloseHandle(eventHandle);

    MarkDeleteThenStopFromWatcher(serviceName);
}

bool SignalStopEvent(const std::wstring& serviceName)
{
    const std::wstring name = StopEventName(serviceName);
    HANDLE eventHandle = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
    if (!eventHandle)
        return false;

    const BOOL ok = SetEvent(eventHandle);
    CloseHandle(eventHandle);
    return ok == TRUE;
}

bool CreateAndStartTunnelService(
    const std::wstring& configPath,
    std::wstring& serviceName,
    std::wstring& error)
{
    serviceName = ServiceNameFromConfig(configPath);

    std::wstring serviceConfigPath = configPath;
    if (IsWindows7OrEarlier())
    {
        if (!StageConfigForWindows7Service(
                configPath,
                serviceConfigPath,
                error))
        {
            return false;
        }
    }

    std::wstring cleanupError;
    StopAndDeleteService(serviceName, true, &cleanupError);

    const std::wstring exePath = GetModulePath();
    if (exePath.empty())
    {
        error = Tr(L"無法取得 EasyWG.exe 路徑。", L"Unable to resolve EasyWG.exe path.");
        return false;
    }

    const std::wstring commandLine =
        QuoteArg(exePath) + L" /service " + QuoteArg(serviceConfigPath) + L" " +
        std::to_wstring(GetCurrentProcessId());

    SC_HANDLE scm = OpenSCManagerW(
        nullptr, nullptr,
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);

    if (!scm)
    {
        error = L"OpenSCManager: " + FormatWin32Error(GetLastError());
        return false;
    }

    const wchar_t dependencies[] = L"Nsi\0TcpIp\0";

    const std::wstring displayName =
        std::wstring(kAppName) + L": " + TunnelNameFromConfig(configPath);

    SC_HANDLE service = CreateServiceW(
        scm,
        serviceName.c_str(),
        displayName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        commandLine.c_str(),
        nullptr,
        nullptr,
        dependencies,
        nullptr,
        nullptr);

    if (!service)
    {
        const DWORD e = GetLastError();
        CloseServiceHandle(scm);
        error = Tr(L"建立臨時服務失敗：", L"Failed to create temporary service: ") + FormatWin32Error(e);
        return false;
    }

    SERVICE_SID_INFO sidInfo{};
    sidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo))
    {
        const DWORD e = GetLastError();
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        error = Tr(L"設定 Service SID 失敗：", L"Failed to configure Service SID: ") + FormatWin32Error(e);
        return false;
    }

    std::wstring descriptionText =
        L"Temporary WireGuard tunnel service created by EasyWG Portable.";
    SERVICE_DESCRIPTIONW description{};
    description.lpDescription = descriptionText.data();
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);

    if (!StartServiceW(service, 0, nullptr))
    {
        const DWORD e = GetLastError();
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        error = Tr(L"啟動 Tunnel 服務失敗：", L"Failed to start tunnel service: ") + FormatWin32Error(e);
        return false;
    }

    DWORD lastState = SERVICE_START_PENDING;
    const bool running = WaitForServiceState(service, SERVICE_RUNNING, 20000, lastState);

    if (!running)
    {
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        QueryServiceStatusEx(
            service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed);

        SERVICE_STATUS stopStatus{};
        ControlService(service, SERVICE_CONTROL_STOP, &stopStatus);
        DeleteService(service);

        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        std::wstringstream ss;
        ss << Tr(L"Tunnel 未進入 Running 狀態。最後狀態=", L"Tunnel did not enter Running state. Last state=")
           << lastState
           << Tr(L"，Win32 錯誤碼=", L", Win32 error=") << status.dwWin32ExitCode
           << Tr(L"，服務特定錯誤碼=", L", service-specific error=") << status.dwServiceSpecificExitCode
           << Tr(L"，PID=", L", PID=") << status.dwProcessId
           << L".";
        error = ss.str();

        if (IsWindows7OrEarlier())
        {
            const std::wstring baseDir = GetProgramDataEasyWGDirectory();
            if (!baseDir.empty())
            {
                error += L"\r\n\r\n";
                error += Tr(
                    L"Win7 診斷紀錄：",
                    L"Windows 7 diagnostic log: ");
                error += (fs::path(baseDir) / L"win7-service-debug.log").wstring();
            }
        }

        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool IsProcessElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);

    return ok && elevation.TokenIsElevated != 0;
}

bool RunElevatedHelper(const std::wstring& parameters, DWORD& exitCode, std::wstring& error)
{
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.hwnd = g_mainWindow;
    sei.lpVerb = L"runas";
    const std::wstring exePath = GetModulePath();
    sei.lpFile = exePath.c_str();
    sei.lpParameters = parameters.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei))
    {
        const DWORD e = GetLastError();
        error = (e == ERROR_CANCELLED)
            ? Tr(L"使用者取消系統管理員授權。", L"Administrator authorization was cancelled.")
            : Tr(L"無法啟動系統管理員操作：", L"Unable to start elevated operation: ") + FormatWin32Error(e);
        return false;
    }

    WaitForSingleObject(sei.hProcess, INFINITE);
    exitCode = 1;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);

    if (exitCode != 0)
    {
        std::wstringstream ss;
        ss << Tr(L"系統管理員操作失敗，結束碼：", L"Elevated operation failed, exit code: ") << exitCode;
        error = ss.str();
        return false;
    }

    return true;
}

bool RunProcessHidden(
    const std::wstring& executable,
    const std::wstring& arguments,
    DWORD timeoutMs,
    DWORD& exitCode)
{
    std::wstring command = QuoteArg(executable);
    if (!arguments.empty())
        command += L" " + arguments;

    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(
            nullptr, mutableCommand.data(),
            nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW,
            nullptr, nullptr,
            &si, &pi))
    {
        return false;
    }

    const DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (wait == WAIT_TIMEOUT)
    {
        TerminateProcess(pi.hProcess, 124);
        WaitForSingleObject(pi.hProcess, 5000);
    }

    exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return wait != WAIT_FAILED;
}

std::wstring MakeTempFilePath(const wchar_t* prefix)
{
    wchar_t tempDir[MAX_PATH]{};
    if (!GetTempPathW(static_cast<DWORD>(std::size(tempDir)), tempDir))
        return {};

    wchar_t tempFile[MAX_PATH]{};
    if (!GetTempFileNameW(tempDir, prefix, 0, tempFile))
        return {};

    return tempFile;
}


bool WriteEmbeddedScriptToTemp(
    const char* scriptText,
    const wchar_t* prefix,
    std::wstring& scriptPath,
    std::wstring& error)
{
    const std::wstring tempBase = MakeTempFilePath(prefix);
    if (tempBase.empty())
    {
        error = Tr(L"無法建立暫存腳本檔。", L"Unable to create a temporary script file.");
        return false;
    }

    DeleteFileW(tempBase.c_str());
    scriptPath = tempBase + L".ps1";

    std::ofstream file(fs::path(scriptPath), std::ios::binary | std::ios::trunc);
    if (!file)
    {
        error = Tr(L"無法寫入暫存腳本檔。", L"Unable to write the temporary script file.");
        return false;
    }

    file.write(scriptText, static_cast<std::streamsize>(std::strlen(scriptText)));
    file.close();

    if (!file)
    {
        DeleteFileW(scriptPath.c_str());
        scriptPath.clear();
        error = Tr(L"暫存腳本寫入失敗。", L"Failed to write the temporary script.");
        return false;
    }

    return true;
}

bool DownloadOfficialWireGuardNtComponent(
    HWND bootstrap,
    const std::wstring& appDir,
    std::wstring& error)
{
    const std::wstring wireguardPath =
        (fs::path(appDir) / L"wireguard.dll").wstring();

    std::wstring script;
    if (!WriteEmbeddedScriptToTemp(
            EmbeddedScripts::kBootstrapWireGuardNtScript,
            L"EWN",
            script,
            error))
    {
        return false;
    }

    const std::wstring resultFile = MakeTempFilePath(L"EWO");
    if (resultFile.empty())
    {
        DeleteFileW(script.c_str());
        error = Tr(
            L"無法建立 WireGuardNT 下載結果檔。",
            L"Unable to create the WireGuardNT download result file.");
        return false;
    }

    SetBootstrapText(
        bootstrap,
        Tr(L"正在取得 WireGuardNT 官方最新版，請稍候…",
           L"Resolving the latest official WireGuardNT version, please wait..."));

    const std::wstring args =
        L"-NoProfile -ExecutionPolicy Bypass -File " + QuoteArg(script) +
        L" -OutputDir " + QuoteArg(appDir) +
        L" -ResultFile " + QuoteArg(resultFile);

    DWORD exitCode = 1;
    const bool ran = RunProcessHidden(
        L"powershell.exe",
        args,
        10 * 60 * 1000,
        exitCode);

    const std::wstring result = Trim(ReadTextFile(resultFile));

    DeleteFileW(script.c_str());
    DeleteFileW(resultFile.c_str());

    if (ran && exitCode == 0 && result.rfind(L"OK|", 0) == 0 &&
        FileExistsNonEmpty(wireguardPath))
    {
        return true;
    }

    std::wstring officialError = Tr(
        L"從 WireGuard 官方取得 wireguard.dll 失敗。",
        L"Failed to obtain wireguard.dll from the official WireGuard source.");

    if (!result.empty())
        officialError += L"\r\n" + result;
    else if (!ran)
        officialError += std::wstring(L"\r\n") + Tr(
            L"PowerShell 下載流程未成功執行。",
            L"The PowerShell download flow did not run successfully.");
    else if (exitCode != 0)
    {
        std::wstringstream ss;
        ss << L"\r\n"
           << Tr(L"PowerShell 結束碼：", L"PowerShell exit code: ")
           << exitCode;
        officialError += ss.str();
    }

    SetBootstrapText(
        bootstrap,
        Tr(L"官方下載失敗，正在改用 EasyWG GitHub 備援來源…",
           L"Official download failed, trying the EasyWG GitHub fallback source..."));

    std::wstring fallbackError;
    if (DownloadUrlToFile(kWireGuardFallbackDownloadUrl, wireguardPath, fallbackError) &&
        FileExistsNonEmpty(wireguardPath))
    {
        return true;
    }

    error = officialError;
    error += L"\r\n\r\n";
    error += Tr(
        L"已嘗試 EasyWG GitHub 備援來源，但仍無法取得 wireguard.dll。",
        L"The EasyWG GitHub fallback source was also tried, but wireguard.dll still could not be obtained.");
    error += L"\r\n";
    error += Tr(L"備援來源：", L"Fallback source: ");
    error += kWireGuardFallbackDownloadUrl;

    if (!fallbackError.empty())
        error += L"\r\n" + fallbackError;

    return false;
}



bool DownloadOfficialWintunComponent(
    HWND bootstrap,
    const std::wstring& appDir,
    std::wstring& error)
{
    const std::wstring zipPath =
        (fs::path(appDir) / L".easywg-wintun-download.zip").wstring();

    SetBootstrapText(
        bootstrap,
        Tr(L"正在從 Wintun 官方下載 Windows 7 元件，請稍候…",
           L"Downloading the official Windows 7 Wintun component, please wait..."));

    if (!DownloadUrlToFile(kWintunDownloadUrl, zipPath, error))
        return false;

    std::wstring script;
    if (!WriteEmbeddedScriptToTemp(
            EmbeddedScripts::kExtractWintunScript,
            L"EWW",
            script,
            error))
    {
        DeleteFileW(zipPath.c_str());
        return false;
    }

    const std::wstring resultFile = MakeTempFilePath(L"EWR");
    if (resultFile.empty())
    {
        DeleteFileW(script.c_str());
        DeleteFileW(zipPath.c_str());
        error = Tr(L"無法建立 Wintun 解壓結果檔。", L"Unable to create the Wintun extraction result file.");
        return false;
    }

    const std::wstring args =
        L"-NoProfile -ExecutionPolicy Bypass -File " + QuoteArg(script) +
        L" -ZipPath " + QuoteArg(zipPath) +
        L" -OutputDir " + QuoteArg(appDir) +
        L" -ResultFile " + QuoteArg(resultFile);

    DWORD exitCode = 1;
    const bool ran = RunProcessHidden(
        L"powershell.exe",
        args,
        120000,
        exitCode);

    const std::wstring result = Trim(ReadTextFile(resultFile));

    DeleteFileW(script.c_str());
    DeleteFileW(resultFile.c_str());
    DeleteFileW(zipPath.c_str());

    if (!ran || exitCode != 0 || result != L"OK")
    {
        error = Tr(
            L"從 Wintun 官方取得 wintun.dll 失敗。",
            L"Failed to obtain wintun.dll from the official Wintun source.");
        if (!result.empty())
            error += L"\r\n" + result;
        return false;
    }

    return FileExistsNonEmpty(
        (fs::path(appDir) / L"wintun.dll").wstring());
}

bool FilesEqualBinary(
    const std::wstring& leftPath,
    const std::wstring& rightPath)
{
    HANDLE left = CreateFileW(
        leftPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (left == INVALID_HANDLE_VALUE)
        return false;

    HANDLE right = CreateFileW(
        rightPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (right == INVALID_HANDLE_VALUE)
    {
        CloseHandle(left);
        return false;
    }

    LARGE_INTEGER leftSize{};
    LARGE_INTEGER rightSize{};
    bool equal =
        GetFileSizeEx(left, &leftSize) &&
        GetFileSizeEx(right, &rightSize) &&
        leftSize.QuadPart == rightSize.QuadPart;

    std::vector<unsigned char> leftBuffer(64 * 1024);
    std::vector<unsigned char> rightBuffer(64 * 1024);

    while (equal)
    {
        DWORD leftRead = 0;
        DWORD rightRead = 0;

        if (!ReadFile(
                left,
                leftBuffer.data(),
                static_cast<DWORD>(leftBuffer.size()),
                &leftRead,
                nullptr) ||
            !ReadFile(
                right,
                rightBuffer.data(),
                static_cast<DWORD>(rightBuffer.size()),
                &rightRead,
                nullptr))
        {
            equal = false;
            break;
        }

        if (leftRead != rightRead)
        {
            equal = false;
            break;
        }

        if (leftRead == 0)
            break;

        if (memcmp(leftBuffer.data(), rightBuffer.data(), leftRead) != 0)
        {
            equal = false;
            break;
        }
    }

    CloseHandle(right);
    CloseHandle(left);
    return equal;
}

bool ReplaceFileFromUpdate(
    const std::wstring& sourcePath,
    const std::wstring& targetPath,
    std::wstring& error)
{
    const std::wstring tempTarget =
        targetPath + L".easywg.update." +
        std::to_wstring(GetCurrentProcessId());

    if (!CopyFileW(
            sourcePath.c_str(),
            tempTarget.c_str(),
            FALSE))
    {
        error = Tr(
            L"複製更新元件失敗：",
            L"Failed to copy the updated component: ") +
            FormatWin32Error(GetLastError());
        return false;
    }

    if (!MoveFileExW(
            tempTarget.c_str(),
            targetPath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        const DWORD e = GetLastError();
        DeleteFileW(tempTarget.c_str());
        error = Tr(
            L"套用更新元件失敗：",
            L"Failed to apply the updated component: ") +
            FormatWin32Error(e);
        return false;
    }

    return true;
}

bool CheckWindows7CoreUpdatesNative(
    const std::wstring& appDir,
    std::wstring& result)
{
    const std::wstring tempRoot =
        (fs::path(fs::temp_directory_path()) /
         (L"EasyWG-WIN7-UPDATE-" +
          std::to_wstring(GetCurrentProcessId()))).wstring();

    try
    {
        fs::remove_all(fs::path(tempRoot));
        fs::create_directories(fs::path(tempRoot));
    }
    catch (...)
    {
        result = L"ERROR: unable to create temporary Windows 7 update directory";
        return false;
    }

    const std::wstring stagedTunnel =
        (fs::path(tempRoot) / L"tunnel-win7.dll").wstring();

    std::wstring error;
    if (!DownloadUrlToFile(
            kLegacyTunnelWin7DownloadUrl,
            stagedTunnel,
            error))
    {
        try { fs::remove_all(fs::path(tempRoot)); } catch (...) {}
        result = L"ERROR: " + error;
        return false;
    }

    if (!DownloadOfficialWintunComponent(
            nullptr,
            tempRoot,
            error))
    {
        try { fs::remove_all(fs::path(tempRoot)); } catch (...) {}
        result = L"ERROR: " + error;
        return false;
    }

    const std::wstring stagedWintun =
        (fs::path(tempRoot) / L"wintun.dll").wstring();

    const std::wstring currentTunnel =
        (fs::path(appDir) / L"tunnel-win7.dll").wstring();

    const std::wstring currentWintun =
        (fs::path(appDir) / L"wintun.dll").wstring();

    const bool needTunnel =
        !FileExistsNonEmpty(currentTunnel) ||
        !FilesEqualBinary(currentTunnel, stagedTunnel);

    const bool needWintun =
        !FileExistsNonEmpty(currentWintun) ||
        !FilesEqualBinary(currentWintun, stagedWintun);

    bool ok = true;

    if (needTunnel)
        ok = ReplaceFileFromUpdate(stagedTunnel, currentTunnel, error);

    if (ok && needWintun)
        ok = ReplaceFileFromUpdate(stagedWintun, currentWintun, error);

    try { fs::remove_all(fs::path(tempRoot)); } catch (...) {}

    if (!ok)
    {
        result = L"ERROR: " + error;
        return false;
    }

    result = (needTunnel || needWintun)
        ? L"UPDATED_WIN7"
        : L"NO_UPDATE_WIN7";

    return true;
}

bool ImportZipConfig(const std::wstring& zipPath, std::wstring& selectedConfig, std::wstring& error)
{
    std::wstring script;
    if (!WriteEmbeddedScriptToTemp(
            EmbeddedScripts::kImportZipScript,
            L"EWZ",
            script,
            error))
    {
        return false;
    }

    const std::wstring resultFile = MakeTempFilePath(L"EWR");
    if (resultFile.empty())
    {
        DeleteFileW(script.c_str());
        error = Tr(L"無法建立暫存結果檔。", L"Unable to create a temporary result file.");
        return false;
    }

    const std::wstring args =
        L"-NoProfile -ExecutionPolicy Bypass -File " + QuoteArg(script) +
        L" -ZipPath " + QuoteArg(zipPath) +
        L" -OutputDir " + QuoteArg(GetModuleDirectory()) +
        L" -ResultFile " + QuoteArg(resultFile);

    DWORD exitCode = 1;
    const bool ran = RunProcessHidden(L"powershell.exe", args, 120000, exitCode);
    const std::wstring result = ReadTextFile(resultFile);

    DeleteFileW(script.c_str());
    DeleteFileW(resultFile.c_str());

    if (!ran || exitCode != 0)
    {
        error = Tr(L"ZIP 匯入失敗。", L"ZIP import failed.");
        if (!result.empty())
            error += L"\r\n" + result;
        return false;
    }

    std::wistringstream input(result);
    std::wstring firstLine;
    std::getline(input, firstLine);
    firstLine = Trim(firstLine);

    if (firstLine.empty() || !FileExists(firstLine))
    {
        error = Tr(L"ZIP 內沒有可用的 .conf 設定檔。", L"No usable .conf file was found in the ZIP archive.");
        return false;
    }

    selectedConfig = FullPath(firstLine);
    return true;
}

std::wstring GetFileVersionString(const std::wstring& path)
{
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (size == 0)
        return {};

    std::vector<unsigned char> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data()))
        return {};

    VS_FIXEDFILEINFO* info = nullptr;
    UINT infoSize = 0;
    if (!VerQueryValueW(
            data.data(),
            L"\\",
            reinterpret_cast<void**>(&info),
            &infoSize) ||
        !info ||
        infoSize < sizeof(VS_FIXEDFILEINFO) ||
        info->dwSignature != 0xFEEF04BD)
    {
        return {};
    }

    const unsigned major = HIWORD(info->dwFileVersionMS);
    const unsigned minor = LOWORD(info->dwFileVersionMS);
    const unsigned build = HIWORD(info->dwFileVersionLS);
    const unsigned revision = LOWORD(info->dwFileVersionLS);

    std::wstringstream ss;
    ss << major << L"." << minor;
    if (build != 0 || revision != 0)
        ss << L"." << build;
    if (revision != 0)
        ss << L"." << revision;

    return ss.str();
}

std::wstring FormatDuration(std::chrono::seconds seconds)
{
    const auto total = seconds.count();
    const long long hours = total / 3600;
    const long long minutes = (total % 3600) / 60;
    const long long secs = total % 60;

    wchar_t buffer[64]{};
    swprintf_s(buffer, L"%02lld:%02lld:%02lld", hours, minutes, secs);
    return buffer;
}

std::wstring BuildConnectionInfoText()
{
    const std::wstring configPath = !g_activeConfigPath.empty()
        ? g_activeConfigPath
        : ResolveConfigPath(GetControlText(g_configEdit));

    if (configPath.empty() || !FileExists(configPath))
    {
        return Tr(
            L"選擇 .conf 或 .zip 設定檔後，這裡會顯示 Tunnel、位址、Endpoint 與路由資訊。",
            L"Select a .conf or .zip file to display tunnel, address, endpoint, and routing information.");
    }

    const ConfigInfo info = ParseConfigInfo(configPath);
    const std::wstring tunnel = TunnelNameFromConfig(configPath);

    std::wstringstream ss;
    ss << Tr(L"Tunnel：", L"Tunnel: ") << (tunnel.empty() ? L"-" : tunnel) << L"\r\n";
    ss << Tr(L"位址：", L"Address: ") << (info.address.empty() ? L"-" : info.address) << L"\r\n";
    ss << Tr(L"Endpoint：", L"Endpoint: ") << (info.endpoint.empty() ? L"-" : info.endpoint) << L"\r\n";
    ss << Tr(L"Allowed IPs：", L"Allowed IPs: ") << (info.allowedIps.empty() ? L"-" : info.allowedIps) << L"\r\n";
    ss << Tr(L"DNS：", L"DNS: ") << (info.dns.empty() ? L"-" : info.dns);

    if (!g_activeServiceName.empty() && g_lastServiceState == SERVICE_RUNNING)
    {
        ss << L"\r\n" << Tr(L"已連線：", L"Connected: ");
        if (g_hasConnectedTime)
        {
            wchar_t start[64]{};
            swprintf_s(start, L"%02u:%02u:%02u",
                g_connectedLocalTime.wHour,
                g_connectedLocalTime.wMinute,
                g_connectedLocalTime.wSecond);
            ss << start << L"  ("
               << FormatDuration(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - g_connectedAt))
               << L")";
        }
        else
        {
            ss << Tr(L"是", L"Yes");
        }
    }

    const std::wstring ntVersion = GetFileVersionString(
        (fs::path(GetModuleDirectory()) / L"wireguard.dll").wstring());
    std::wstring commit = ReadFirstLine(
        (fs::path(GetModuleDirectory()) / L"wireguard-windows-commit.txt").wstring());
    if (commit.size() > 8)
        commit.resize(8);

    if (!ntVersion.empty() || !commit.empty())
    {
        ss << L"\r\n" << Tr(L"核心：", L"Core: ");
        if (!ntVersion.empty())
            ss << L"WireGuardNT " << ntVersion;
        if (!commit.empty())
        {
            if (!ntVersion.empty())
                ss << L" / ";
            ss << L"tunnel " << commit;
        }
    }

    return ss.str();
}

bool SetWindowTextIfChanged(HWND control, const std::wstring& text)
{
    if (!control)
        return false;

    const int len = GetWindowTextLengthW(control);
    std::wstring current;
    if (len > 0)
    {
        current.resize(static_cast<size_t>(len) + 1);
        const int written = GetWindowTextW(control, current.data(), len + 1);
        if (written > 0)
            current.resize(static_cast<size_t>(written));
        else
            current.clear();
    }

    if (current == text)
        return false;

    SetWindowTextW(control, text.c_str());
    return true;
}

void UpdateConnectionInfo()
{
    if (g_infoEdit)
        SetWindowTextIfChanged(g_infoEdit, BuildConnectionInfoText());
}

std::wstring ServiceStateText(DWORD state)
{
    switch (state)
    {
    case SERVICE_STOPPED:
        return Tr(L"● 未連線", L"● Disconnected");
    case SERVICE_START_PENDING:
        return Tr(L"● 啟動中", L"● Starting");
    case SERVICE_STOP_PENDING:
        return Tr(L"● 中斷中", L"● Disconnecting");
    case SERVICE_RUNNING:
        return Tr(L"● 已連線", L"● Connected");
    case SERVICE_CONTINUE_PENDING:
        return Tr(L"● 恢復中", L"● Resuming");
    case SERVICE_PAUSE_PENDING:
        return Tr(L"● 暫停中", L"● Pausing");
    case SERVICE_PAUSED:
        return Tr(L"● 已暫停", L"● Paused");
    default:
        return Tr(L"● 未知狀態", L"● Unknown");
    }
}

void SetStatus(DWORD state)
{
    const bool stateChanged = (g_lastServiceState != state);
    g_lastServiceState = state;

    if (g_statusLabel)
    {
        SetWindowTextIfChanged(g_statusLabel, ServiceStateText(state));

        if (stateChanged)
            InvalidateRect(g_statusLabel, nullptr, TRUE);
    }
}

void UpdateTrayTooltip()
{
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_mainWindow;
    nid.uID = 1;
    nid.uFlags = NIF_TIP;

    const std::wstring tip = std::wstring(kAppName) + L" - " + ServiceStateText(g_lastServiceState);
    wcsncpy_s(nid.szTip, tip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void RefreshStatus()
{
    if (g_activeServiceName.empty())
    {
        SetStatus(SERVICE_STOPPED);
        EnableWindow(g_connectButton, TRUE);
        EnableWindow(g_disconnectButton, FALSE);
        UpdateConnectionInfo();
        UpdateTrayTooltip();
        return;
    }

    DWORD state = SERVICE_STOPPED;
    DWORD exitCode = 0;
    if (!QueryServiceStatusByName(g_activeServiceName, state, &exitCode))
    {
        SetStatus(SERVICE_STOPPED);
        EnableWindow(g_connectButton, TRUE);
        EnableWindow(g_disconnectButton, FALSE);
        g_activeServiceName.clear();
        g_activeConfigPath.clear();
        g_hasConnectedTime = false;
        UpdateConnectionInfo();
        UpdateTrayTooltip();
        return;
    }

    SetStatus(state);
    EnableWindow(g_connectButton, state == SERVICE_STOPPED ? TRUE : FALSE);
    EnableWindow(g_disconnectButton, state != SERVICE_STOPPED ? TRUE : FALSE);

    if (state == SERVICE_STOPPED)
    {
        if (exitCode != ERROR_SUCCESS)
        {
            std::wstringstream ss;
            ss << Tr(L"Tunnel 已停止，服務錯誤碼：", L"Tunnel stopped with service error: ") << exitCode;
            AppendLog(ss.str());
        }

        std::wstring ignored;
        StopAndDeleteService(g_activeServiceName, false, &ignored);
        g_activeServiceName.clear();
        g_activeConfigPath.clear();
        g_hasConnectedTime = false;
    }

    UpdateConnectionInfo();
    UpdateTrayTooltip();
}

void ApplySelectedConfig(const std::wstring& path, bool logSelection)
{
    if (!g_configEdit)
        return;

    const std::wstring full = ResolveConfigPath(path);
    const std::wstring display = ConfigPathForDisplay(full);

    if (!g_temporaryConfigPath.empty() &&
        _wcsicmp(FullPath(g_temporaryConfigPath).c_str(), full.c_str()) != 0)
    {
        DeleteFileW(g_temporaryConfigPath.c_str());
        g_temporaryConfigPath.clear();
    }

    SetWindowTextW(g_configEdit, display.c_str());
    g_settings.lastConfig = ConfigPathForStorage(full);
    SaveSettings();
    UpdateConnectionInfo();

    if (logSelection)
        AppendLog(Tr(L"已選擇設定檔：", L"Selected configuration: ") + full);
}

bool SelectConfigOrZip(const std::wstring& inputPath)
{
    if (inputPath.empty())
        return false;

    const std::wstring full = FullPath(inputPath);
    const std::wstring ext = ToLower(fs::path(full).extension().wstring());

    if (ext == L".conf")
    {
        ApplySelectedConfig(full, true);
        return true;
    }

    if (ext == L".zip")
    {
        std::wstring config;
        std::wstring error;
        AppendLog(Tr(L"正在從 ZIP 匯入 .conf：", L"Importing .conf from ZIP: ") + full);

        if (!ImportZipConfig(full, config, error))
        {
            MessageBoxW(g_mainWindow, error.c_str(), kAppName, MB_ICONERROR);
            AppendLog(error);
            return false;
        }

        ApplySelectedConfig(config, false);
        AppendLog(Tr(L"ZIP 匯入完成，使用設定檔：", L"ZIP import complete. Using: ") + config);
        return true;
    }

    MessageBoxW(
        g_mainWindow,
        Tr(L"只支援 .conf 或 .zip 檔案。", L"Only .conf and .zip files are supported."),
        kAppName,
        MB_ICONWARNING);
    return false;
}

void BrowseForConfig(HWND owner)
{
    wchar_t fileName[32768]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter =
        L"WireGuard config or ZIP (*.conf;*.zip)\0*.conf;*.zip\0"
        L"WireGuard config (*.conf)\0*.conf\0"
        L"ZIP archive (*.zip)\0*.zip\0"
        L"All files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = static_cast<DWORD>(std::size(fileName));
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;

    if (GetOpenFileNameW(&ofn))
        SelectConfigOrZip(fileName);
}


void EditCurrentConfig()
{
    const std::wstring configPath = ResolveConfigPath(GetControlText(g_configEdit));

    std::wstring validationError;
    if (!ValidateConfigPath(configPath, validationError))
    {
        MessageBoxW(
            g_mainWindow,
            validationError.c_str(),
            kAppName,
            MB_ICONWARNING);
        AppendLog(validationError);
        return;
    }

    const std::wstring command =
        L"notepad.exe " + QuoteArg(configPath);

    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(
            nullptr,
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &si,
            &pi))
    {
        const std::wstring error =
            Tr(L"無法開啟記事本編輯設定檔：", L"Unable to open the configuration in Notepad: ") +
            FormatWin32Error(GetLastError());

        MessageBoxW(
            g_mainWindow,
            error.c_str(),
            kAppName,
            MB_ICONERROR);
        AppendLog(error);
        return;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    AppendLog(
        Tr(L"已開啟設定檔編輯：", L"Opened configuration for editing: ") +
        configPath);

    if (!g_activeServiceName.empty())
    {
        AppendLog(Tr(
            L"目前 VPN 已連線；修改 .conf 後需中斷並重新連線才會套用。",
            L"The VPN is currently connected; disconnect and reconnect to apply .conf changes."));
    }
}

void DoConnect()
{
    if (!g_activeServiceName.empty())
    {
        MessageBoxW(
            g_mainWindow,
            Tr(L"目前已有 Tunnel 在執行。", L"A tunnel is already running."),
            kAppName,
            MB_ICONINFORMATION);
        return;
    }

    std::wstring configPath = ResolveConfigPath(GetControlText(g_configEdit));
    std::wstring validationError;
    if (!ValidateConfigPath(configPath, validationError))
    {
        MessageBoxW(g_mainWindow, validationError.c_str(), kAppName, MB_ICONWARNING);
        AppendLog(validationError);
        return;
    }

    const std::wstring dir = GetModuleDirectory();
    const bool legacyWin7 = IsWindows7OrEarlier();

    const std::wstring primaryDll = legacyWin7
        ? (fs::path(dir) / L"tunnel-win7.dll").wstring()
        : (fs::path(dir) / L"tunnel.dll").wstring();

    const std::wstring dependencyDll = legacyWin7
        ? (fs::path(dir) / L"wintun.dll").wstring()
        : (fs::path(dir) / L"wireguard.dll").wstring();

    if (!FileExists(primaryDll) || !FileExists(dependencyDll))
    {
        const std::wstring message = legacyWin7
            ? Tr(
                L"找不到 Windows 7 必要核心 DLL。\r\n\r\n需要：\r\n  tunnel-win7.dll\r\n  wintun.dll\r\n\r\n請重新啟動 EasyWG，程式會自動下載缺少的元件。",
                L"Required Windows 7 core DLL files were not found.\r\n\r\nRequired:\r\n  tunnel-win7.dll\r\n  wintun.dll\r\n\r\nRestart EasyWG and the application will automatically download missing components.")
            : Tr(
                L"找不到必要核心 DLL。\r\n\r\n需要：\r\n  tunnel.dll\r\n  wireguard.dll\r\n\r\n請重新啟動 EasyWG，程式會自動下載缺少的元件。",
                L"Required core DLL files were not found.\r\n\r\nRequired:\r\n  tunnel.dll\r\n  wireguard.dll\r\n\r\nRestart EasyWG and the application will automatically download missing components.");

        MessageBoxW(g_mainWindow, message.c_str(), kAppName, MB_ICONERROR);

        if (legacyWin7)
        {
            AppendLog(Tr(
                L"缺少 tunnel-win7.dll 或 wintun.dll。",
                L"Missing tunnel-win7.dll or wintun.dll."));
        }
        else
        {
            AppendLog(Tr(
                L"缺少 tunnel.dll 或 wireguard.dll。",
                L"Missing tunnel.dll or wireguard.dll."));
        }
        return;
    }

    SetWindowTextW(g_configEdit,
                   IsTemporaryConfigPath(configPath) ? kTemporaryConfigDisplay
                                                     : ConfigPathForDisplay(configPath).c_str());
    SetStatus(SERVICE_START_PENDING);
    EnableWindow(g_connectButton, FALSE);

    const std::wstring serviceName = ServiceNameFromConfig(configPath);
    std::wstring error;
    AppendLog(Tr(L"準備啟動：", L"Preparing to start: ") + configPath);

    bool ok = false;
    if (IsProcessElevated())
    {
        std::wstring createdName;
        ok = CreateAndStartTunnelService(configPath, createdName, error);
    }
    else
    {
        DWORD helperExit = 1;
        const std::wstring params =
            L"/elevated-start " + QuoteArg(configPath) + L" " +
            std::to_wstring(GetCurrentProcessId());
        ok = RunElevatedHelper(params, helperExit, error);
    }

    if (!ok)
    {
        SetStatus(SERVICE_STOPPED);
        EnableWindow(g_connectButton, TRUE);
        MessageBoxW(g_mainWindow, error.c_str(), kAppName, MB_ICONERROR);
        AppendLog(error);
        return;
    }

    DWORD state = SERVICE_STOPPED;
    const ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < 5000)
    {
        if (QueryServiceStatusByName(serviceName, state) && state == SERVICE_RUNNING)
            break;
        Sleep(150);
    }

    if (state != SERVICE_RUNNING)
    {
        error = Tr(
            L"服務已建立，但無法確認 Tunnel 進入 Running 狀態。",
            L"The service was created, but the tunnel did not reach Running state.");
        SetStatus(SERVICE_STOPPED);
        EnableWindow(g_connectButton, TRUE);
        MessageBoxW(g_mainWindow, error.c_str(), kAppName, MB_ICONERROR);
        AppendLog(error);
        return;
    }

    g_activeServiceName = serviceName;
    g_activeConfigPath = configPath;
    GetLocalTime(&g_connectedLocalTime);
    g_connectedAt = std::chrono::steady_clock::now();
    g_hasConnectedTime = true;
    if (!IsTemporaryConfigPath(configPath))
    {
        g_settings.lastConfig = ConfigPathForStorage(configPath);
        SaveSettings();
    }

    AppendLog(Tr(L"已啟動臨時 Tunnel 服務：", L"Temporary tunnel service started: ") + serviceName);
    RefreshStatus();
}

void DoDisconnect(bool silent)
{
    if (g_activeServiceName.empty())
        return;

    const std::wstring serviceName = g_activeServiceName;
    SetStatus(SERVICE_STOP_PENDING);
    EnableWindow(g_disconnectButton, FALSE);

    bool stopped = SignalStopEvent(serviceName);
    if (stopped)
        stopped = WaitForServiceGone(serviceName, 12000);

    std::wstring error;
    if (!stopped)
    {
        if (IsProcessElevated())
        {
            stopped = StopAndDeleteService(serviceName, true, &error);
        }
        else
        {
            DWORD helperExit = 1;
            const std::wstring params = L"/elevated-stop " + QuoteArg(serviceName);
            stopped = RunElevatedHelper(params, helperExit, error);
        }
    }

    g_activeServiceName.clear();
    g_activeConfigPath.clear();
    g_hasConnectedTime = false;

    if (stopped)
    {
        AppendLog(Tr(L"已停止並移除臨時 Tunnel 服務：", L"Temporary tunnel service stopped and removed: ") + serviceName);
    }
    else
    {
        if (error.empty())
            error = Tr(L"無法完全停止 Tunnel。", L"Unable to fully stop the tunnel.");
        AppendLog(error);
        if (!silent)
            MessageBoxW(g_mainWindow, error.c_str(), kAppName, MB_ICONWARNING);
    }

    RefreshStatus();
}


bool GeneratePortableKeyPair(std::array<BYTE, 32>& publicKey,
                             std::array<BYTE, 32>& privateKey)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = static_cast<NTSTATUS>(-1);
    if (!IsWindows7OrEarlier())
        status = BCryptOpenAlgorithmProvider(&algorithm, L"ECDH", nullptr, 0);
    if (status >= 0)
    {
        const wchar_t curve[] = L"curve25519";
        status = BCryptSetProperty(
            algorithm, L"ECCCurveName",
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(curve)),
            static_cast<ULONG>(sizeof(curve)), 0);
    }
    if (status >= 0)
        status = BCryptGenerateKeyPair(algorithm, &key, 255, 0);
    if (status >= 0)
        status = BCryptFinalizeKeyPair(key, 0);

    struct ExportBlob
    {
        BCRYPT_ECCKEY_BLOB header;
        BYTE publicPart[32];
        BYTE unused[32];
        BYTE privatePart[32];
    } blob{};
    ULONG written = 0;
    if (status >= 0)
        status = BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                                 reinterpret_cast<PUCHAR>(&blob), sizeof(blob),
                                 &written, 0);
    const bool cngOk = status >= 0 && written >= sizeof(blob);
    if (cngOk)
    {
        std::copy(std::begin(blob.publicPart), std::end(blob.publicPart), publicKey.begin());
        std::copy(std::begin(blob.privatePart), std::end(blob.privatePart), privateKey.begin());
    }
    SecureZeroMemory(&blob, sizeof(blob));
    if (key) BCryptDestroyKey(key);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (cngOk) return true;

    if (BCryptGenRandom(nullptr, privateKey.data(), static_cast<ULONG>(privateKey.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return false;
    return easywg_x25519::public_from_private(publicKey.data(), privateKey.data());
}

std::wstring SafeRequestFileName(const std::wstring& suggested)
{
    std::wstring name = fs::path(suggested).filename().wstring();
    if (name.empty()) name = L"EasyWG_Auto.conf";
    if (ToLower(fs::path(name).extension().wstring()) != L".conf")
        name += L".conf";
    for (wchar_t& ch : name)
    {
        if (ch < 32 || wcschr(L"<>:\\|?*\"/", ch)) ch = L'_';
    }
    if (name.size() > 80)
        name = name.substr(0, 75) + L".conf";
    return name;
}

bool WriteUtf8ConfigFile(const std::wstring& path, const std::wstring& text,
                         std::wstring& error)
{
    std::string utf8 = easywg_request::WideToUtf8(text);
    std::ofstream output(fs::path(path), std::ios::binary | std::ios::trunc);
    if (!output)
    {
        error = Tr(L"無法建立 WireGuard 設定檔：", L"Unable to create WireGuard configuration: ") + path;
        if (!utf8.empty()) SecureZeroMemory(utf8.data(), utf8.size());
        return false;
    }
    output.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    output.close();
    const bool ok = !output.fail();
    if (!utf8.empty()) SecureZeroMemory(utf8.data(), utf8.size());
    if (!ok)
    {
        error = Tr(L"寫入 WireGuard 設定檔失敗：", L"Failed to write WireGuard configuration: ") + path;
        return false;
    }
    return true;
}

std::wstring MakeUniquePermanentConfigPath(const std::wstring& suggested)
{
    const fs::path directory(GetModuleDirectory());
    const fs::path safe(SafeRequestFileName(suggested));
    fs::path candidate = directory / safe;
    if (!FileExists(candidate.wstring())) return candidate.wstring();

    const std::wstring stem = safe.stem().wstring();
    for (int i = 2; i < 1000; ++i)
    {
        candidate = directory / (stem + L"_" + std::to_wstring(i) + L".conf");
        if (!FileExists(candidate.wstring())) return candidate.wstring();
    }
    return (directory / (stem + L"_" + std::to_wstring(GetTickCount64()) + L".conf")).wstring();
}

std::wstring TemporaryConfigPath()
{
    wchar_t temp[MAX_PATH]{};
    if (!GetTempPathW(static_cast<DWORD>(std::size(temp)), temp))
        return (fs::path(GetModuleDirectory()) / L"EasyWG_Temporary.conf").wstring();
    fs::path directory = fs::path(temp) / L"EasyWG_Portable";
    std::error_code ec;
    fs::create_directories(directory, ec);
    return (directory / (L"EasyWG_Temporary_" + std::to_wstring(GetCurrentProcessId()) + L".conf")).wstring();
}

void CleanupStaleTemporaryConfigs()
{
    // This is called only after this process owns the single-instance mutex,
    // so it cannot delete a temporary profile still used by another UI instance.
    DeleteFileW((fs::path(GetModuleDirectory()) / L"EasyWG_Temporary.conf").wstring().c_str());

    wchar_t temp[MAX_PATH]{};
    if (!GetTempPathW(static_cast<DWORD>(std::size(temp)), temp)) return;
    const fs::path directory = fs::path(temp) / L"EasyWG_Portable";
    std::error_code ec;
    if (!fs::is_directory(directory, ec)) return;
    for (fs::directory_iterator it(directory, ec), end; !ec && it != end; it.increment(ec))
    {
        if (!it->is_regular_file(ec)) continue;
        const std::wstring name = it->path().filename().wstring();
        if (name.rfind(L"EasyWG_Temporary_", 0) == 0 &&
            _wcsicmp(it->path().extension().c_str(), L".conf") == 0)
            fs::remove(it->path(), ec);
        ec.clear();
    }
}

std::wstring BuildRequestedConfigText(const easywg_request::Result& result,
                                      const std::wstring& requestHost, int requestPort,
                                      const std::array<BYTE, 32>& privateKey,
                                      const std::array<BYTE, 32>& presharedKey)
{
    std::wstring endpoint = Trim(result.endpoint);
    if (endpoint.empty()) endpoint = requestHost;
    std::wstringstream config;
    config << L"[Interface]\r\n"
           << L"PrivateKey = "
           << easywg_request::Utf8ToWide(easywg_request::Base64Encode(privateKey.data(), 32))
           << L"\r\nAddress = " << result.address << L"\r\n";
    if (!Trim(result.dns).empty()) config << L"DNS = " << result.dns << L"\r\n";
    config << L"\r\n[Peer]\r\n"
           << L"PublicKey = " << result.serverPublicKey << L"\r\n"
           << L"PresharedKey = "
           << easywg_request::Utf8ToWide(easywg_request::Base64Encode(presharedKey.data(), 32))
           << L"\r\nEndpoint = " << endpoint << L":" << requestPort << L"\r\n"
           << L"AllowedIPs = " << result.allowedIps << L"\r\n"
           << L"PersistentKeepalive = 25\r\n";
    return config.str();
}

void CompleteQuickRequest()
{
    QuickRequestCompletion completion;
    {
        std::lock_guard<std::mutex> lock(g_requestMutex);
        completion = std::move(g_requestCompletion);
        g_requestCompletion = {};
    }
    g_requestRunning = false;

    if (!completion.ok)
    {
        if (g_reqSubmit) EnableWindow(g_reqSubmit, TRUE);
        if (g_reqStatus) SetWindowTextW(g_reqStatus, completion.error.c_str());
        if (!completion.error.empty())
            MessageBoxW(g_requestWindow ? g_requestWindow : g_mainWindow,
                        completion.error.c_str(), kAppName, MB_ICONERROR);
        SecureClearWideString(completion.configText);
        return;
    }

    std::wstring path = completion.temporary
        ? TemporaryConfigPath()
        : MakeUniquePermanentConfigPath(completion.suggestedFileName);
    std::wstring error;
    if (!WriteUtf8ConfigFile(path, completion.configText, error))
    {
        if (g_reqSubmit) EnableWindow(g_reqSubmit, TRUE);
        if (g_reqStatus) SetWindowTextW(g_reqStatus, error.c_str());
        MessageBoxW(g_requestWindow ? g_requestWindow : g_mainWindow,
                    error.c_str(), kAppName, MB_ICONERROR);
        SecureClearWideString(completion.configText);
        return;
    }

    if (completion.temporary)
    {
        if (!g_temporaryConfigPath.empty() &&
            _wcsicmp(g_temporaryConfigPath.c_str(), path.c_str()) != 0)
            DeleteFileW(g_temporaryConfigPath.c_str());
        g_temporaryConfigPath = path;
        SetWindowTextW(g_configEdit, kTemporaryConfigDisplay);
        UpdateConnectionInfo();
        AppendLog(Tr(L"臨時連線申請完成，設定只保留到程式退出。",
                     L"Temporary connection request completed; the configuration is kept only until the app exits."));
    }
    else
    {
        ApplySelectedConfig(path, false);
        AppendLog(Tr(L"快速申請完成，設定檔已儲存：",
                     L"Quick request completed; configuration saved: ") + path);
    }

    if (g_requestWindow && IsWindow(g_requestWindow))
        DestroyWindow(g_requestWindow);
    ShowMainWindow();
    SecureClearWideString(completion.configText);
    DoConnect();
}

void StartQuickRequest()
{
    if (g_requestRunning) return;
    const bool temporary = SendMessageW(g_reqTemporary, BM_GETCHECK, 0, 0) == BST_CHECKED;
    const bool fullTunnel = SendMessageW(g_reqFullTunnel, BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::wstring connectionName = temporary ? L"New Device" : Trim(GetControlText(g_reqName));
    const std::wstring server = Trim(GetControlText(g_reqServer));
    const int port = _wtoi(Trim(GetControlText(g_reqPort)).c_str());
    std::wstring password = GetControlText(g_reqPassword);
    if (connectionName.empty() || server.empty() || port < 1 || port > 65535 || password.empty())
    {
        MessageBoxW(g_requestWindow,
                    Tr(L"請輸入連線名稱、申請伺服器、1～65535 的連接埠與申請密碼。",
                       L"Enter a connection name, request server, port from 1 to 65535, and request password."),
                    kAppName, MB_ICONWARNING);
        return;
    }

    g_settings.requestServer = server;
    g_settings.requestPort = port;
    if (!temporary) g_settings.requestName = connectionName;
    SaveSettings();
    EnableWindow(g_reqSubmit, FALSE);
    SetWindowTextW(g_reqStatus,
                   Tr(L"正在驗證密碼並申請 WireGuard 設定…",
                      L"Verifying the password and requesting WireGuard configuration..."));
    g_requestRunning = true;

    std::thread([server, port, password, temporary, fullTunnel, connectionName]() mutable {
        QuickRequestCompletion completion;
        completion.temporary = temporary;
        completion.requestHost = server;

        easywg_request::Request request;
        request.temporary = temporary;
        request.fullTunnel = fullTunnel;
        request.clientName = temporary ? L"New Device" : connectionName;

        std::array<BYTE, 32> privateKey{};
        if (!GeneratePortableKeyPair(request.publicKey, privateKey) ||
            !easywg_request::GenerateRandom(request.presharedKey.data(),
                                             static_cast<ULONG>(request.presharedKey.size())))
        {
            completion.error = Tr(L"無法產生 WireGuard 用戶金鑰。",
                                  L"Unable to generate WireGuard client keys.");
        }
        else
        {
            easywg_request::Result result;
            std::wstring error;
            if (easywg_request::PerformRequest(server, static_cast<unsigned short>(port),
                                               password, request, result, error))
            {
                if (Trim(result.address).empty() || Trim(result.allowedIps).empty() ||
                    Trim(result.serverPublicKey).empty())
                {
                    completion.error = Tr(L"Server 回傳的 WireGuard 設定不完整。",
                                          L"The server returned an incomplete WireGuard configuration.");
                }
                else
                {
                    completion.ok = true;
                    completion.suggestedFileName = result.fileName;
                    completion.configText = BuildRequestedConfigText(
                        result, server, port, privateKey, request.presharedKey);
                }
            }
            else
            {
                completion.error = error;
            }
        }
        SecureZeroMemory(privateKey.data(), privateKey.size());
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        {
            std::lock_guard<std::mutex> lock(g_requestMutex);
            g_requestCompletion = std::move(completion);
        }
        if (g_requestWindow && IsWindow(g_requestWindow))
            PostMessageW(g_requestWindow, WM_REQUEST_DONE, 0, 0);
    }).detach();
}

LRESULT CALLBACK RequestWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HFONT normalFont = nullptr;
    static HFONT titleFont = nullptr;
    static HFONT linkFont = nullptr;
    switch (message)
    {
    case WM_CREATE:
    {
        g_requestWindow = hwnd;
        normalFont = CreateUiFont(10, false);
        titleFont = CreateUiFont(14, true);
        LOGFONTW requestLinkLf{};
        GetObjectW(normalFont, sizeof(requestLinkLf), &requestLinkLf);
        requestLinkLf.lfWeight = FW_SEMIBOLD;
        requestLinkLf.lfUnderline = TRUE;
        linkFont = CreateFontIndirectW(&requestLinkLf);

        HWND title = CreateWindowExW(0, L"STATIC",
            Tr(L"EasyWG Server 快速申請連線", L"EasyWG Server Quick Connection Request"),
            WS_CHILD | WS_VISIBLE, 24, 18, 470, 34, hwnd, nullptr, g_instance, nullptr);
        ApplyFont(title, titleFont);

        auto label = [&](const wchar_t* caption, int y) {
            HWND control = CreateWindowExW(0, L"STATIC", caption, WS_CHILD | WS_VISIBLE,
                                            28, y, 122, 28, hwnd, nullptr, g_instance, nullptr);
            ApplyFont(control, normalFont);
        };
        label(Tr(L"連線名稱：", L"Connection name:"), 68);
        label(Tr(L"申請伺服器：", L"Request server:"), 112);
        label(Tr(L"連接埠：", L"Port:"), 156);
        label(Tr(L"申請密碼：", L"Request password:"), 200);

        g_reqName = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_settings.requestName.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            150, 64, 330, 31, hwnd, reinterpret_cast<HMENU>(IDC_REQ_NAME), g_instance, nullptr);
        g_reqServer = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_settings.requestServer.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            150, 108, 330, 31, hwnd, reinterpret_cast<HMENU>(IDC_REQ_SERVER), g_instance, nullptr);
        g_reqPort = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", std::to_wstring(g_settings.requestPort).c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER,
            150, 152, 130, 31, hwnd, reinterpret_cast<HMENU>(IDC_REQ_PORT), g_instance, nullptr);
        g_reqPassword = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            150, 196, 330, 31, hwnd, reinterpret_cast<HMENU>(IDC_REQ_PASSWORD), g_instance, nullptr);
        g_reqFullTunnel = CreateWindowExW(0, L"BUTTON",
            Tr(L"需使用 VPN 主機公網 IP 上網\r\n（不勾選仍可連接內網）",
               L"Route Internet traffic through the VPN server\r\n(Unchecked still allows private-network access)"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE,
            32, 240, 452, 52, hwnd, reinterpret_cast<HMENU>(IDC_REQ_FULL_TUNNEL), g_instance, nullptr);
        g_reqTemporary = CreateWindowExW(0, L"BUTTON",
            Tr(L"臨時連線申請\r\n（關閉程式後需重新申請）",
               L"Temporary connection request\r\n(Request again after exiting the app)"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE,
            32, 296, 452, 52, hwnd, reinterpret_cast<HMENU>(IDC_REQ_TEMPORARY), g_instance, nullptr);
        SendMessageW(g_reqFullTunnel, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(g_reqTemporary, BM_SETCHECK, BST_UNCHECKED, 0);

        g_reqDownload = CreateWindowExW(0, L"STATIC",
            Tr(L"EasyWG Server 伺服器端（GitHub 下載）", L"EasyWG Server (GitHub download)"),
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            32, 360, 430, 28, hwnd, reinterpret_cast<HMENU>(IDC_REQ_DOWNLOAD), g_instance, nullptr);
        g_reqStatus = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX,
            24, 398, 472, 82, hwnd, reinterpret_cast<HMENU>(IDC_REQ_STATUS), g_instance, nullptr);
        g_reqSubmit = CreateWindowExW(0, L"BUTTON",
            Tr(L"申請並連線", L"Request and Connect"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            190, 492, 140, 38, hwnd, reinterpret_cast<HMENU>(IDC_REQ_SUBMIT), g_instance, nullptr);
        g_reqCancel = CreateWindowExW(0, L"BUTTON", Tr(L"取消", L"Cancel"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            340, 492, 100, 38, hwnd, reinterpret_cast<HMENU>(IDC_REQ_CANCEL), g_instance, nullptr);

        for (HWND control : {g_reqName, g_reqServer, g_reqPort, g_reqPassword, g_reqFullTunnel,
                             g_reqTemporary, g_reqStatus, g_reqSubmit, g_reqCancel})
            ApplyFont(control, normalFont);
        ApplyFont(g_reqDownload, linkFont);
        SetFocus(g_reqName);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_REQ_SUBMIT:
            StartQuickRequest();
            return 0;
        case IDC_REQ_CANCEL:
            if (!g_requestRunning) DestroyWindow(hwnd);
            return 0;
        case IDC_REQ_TEMPORARY:
            if (HIWORD(wParam) == BN_CLICKED && g_reqName)
            {
                const bool temporary = SendMessageW(g_reqTemporary, BM_GETCHECK, 0, 0) == BST_CHECKED;
                if (temporary)
                {
                    const std::wstring current = Trim(GetControlText(g_reqName));
                    if (!current.empty()) g_settings.requestName = current;
                    SetWindowTextW(g_reqName, L"New Device");
                    EnableWindow(g_reqName, FALSE);
                }
                else
                {
                    EnableWindow(g_reqName, TRUE);
                    SetWindowTextW(g_reqName,
                        g_settings.requestName.empty() ? L"New Device" : g_settings.requestName.c_str());
                    SetFocus(g_reqName);
                }
            }
            return 0;
        case IDC_REQ_DOWNLOAD:
            if (HIWORD(wParam) == STN_CLICKED)
                ShellExecuteW(hwnd, L"open",
                    L"https://github.com/Terence0816/easy-wireguard-server",
                    nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        }
        break;
    case WM_REQUEST_DONE:
        CompleteQuickRequest();
        return 0;
    case WM_CTLCOLORSTATIC:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        HWND control = reinterpret_cast<HWND>(lParam);
        SetBkMode(dc, TRANSPARENT);
        if (control == g_reqDownload)
            SetTextColor(dc, RGB(20, 92, 190));
        else if (control == g_reqStatus)
            SetTextColor(dc, g_mutedTextColor);
        else
            SetTextColor(dc, g_textColor);
        return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
    }
    case WM_SETCURSOR:
        if (reinterpret_cast<HWND>(wParam) == g_reqDownload)
        {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    case WM_CLOSE:
        if (!g_requestRunning) DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (normalFont) { DeleteObject(normalFont); normalFont = nullptr; }
        if (titleFont) { DeleteObject(titleFont); titleFont = nullptr; }
        if (linkFont) { DeleteObject(linkFont); linkFont = nullptr; }
        g_requestWindow = nullptr;
        if (g_mainWindow && IsWindow(g_mainWindow))
        {
            EnableWindow(g_mainWindow, TRUE);
            SetForegroundWindow(g_mainWindow);
        }
        g_reqName = g_reqServer = g_reqPort = g_reqPassword = nullptr;
        g_reqFullTunnel = g_reqTemporary = nullptr;
        g_reqSubmit = g_reqCancel = g_reqStatus = g_reqDownload = nullptr;
        return 0;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

void ShowQuickRequest()
{
    if (!g_activeServiceName.empty())
    {
        MessageBoxW(g_mainWindow,
                    Tr(L"請先中斷目前的 Tunnel，再申請新的連線。",
                       L"Disconnect the current tunnel before requesting a new connection."),
                    kAppName, MB_ICONINFORMATION);
        return;
    }
    if (g_requestWindow)
    {
        SetForegroundWindow(g_requestWindow);
        return;
    }
    RECT mainRect{};
    GetWindowRect(g_mainWindow, &mainRect);
    const int width = 540, height = 610;
    const int x = mainRect.left + ((mainRect.right - mainRect.left) - width) / 2;
    const int y = mainRect.top + ((mainRect.bottom - mainRect.top) - height) / 2;
    g_requestWindow = CreateWindowExW(
        WS_EX_DLGMODALFRAME, kRequestClass,
        Tr(L"快速申請連線", L"Quick Connection Request"),
        WS_CAPTION | WS_SYSMENU | WS_POPUP | WS_VISIBLE,
        x, y, width, height, g_mainWindow, nullptr, g_instance, nullptr);
    if (g_requestWindow) EnableWindow(g_mainWindow, FALSE);
}

HFONT CreateUiFont(int pointSize, bool bold)
{
    HDC screen = GetDC(nullptr);
    const int dpi = screen ? GetDeviceCaps(screen, LOGPIXELSY) : 96;
    if (screen)
        ReleaseDC(nullptr, screen);

    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(pointSize, dpi, 72);
    lf.lfWeight = bold ? FW_SEMIBOLD : FW_NORMAL;
    wcscpy_s(lf.lfFaceName, L"Segoe UI");
    return CreateFontIndirectW(&lf);
}

void ApplyFont(HWND control, HFONT font)
{
    if (control)
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

void AddTrayIcon()
{
    if (!g_mainWindow)
        return;

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_mainWindow;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    const std::wstring tip = std::wstring(kAppName) + L" - " + ServiceStateText(g_lastServiceState);
    wcsncpy_s(nid.szTip, tip.c_str(), _TRUNCATE);

    Shell_NotifyIconW(NIM_ADD, &nid);
}

void RemoveTrayIcon()
{
    if (!g_mainWindow)
        return;

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_mainWindow;
    nid.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

void ShowMainWindow()
{
    if (!g_mainWindow)
        return;

    ShowWindow(g_mainWindow, SW_SHOW);
    if (IsIconic(g_mainWindow))
        ShowWindow(g_mainWindow, SW_RESTORE);
    SetForegroundWindow(g_mainWindow);
}

void ShowTrayMenu()
{
    HMENU menu = CreatePopupMenu();
    if (!menu)
        return;

    AppendMenuW(menu, MF_STRING, IDM_TRAY_SHOW, Tr(L"主視窗", L"Main Window"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, Tr(L"退出", L"Exit"));

    POINT pt{};
    GetCursorPos(&pt);
    SetForegroundWindow(g_mainWindow);

    TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
        pt.x, pt.y, 0,
        g_mainWindow, nullptr);

    DestroyMenu(menu);
}

void UpdateMenuText()
{
    if (!g_mainMenu)
        return;

    ModifyMenuW(g_mainMenu, IDM_OPTIONS, MF_BYCOMMAND | MF_STRING, IDM_OPTIONS, Tr(L"選項", L"Options"));
    ModifyMenuW(g_mainMenu, IDM_QUICK_REQUEST, MF_BYCOMMAND | MF_STRING, IDM_QUICK_REQUEST, Tr(L"快速申請連線", L"Quick Request"));
    ModifyMenuW(g_mainMenu, IDM_ABOUT, MF_BYCOMMAND | MF_STRING, IDM_ABOUT, Tr(L"關於", L"About"));
    DrawMenuBar(g_mainWindow);
}

void ApplyLanguage()
{
    if (!g_mainWindow)
        return;

    SetWindowTextW(g_mainWindow, kAppName);
    SetWindowTextW(g_headerLabel, Tr(L"WireGuard 快速連線", L"Quick WireGuard Connection"));
    SetWindowTextW(g_configLabel, Tr(L"WireGuard 設定檔", L"WireGuard configuration"));
    SetWindowTextW(g_browseButton, Tr(L"瀏覽...", L"Browse..."));
    SetWindowTextW(g_editConfigButton, Tr(L"編輯", L"Edit"));
    SetWindowTextW(g_connectButton, Tr(L"連線", L"Connect"));
    SetWindowTextW(g_disconnectButton, Tr(L"中斷", L"Disconnect"));
    SetWindowTextW(g_infoLabel, Tr(L"連線資訊", L"Connection information"));
    SetWindowTextW(g_logLabel, Tr(L"執行記錄", L"Activity log"));

    UpdateMenuText();
    SetStatus(g_lastServiceState);
    UpdateConnectionInfo();
    UpdateTrayTooltip();
}

LRESULT CALLBACK AboutWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HFONT normalFont = nullptr;
    static HFONT titleFont = nullptr;
    static HFONT linkFont = nullptr;

    switch (message)
    {
    case WM_CREATE:
    {
        normalFont = CreateUiFont();

        LOGFONTW titleLf{};
        GetObjectW(normalFont, sizeof(titleLf), &titleLf);
        titleLf.lfHeight = -20;
        titleLf.lfWeight = FW_BOLD;
        titleFont = CreateFontIndirectW(&titleLf);

        LOGFONTW linkLf{};
        GetObjectW(normalFont, sizeof(linkLf), &linkLf);
        linkLf.lfUnderline = TRUE;
        linkFont = CreateFontIndirectW(&linkLf);

        HWND title = CreateWindowExW(
            0, L"STATIC", L"EasyWG Portable",
            WS_CHILD | WS_VISIBLE,
            24, 20, 500, 30,
            hwnd, nullptr, g_instance, nullptr);

        std::wstringstream info;
        info << Tr(L"版本：", L"Version: ")
             << EASYWG_VERSION_DISPLAY_W
             << L"\r\n\r\n";
        info << Tr(
            L"功能說明：\r\n"
            L"• 免傳統安裝的 WireGuard 快速連線工具\r\n"
            L"• tunnel.dll 由 EasyWG GitHub 提供\r\n"
            L"• wireguard.dll 由 WireGuard 官方來源取得\r\n"
            L"• 支援標準 .conf 與 ZIP 匯入\r\n"
            L"• 一鍵建立與清理臨時 Tunnel 服務\r\n"
            L"• 系統列常駐、開機自動啟動與啟動時自動連線\r\n"
            L"• 繁體中文 / English 介面切換\r\n"
            L"• 核心 DLL 更新檢測\r\n"
            L"• 退出程式時自動中斷 VPN\r\n\r\n"
            L"注意：.conf 可能包含明文 PrivateKey，請妥善保管。",
            L"Features:\r\n"
            L"• Portable quick WireGuard connection utility\r\n"
            L"• tunnel.dll is provided by the EasyWG GitHub release\r\n"
            L"• wireguard.dll is obtained from the official WireGuard source\r\n"
            L"• Supports standard .conf files and ZIP import\r\n"
            L"• One-click temporary tunnel service lifecycle\r\n"
            L"• System tray mode, Windows startup, and startup auto-connect\r\n"
            L"• Traditional Chinese / English UI\r\n"
            L"• Core DLL update check\r\n"
            L"• Automatically disconnects VPN when the app exits\r\n\r\n"
            L"Note: .conf files may contain a plaintext PrivateKey. Store them securely.");

        HWND body = CreateWindowExW(
            0, L"STATIC", info.str().c_str(),
            WS_CHILD | WS_VISIBLE,
            24, 58, 520, 300,
            hwnd, nullptr, g_instance, nullptr);

        HWND githubLabel = CreateWindowExW(
            0, L"STATIC",
            Tr(L"GitHub 專案首頁：", L"GitHub project:"),
            WS_CHILD | WS_VISIBLE,
            24, 370, 150, 24,
            hwnd, nullptr, g_instance, nullptr);

        HWND githubLink = CreateWindowExW(
            0, L"STATIC", kProjectUrl,
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            174, 370, 350, 24,
            hwnd, reinterpret_cast<HMENU>(IDC_ABOUT_GITHUB), g_instance, nullptr);

        HWND closeButton = CreateWindowExW(
            0, L"BUTTON", Tr(L"關閉", L"Close"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            424, 414, 100, 34,
            hwnd, reinterpret_cast<HMENU>(IDC_ABOUT_CLOSE), g_instance, nullptr);

        ApplyFont(body, normalFont);
        ApplyFont(githubLabel, normalFont);
        ApplyFont(closeButton, normalFont);
        ApplyFont(title, titleFont ? titleFont : normalFont);
        ApplyFont(githubLink, linkFont ? linkFont : normalFont);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_ABOUT_GITHUB && HIWORD(wParam) == STN_CLICKED)
        {
            ShellExecuteW(
                hwnd,
                L"open",
                kProjectUrl,
                nullptr,
                nullptr,
                SW_SHOWNORMAL);
            return 0;
        }

        if (LOWORD(wParam) == IDC_ABOUT_CLOSE)
        {
            DestroyWindow(hwnd);
            return 0;
        }
        break;

    case WM_ERASEBKGND:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        RECT rect{};
        GetClientRect(hwnd, &rect);
        FillRect(dc, &rect, GetSysColorBrush(COLOR_BTNFACE));
        return 1;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        HWND control = reinterpret_cast<HWND>(lParam);

        SetBkColor(dc, GetSysColor(COLOR_BTNFACE));
        SetBkMode(dc, OPAQUE);

        if (GetDlgCtrlID(control) == IDC_ABOUT_GITHUB)
            SetTextColor(dc, RGB(0, 102, 204));
        else
            SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));

        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE));
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (normalFont && normalFont != GetStockObject(DEFAULT_GUI_FONT))
            DeleteObject(normalFont);
        if (titleFont)
            DeleteObject(titleFont);
        if (linkFont)
            DeleteObject(linkFont);

        normalFont = nullptr;
        titleFont = nullptr;
        linkFont = nullptr;
        g_aboutWindow = nullptr;
        return 0;

    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

void ShowAbout()
{
    if (g_aboutWindow)
    {
        ShowWindow(g_aboutWindow, SW_SHOW);
        SetForegroundWindow(g_aboutWindow);
        return;
    }

    g_aboutWindow = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        kAboutClass,
        Tr(L"關於 EasyWG Portable", L"About EasyWG Portable"),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        570, 510,
        g_mainWindow,
        nullptr,
        g_instance,
        nullptr);

    if (!g_aboutWindow)
        return;

    ShowWindow(g_aboutWindow, SW_SHOW);
    UpdateWindow(g_aboutWindow);
}


int RunRestartHelper(DWORD parentPid)
{
    if (parentPid != 0)
    {
        HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
        if (parent)
        {
            WaitForSingleObject(parent, 30000);
            CloseHandle(parent);
        }
    }

    // Wait briefly so the previous UI can release the single-instance mutex
    // and any remaining DLL/file handles.
    Sleep(350);

    const std::wstring exe = GetModulePath();
    const std::wstring dir = GetModuleDirectory();
    if (exe.empty())
        return 2;

    const std::wstring command = QuoteArg(exe) + L" /restarted";

    for (int attempt = 0; attempt < 3; ++attempt)
    {
        std::vector<wchar_t> mutableCommand(command.begin(), command.end());
        mutableCommand.push_back(L'\0');

        STARTUPINFOW si{};
        si.cb = sizeof(si);

        PROCESS_INFORMATION pi{};
        if (CreateProcessW(
                exe.c_str(),
                mutableCommand.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NEW_PROCESS_GROUP,
                nullptr,
                dir.empty() ? nullptr : dir.c_str(),
                &si,
                &pi))
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 0;
        }

        Sleep(500);
    }

    const DWORD error = GetLastError();
    return static_cast<int>(error ? error : 3);
}

bool LaunchRestartHelper(std::wstring& error)
{
    const std::wstring exe = GetModulePath();
    const std::wstring dir = GetModuleDirectory();
    if (exe.empty())
    {
        error = Tr(L"無法取得程式路徑。", L"Unable to determine the application path.");
        return false;
    }

    const std::wstring command =
        QuoteArg(exe) + L" /restart-helper " + std::to_wstring(GetCurrentProcessId());

    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(
            exe.c_str(),
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_PROCESS_GROUP,
            nullptr,
            dir.empty() ? nullptr : dir.c_str(),
            &si,
            &pi))
    {
        error = Tr(L"無法建立重新啟動輔助程序：", L"Unable to create restart helper: ") +
            FormatWin32Error(GetLastError());
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

void RestartApplication()
{
    std::wstring error;
    if (!LaunchRestartHelper(error))
    {
        AppendLog(error);
        MessageBoxW(g_mainWindow, error.c_str(), kAppName, MB_ICONERROR);
        return;
    }

    g_forceExit = true;
    g_closing = true;
    DestroyWindow(g_mainWindow);
}

void StartCoreUpdate()
{
    if (g_updateRunning.exchange(true))
    {
        MessageBoxW(
            g_mainWindow,
            Tr(L"更新檢測正在執行中。", L"An update check is already running."),
            kAppName,
            MB_ICONINFORMATION);
        return;
    }

    AppendLog(Tr(L"開始檢測官方 DLL 更新。", L"Checking for official DLL updates."));
    DoDisconnect(true);

    std::thread([]()
    {
        const std::wstring appDir = GetModuleDirectory();

        if (IsWindows7OrEarlier())
        {
            std::wstring result;
            CheckWindows7CoreUpdatesNative(appDir, result);

            {
                std::lock_guard<std::mutex> lock(g_updateMutex);
                g_updateResult = result;
            }

            PostMessageW(g_mainWindow, WM_UPDATE_DONE, 0, 0);
            return;
        }

        const std::wstring resultFile = MakeTempFilePath(L"EWU");

        std::wstring result;
        std::wstring script;
        std::wstring scriptError;
        DWORD exitCode = 1;

        if (resultFile.empty())
        {
            result = L"ERROR: unable to create temporary result file";
        }
        else if (!WriteEmbeddedScriptToTemp(
                     EmbeddedScripts::kCoreUpdateScript,
                     L"EWC",
                     script,
                     scriptError))
        {
            result = L"ERROR: " + scriptError;
        }
        else
        {
            const std::wstring projectDir = fs::path(appDir).parent_path().wstring();
            const std::wstring args =
                L"-NoProfile -ExecutionPolicy Bypass -File " + QuoteArg(script) +
                L" -AppDir " + QuoteArg(appDir) +
                L" -ProjectDir " + QuoteArg(projectDir) +
                L" -ResultFile " + QuoteArg(resultFile);

            if (!RunProcessHidden(L"powershell.exe", args, 30 * 60 * 1000, exitCode))
            {
                result = L"ERROR: unable to run embedded PowerShell updater";
            }
            else
            {
                result = Trim(ReadTextFile(resultFile));
                if (result.empty())
                {
                    std::wstringstream ss;
                    ss << L"ERROR: updater exit code " << exitCode;
                    result = ss.str();
                }
            }
        }

        if (!script.empty())
            DeleteFileW(script.c_str());
        if (!resultFile.empty())
            DeleteFileW(resultFile.c_str());

        {
            std::lock_guard<std::mutex> lock(g_updateMutex);
            g_updateResult = result;
        }

        PostMessageW(g_mainWindow, WM_UPDATE_DONE, exitCode, 0);
    }).detach();
}

void HandleUpdateDone()
{
    g_updateRunning = false;

    std::wstring result;
    {
        std::lock_guard<std::mutex> lock(g_updateMutex);
        result = g_updateResult;
    }

    if (result.rfind(L"UPDATED", 0) == 0)
    {
        AppendLog(Tr(L"官方 DLL 更新完成，準備重新啟動。", L"Official DLL update completed. Restarting."));
        MessageBoxW(
            g_mainWindow,
            Tr(L"官方 DLL 已更新完成，程式將立即重新啟動。", L"Official DLL files were updated. The application will restart now."),
            kAppName,
            MB_ICONINFORMATION);
        RestartApplication();
        return;
    }

    if (result.rfind(L"NO_UPDATE", 0) == 0)
    {
        AppendLog(Tr(L"目前已是最新官方 DLL。", L"Official DLL files are already up to date."));
        MessageBoxW(
            g_mainWindow,
            Tr(L"目前已是最新官方 DLL。", L"Official DLL files are already up to date."),
            kAppName,
            MB_ICONINFORMATION);
        return;
    }

    if (result.rfind(L"TUNNEL_UPDATE_AVAILABLE", 0) == 0)
    {
        AppendLog(Tr(
            L"WireGuardNT 已處理，但 tunnel.dll 有新版且目前環境無法自動編譯。",
            L"WireGuardNT was handled, but a newer tunnel.dll requires a build environment."));
        MessageBoxW(
            g_mainWindow,
            Tr(
                L"偵測到新版 tunnel.dll 上游原碼，但目前找不到可用的原碼編譯腳本。\r\n"
                L"若在完整原碼目錄中執行，可透過 update_official_core.bat 自動編譯更新。",
                L"A newer tunnel.dll upstream revision was detected, but no usable source build script is available.\r\n"
                L"In the full source tree, update_official_core.bat can build and update it."),
            kAppName,
            MB_ICONWARNING);
        return;
    }

    AppendLog(Tr(L"官方 DLL 更新檢測失敗：", L"Official DLL update check failed: ") + result);
    MessageBoxW(
        g_mainWindow,
        (Tr(L"官方 DLL 更新檢測失敗：\r\n", L"Official DLL update check failed:\r\n") + result).c_str(),
        kAppName,
        MB_ICONERROR);
}

void CreateMainMenu()
{
    g_mainMenu = CreateMenu();
    AppendMenuW(g_mainMenu, MF_STRING, IDM_OPTIONS, Tr(L"選項", L"Options"));
    AppendMenuW(g_mainMenu, MF_STRING, IDM_QUICK_REQUEST, Tr(L"快速申請連線", L"Quick Request"));
    AppendMenuW(g_mainMenu, MF_STRING, IDM_ABOUT, Tr(L"關於", L"About"));
}

void UpdateOptionsDependencies()
{
    if (!g_optionsWindow)
        return;

    const bool autostart = SendMessageW(g_optAutostart, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (autostart)
        SendMessageW(g_optStayTray, BM_SETCHECK, BST_CHECKED, 0);
    EnableWindow(g_optStayTray, autostart ? FALSE : TRUE);

    const bool hasConfig = !IsTemporarySelection() &&
                           IsUsableConfPath(GetControlText(g_configEdit));
    if (!hasConfig)
        SendMessageW(g_optAutoConnect, BM_SETCHECK, BST_UNCHECKED, 0);
    EnableWindow(g_optAutoConnect, hasConfig ? TRUE : FALSE);
}

void SaveOptions()
{
    Settings updated = g_settings;
    updated.autostart = SendMessageW(g_optAutostart, BM_GETCHECK, 0, 0) == BST_CHECKED;
    updated.stayTray = SendMessageW(g_optStayTray, BM_GETCHECK, 0, 0) == BST_CHECKED;
    updated.autoConnect = SendMessageW(g_optAutoConnect, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (updated.autostart)
        updated.stayTray = true;

    if (updated.autoConnect && !IsUsableConfPath(GetControlText(g_configEdit)))
        updated.autoConnect = false;

    const int languageIndex = static_cast<int>(SendMessageW(g_optLanguage, CB_GETCURSEL, 0, 0));
    updated.language = languageIndex == 1 ? Language::English : Language::ZhTW;
    if (!IsTemporarySelection())
        updated.lastConfig = ConfigPathForStorage(ResolveConfigPath(GetControlText(g_configEdit)));
    else
        updated.autoConnect = false;

    std::wstring error;
    if (!SetAutostartRegistry(updated.autostart, error))
    {
        MessageBoxW(g_optionsWindow, error.c_str(), kAppName, MB_ICONERROR);
        return;
    }

    const Settings previous = g_settings;
    g_settings = updated;

    if (!SaveSettings())
    {
        g_settings = previous;
        std::wstring rollbackError;
        SetAutostartRegistry(previous.autostart, rollbackError);

        MessageBoxW(
            g_optionsWindow,
            Tr(
                L"無法儲存 EasyWG.ini。請確認程式目錄可寫入。",
                L"Unable to save EasyWG.ini. Make sure the application directory is writable."),
            kAppName,
            MB_ICONERROR);
        return;
    }

    ApplyLanguage();
    AppendLog(Tr(L"設定已儲存到 EasyWG.ini。", L"Settings saved to EasyWG.ini."));
    DestroyWindow(g_optionsWindow);
}

void ApplyOptionsLanguage()
{
    if (!g_optionsWindow)
        return;

    SetWindowTextW(g_optionsWindow, Tr(L"EasyWG 選項", L"EasyWG Options"));
    SetWindowTextW(g_optAutostart, Tr(L"開機自動啟動（背景系統列常駐）", L"Start with Windows (background tray mode)"));
    SetWindowTextW(g_optStayTray, Tr(L"關閉主視窗時常駐系統列", L"Keep running in tray when main window closes"));
    SetWindowTextW(g_optAutoConnect, Tr(L"啟動時自動連線（已有設定檔）", L"Connect automatically at startup (existing config)"));
    SetWindowTextW(g_optLanguageLabel, Tr(L"介面語言", L"Interface language"));
    SetWindowTextW(
        g_optUpdate,
        IsWindows7OrEarlier()
            ? Tr(L"檢測 Win7 核心 DLL 更新", L"Check Windows 7 core DLL updates")
            : Tr(L"檢測官方 DLL 更新", L"Check official DLL updates"));
    SetWindowTextW(g_optSave, Tr(L"儲存設定", L"Save Settings"));
    SetWindowTextW(g_optCancel, Tr(L"取消", L"Cancel"));
    SetWindowTextW(g_optHint, Tr(
        L"開啟自動啟動時，系統列常駐會強制啟用且不可關閉。",
        L"When startup is enabled, tray residency is forced on and cannot be disabled."));
}

LRESULT CALLBACK OptionsWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HFONT normalFont = nullptr;
    static HFONT titleFont = nullptr;

    switch (message)
    {
    case WM_CREATE:
    {
        g_optionsWindow = hwnd;
        normalFont = CreateUiFont(9, false);
        titleFont = CreateUiFont(10, true);

        HWND title = CreateWindowExW(
            0, L"STATIC", Tr(L"程式設定", L"Application Settings"),
            WS_CHILD | WS_VISIBLE,
            22, 18, 420, 24,
            hwnd, nullptr, g_instance, nullptr);

        g_optAutostart = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            24, 58, 410, 26,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_AUTOSTART), g_instance, nullptr);

        g_optStayTray = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            24, 92, 410, 26,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_STAYTRAY), g_instance, nullptr);

        g_optAutoConnect = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            24, 126, 410, 26,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_AUTOCONNECT), g_instance, nullptr);

        g_optHint = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
            43, 154, 390, 58,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_HINT), g_instance, nullptr);

        g_optLanguageLabel = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE,
            24, 226, 120, 24,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_LANGUAGE_LABEL), g_instance, nullptr);

        g_optLanguage = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
            152, 222, 210, 200,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_LANGUAGE), g_instance, nullptr);

        SendMessageW(g_optLanguage, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"繁體中文"));
        SendMessageW(g_optLanguage, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"English"));
        SendMessageW(g_optLanguage, CB_SETCURSEL,
            g_settings.language == Language::English ? 1 : 0, 0);

        g_optUpdate = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            24, 272, 210, 34,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_UPDATE), g_instance, nullptr);

        g_optSave = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            238, 334, 100, 34,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_SAVE), g_instance, nullptr);

        g_optCancel = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            348, 334, 100, 34,
            hwnd, reinterpret_cast<HMENU>(IDC_OPT_CANCEL), g_instance, nullptr);

        for (HWND control : { g_optAutostart, g_optStayTray, g_optAutoConnect,
                              g_optHint, g_optLanguageLabel, g_optLanguage,
                              g_optUpdate, g_optSave, g_optCancel })
        {
            ApplyFont(control, normalFont);
        }
        ApplyFont(title, titleFont);

        SendMessageW(g_optAutostart, BM_SETCHECK, g_settings.autostart ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(g_optStayTray, BM_SETCHECK, g_settings.stayTray ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(g_optAutoConnect, BM_SETCHECK, g_settings.autoConnect ? BST_CHECKED : BST_UNCHECKED, 0);

        ApplyOptionsLanguage();
        UpdateOptionsDependencies();
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_OPT_AUTOSTART:
            UpdateOptionsDependencies();
            return 0;

        case IDC_OPT_AUTOCONNECT:
            UpdateOptionsDependencies();
            return 0;

        case IDC_OPT_SAVE:
            SaveOptions();
            return 0;

        case IDC_OPT_CANCEL:
            DestroyWindow(hwnd);
            return 0;

        case IDC_OPT_UPDATE:
            DestroyWindow(hwnd);
            StartCoreUpdate();
            return 0;

        default:
            break;
        }
        break;

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, g_textColor);
        return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
    }

    case WM_ERASEBKGND:
    {
        RECT rc{};
        GetClientRect(hwnd, &rc);
        HBRUSH brush = CreateSolidBrush(g_backgroundColor);
        FillRect(reinterpret_cast<HDC>(wParam), &rc, brush);
        DeleteObject(brush);
        return 1;
    }

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        g_optionsWindow = nullptr;
        g_optAutostart = nullptr;
        g_optStayTray = nullptr;
        g_optAutoConnect = nullptr;
        g_optLanguage = nullptr;
        g_optUpdate = nullptr;
        g_optSave = nullptr;
        g_optCancel = nullptr;
        g_optLanguageLabel = nullptr;
        g_optHint = nullptr;

        if (normalFont)
        {
            DeleteObject(normalFont);
            normalFont = nullptr;
        }
        if (titleFont)
        {
            DeleteObject(titleFont);
            titleFont = nullptr;
        }
        return 0;

    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

void ShowOptions()
{
    if (g_optionsWindow)
    {
        ShowWindow(g_optionsWindow, SW_SHOW);
        SetForegroundWindow(g_optionsWindow);
        return;
    }

    HWND window = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        kOptionsClass,
        Tr(L"EasyWG 選項", L"EasyWG Options"),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        490, 430,
        g_mainWindow, nullptr, g_instance, nullptr);

    if (!window)
        return;

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
}

void DrawCard(HDC dc, const RECT& rc)
{
    HBRUSH brush = CreateSolidBrush(g_cardColor);
    HPEN pen = CreatePen(PS_SOLID, 1, g_borderColor);
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen = SelectObject(dc, pen);

    RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, 12, 12);

    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);
}

void ExitApplication()
{
    g_forceExit = true;
    g_closing = true;
    DoDisconnect(true);
    if (!g_temporaryConfigPath.empty())
    {
        DeleteFileW(g_temporaryConfigPath.c_str());
        g_temporaryConfigPath.clear();
    }
    DestroyWindow(g_mainWindow);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HFONT normalFont = nullptr;
    static HFONT titleFont = nullptr;
    static HBRUSH editBrush = nullptr;

    switch (message)
    {
    case WM_CREATE:
    {
        g_mainWindow = hwnd;
        normalFont = CreateUiFont(9, false);
        titleFont = CreateUiFont(IsWindows7OrEarlier() ? 13 : 14, true);
        editBrush = CreateSolidBrush(g_cardColor);

        g_headerLabel = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
            20, 10, 540, 40,
            hwnd, reinterpret_cast<HMENU>(IDC_HEADER), g_instance, nullptr);

        g_configLabel = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE,
            32, 68, 240, 22,
            hwnd, reinterpret_cast<HMENU>(IDC_CONFIG_LABEL), g_instance, nullptr);

        const std::wstring initialDisplay = ConfigPathForDisplay(g_initialConfig);
        g_configEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", initialDisplay.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            32, 92, 575, 28,
            hwnd, reinterpret_cast<HMENU>(IDC_CONFIG), g_instance, nullptr);

        g_browseButton = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            617, 91, 108, 30,
            hwnd, reinterpret_cast<HMENU>(IDC_BROWSE), g_instance, nullptr);

        g_editConfigButton = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            617, 136, 108, 38,
            hwnd, reinterpret_cast<HMENU>(IDC_EDIT_CONFIG), g_instance, nullptr);

        g_connectButton = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            32, 136, 120, 38,
            hwnd, reinterpret_cast<HMENU>(IDC_CONNECT), g_instance, nullptr);

        g_disconnectButton = CreateWindowExW(
            0, L"BUTTON", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            162, 136, 120, 38,
            hwnd, reinterpret_cast<HMENU>(IDC_DISCONNECT), g_instance, nullptr);

        g_statusLabel = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE,
            316, 145, 240, 25,
            hwnd, reinterpret_cast<HMENU>(IDC_STATUS), g_instance, nullptr);

        g_infoLabel = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE,
            32, 190, 240, 22,
            hwnd, reinterpret_cast<HMENU>(IDC_INFO_LABEL), g_instance, nullptr);

        g_infoEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            32, 214, 693, 116,
            hwnd, reinterpret_cast<HMENU>(IDC_INFO), g_instance, nullptr);

        g_logLabel = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
            32, 368, 240, 22,
            hwnd, reinterpret_cast<HMENU>(IDC_LOG_LABEL), g_instance, nullptr);

        g_logEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            32, 392, 693, 112,
            hwnd, reinterpret_cast<HMENU>(IDC_LOG), g_instance, nullptr);

        for (HWND control : { g_configLabel, g_configEdit, g_browseButton, g_editConfigButton,
                              g_connectButton, g_disconnectButton, g_statusLabel, g_infoLabel, g_infoEdit,
                              g_logLabel, g_logEdit })
        {
            ApplyFont(control, normalFont);
        }
        ApplyFont(g_headerLabel, titleFont);

        EnableWindow(g_disconnectButton, FALSE);
        DragAcceptFiles(hwnd, TRUE);
        SetTimer(hwnd, kStatusTimerId, 1000, nullptr);

        AddTrayIcon();
        ApplyLanguage();

        AppendLog(Tr(
            L"程式啟動。可選擇或拖入 .conf / .zip。",
            L"Application started. Select or drop a .conf / .zip file."));
        AppendLog(Tr(
            L"連線時才會要求系統管理員權限；背景常駐本身不需提權。",
            L"Administrator rights are requested only when creating a tunnel; tray residency itself is not elevated."));

        if (!g_initialConfig.empty())
        {
            const std::wstring initialExt = ToLower(fs::path(g_initialConfig).extension().wstring());
            if (initialExt == L".zip")
                SelectConfigOrZip(g_initialConfig);
            else
                UpdateConnectionInfo();
        }

        if (g_autoConnectDisabledMissing)
        {
            AppendLog(
                Tr(L"自動連線設定已取消：找不到設定檔：",
                   L"Auto-connect was disabled because the configuration file was not found: ") +
                g_missingAutoConnectConfig);
        }

        if (g_settings.autoConnect)
            PostMessageW(hwnd, WM_AUTO_CONNECT, 0, 0);

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BROWSE:
            BrowseForConfig(hwnd);
            return 0;

        case IDC_EDIT_CONFIG:
            EditCurrentConfig();
            return 0;

        case IDC_CONNECT:
            DoConnect();
            return 0;

        case IDC_DISCONNECT:
            DoDisconnect(false);
            return 0;

        case IDM_OPTIONS:
            ShowOptions();
            return 0;

        case IDM_QUICK_REQUEST:
            ShowQuickRequest();
            return 0;

        case IDM_ABOUT:
            ShowAbout();
            return 0;

        case IDM_TRAY_SHOW:
            ShowMainWindow();
            return 0;

        case IDM_TRAY_EXIT:
            ExitApplication();
            return 0;

        default:
            break;
        }
        break;

    case WM_DROPFILES:
    {
        HDROP drop = reinterpret_cast<HDROP>(wParam);
        wchar_t path[32768]{};
        if (DragQueryFileW(drop, 0, path, static_cast<UINT>(std::size(path))))
            SelectConfigOrZip(path);
        DragFinish(drop);
        return 0;
    }

    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU)
        {
            ShowTrayMenu();
            return 0;
        }
        if (lParam == WM_LBUTTONDBLCLK)
        {
            ShowMainWindow();
            return 0;
        }
        break;

    case WM_TIMER:
        if (wParam == kStatusTimerId)
            RefreshStatus();
        return 0;

    case WM_UPDATE_DONE:
        HandleUpdateDone();
        return 0;

    case WM_AUTO_CONNECT:
    {
        if (!g_settings.autoConnect)
            return 0;

        const std::wstring configPath = ResolveConfigPath(GetControlText(g_configEdit));
        if (!IsUsableConfPath(configPath))
        {
            g_settings.autoConnect = false;
            SaveSettings();
            AppendLog(Tr(
                L"啟動時自動連線已取消：設定檔不存在或不是 .conf。",
                L"Startup auto-connect was disabled because the configuration is missing or is not a .conf file."));
            return 0;
        }

        AppendLog(Tr(
            L"啟動時自動連線：準備連線。",
            L"Startup auto-connect: preparing connection."));
        DoConnect();
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        HWND control = reinterpret_cast<HWND>(lParam);

        if (control == g_infoEdit || control == g_logEdit)
        {
            SetBkMode(dc, OPAQUE);
            SetBkColor(dc, g_cardColor);
            SetTextColor(dc, g_textColor);
            return reinterpret_cast<LRESULT>(editBrush);
        }

        if (control == g_statusLabel)
        {
            // The status label used a transparent NULL_BRUSH background. When
            // the text changed (for example Starting -> Connected), some DPI /
            // theme combinations left the previous glyphs behind and made the
            // green status look overlapped. Paint the whole label background
            // opaquely with the card colour before drawing the new state.
            SetBkMode(dc, OPAQUE);
            SetBkColor(dc, g_cardColor);
            if (g_lastServiceState == SERVICE_RUNNING)
                SetTextColor(dc, g_statusOnlineColor);
            else if (g_lastServiceState == SERVICE_START_PENDING || g_lastServiceState == SERVICE_STOP_PENDING)
                SetTextColor(dc, g_statusPendingColor);
            else
                SetTextColor(dc, g_statusOfflineColor);
            return reinterpret_cast<LRESULT>(editBrush);
        }

        SetBkMode(dc, TRANSPARENT);

        if (control == g_configLabel || control == g_infoLabel || control == g_logLabel)
        {
            SetTextColor(dc, g_mutedTextColor);
        }
        else
        {
            SetTextColor(dc, g_textColor);
        }

        return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
    }

    case WM_CTLCOLOREDIT:
    {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetBkColor(dc, g_cardColor);
        SetTextColor(dc, g_textColor);
        return reinterpret_cast<LRESULT>(editBrush);
    }

    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);

        RECT client{};
        GetClientRect(hwnd, &client);
        HBRUSH background = CreateSolidBrush(g_backgroundColor);
        FillRect(dc, &client, background);
        DeleteObject(background);

        RECT card1{ 16, 52, 742, 350 };
        RECT card2{ 16, 364, 742, 546 };
        DrawCard(dc, card1);
        DrawCard(dc, card2);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_CLOSE:
        if (g_forceExit || (!g_settings.stayTray && !g_settings.autostart))
        {
            ExitApplication();
        }
        else
        {
            ShowWindow(hwnd, SW_HIDE);
            AppendLog(Tr(L"主視窗已隱藏，程式繼續常駐系統列。", L"Main window hidden; the application remains in the system tray."));
        }
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, kStatusTimerId);
        RemoveTrayIcon();

        if (normalFont)
        {
            DeleteObject(normalFont);
            normalFont = nullptr;
        }
        if (titleFont)
        {
            DeleteObject(titleFont);
            titleFont = nullptr;
        }
        if (editBrush)
        {
            DeleteObject(editBrush);
            editBrush = nullptr;
        }

        if (!g_temporaryConfigPath.empty())
        {
            DeleteFileW(g_temporaryConfigPath.c_str());
            g_temporaryConfigPath.clear();
        }
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

int RunServiceMode(const std::wstring& configPath, DWORD parentPid)
{
    const std::wstring moduleDir = GetModuleDirectory();
    if (moduleDir.empty())
        return 10;

    const bool legacyWin7 = IsWindows7OrEarlier();

    if (legacyWin7)
    {
        AppendWindows7ServiceDebug(
            L"RunServiceMode start. Config=" + configPath);
    }

    const std::wstring tunnelDllPath = legacyWin7
        ? (fs::path(moduleDir) / L"tunnel-win7.dll").wstring()
        : (fs::path(moduleDir) / L"tunnel.dll").wstring();

    const std::wstring dependencyDllPath = legacyWin7
        ? (fs::path(moduleDir) / L"wintun.dll").wstring()
        : (fs::path(moduleDir) / L"wireguard.dll").wstring();

    if (!FileExists(tunnelDllPath) || !FileExists(dependencyDllPath))
    {
        if (legacyWin7)
        {
            AppendWindows7ServiceDebug(
                L"Required DLL missing. Tunnel=" + tunnelDllPath +
                L" Dependency=" + dependencyDllPath);
        }
        return 11;
    }

    const std::wstring serviceName = ServiceNameFromConfig(configPath);

    if (parentPid != 0)
    {
        std::thread parentWatcher(WatchParentAndCleanup, parentPid, serviceName);
        parentWatcher.detach();
    }

    std::thread eventWatcher(WatchStopEventAndCleanup, serviceName);
    eventWatcher.detach();

    SetCurrentDirectoryW(moduleDir.c_str());
    SetDllDirectoryW(moduleDir.c_str());

    HMODULE tunnel = LoadLibraryW(tunnelDllPath.c_str());
    const DWORD loadError = tunnel ? ERROR_SUCCESS : GetLastError();

    SetDllDirectoryW(nullptr);

    if (!tunnel)
    {
        if (legacyWin7)
        {
            AppendWindows7ServiceDebug(
                L"LoadLibrary failed. Error=" +
                std::to_wstring(loadError));
        }
        return static_cast<int>(loadError ? loadError : 12);
    }

    if (legacyWin7)
    {
        using ForceLegacyProc = void(__cdecl*)(BOOL);
        auto forceLegacy = reinterpret_cast<ForceLegacyProc>(
            GetProcAddress(tunnel, "WireGuardForceLegacyImplementation"));

        if (!forceLegacy)
        {
            AppendWindows7ServiceDebug(
                L"WireGuardForceLegacyImplementation export not found.");
            FreeLibrary(tunnel);
            return 15;
        }

        AppendWindows7ServiceDebug(
            L"Calling WireGuardForceLegacyImplementation(TRUE).");
        forceLegacy(TRUE);
    }

    using TunnelServiceProc = BOOL(__cdecl*)(LPCWSTR);
    auto proc = reinterpret_cast<TunnelServiceProc>(
        GetProcAddress(tunnel, "WireGuardTunnelService"));

    if (!proc)
    {
        const DWORD e = GetLastError();
        if (legacyWin7)
        {
            AppendWindows7ServiceDebug(
                L"WireGuardTunnelService export not found. Error=" +
                std::to_wstring(e));
        }
        FreeLibrary(tunnel);
        return static_cast<int>(e ? e : 13);
    }

    if (legacyWin7)
    {
        AppendWindows7ServiceDebug(
            L"Calling WireGuardTunnelService.");
    }

    const BOOL result = proc(configPath.c_str());

    if (legacyWin7)
    {
        AppendWindows7ServiceDebug(
            std::wstring(L"WireGuardTunnelService returned ") +
            (result ? L"TRUE" : L"FALSE"));
    }

    FreeLibrary(tunnel);
    return result ? 0 : 14;
}

int RunElevatedStart(const std::wstring& configPath, DWORD parentPid)
{
    if (!IsProcessElevated())
        return 5;

    std::wstring serviceName;
    std::wstring error;

    // CreateAndStartTunnelService embeds the current process ID as watcher parent.
    // For the elevated helper we need the non-elevated UI PID, so create service here
    // with a temporary global override by directly reproducing the command line behavior.
    serviceName = ServiceNameFromConfig(configPath);

    std::wstring serviceConfigPath = configPath;
    if (IsWindows7OrEarlier())
    {
        if (!StageConfigForWindows7Service(
                configPath,
                serviceConfigPath,
                error))
        {
            return 16;
        }
    }

    std::wstring cleanupError;
    StopAndDeleteService(serviceName, true, &cleanupError);

    const std::wstring exePath = GetModulePath();
    const std::wstring commandLine =
        QuoteArg(exePath) + L" /service " + QuoteArg(serviceConfigPath) + L" " +
        std::to_wstring(parentPid);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm)
        return 6;

    const wchar_t dependencies[] = L"Nsi\0TcpIp\0";
    const std::wstring displayName = std::wstring(kAppName) + L": " + TunnelNameFromConfig(configPath);

    SC_HANDLE service = CreateServiceW(
        scm, serviceName.c_str(), displayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, commandLine.c_str(),
        nullptr, nullptr, dependencies, nullptr, nullptr);

    if (!service)
    {
        CloseServiceHandle(scm);
        return 7;
    }

    SERVICE_SID_INFO sidInfo{};
    sidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo))
    {
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 8;
    }

    if (!StartServiceW(service, 0, nullptr))
    {
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 9;
    }

    DWORD lastState = SERVICE_START_PENDING;
    const bool running = WaitForServiceState(service, SERVICE_RUNNING, 20000, lastState);
    if (!running)
    {
        SERVICE_STATUS stopStatus{};
        ControlService(service, SERVICE_CONTROL_STOP, &stopStatus);
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 10;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

int RunElevatedStop(const std::wstring& serviceName)
{
    if (!IsProcessElevated())
        return 5;

    std::wstring error;
    return StopAndDeleteService(serviceName, true, &error) ? 0 : 6;
}

bool RegisterWindowClasses()
{
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = g_instance;
    wc.lpszClassName = kWindowClass;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = nullptr;

    if (!RegisterClassExW(&wc))
        return false;

    WNDCLASSEXW options{};
    options.cbSize = sizeof(options);
    options.lpfnWndProc = OptionsWindowProc;
    options.hInstance = g_instance;
    options.lpszClassName = kOptionsClass;
    options.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    options.hIcon = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    options.hIconSm = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    options.hbrBackground = CreateSolidBrush(g_backgroundColor);

    if (!RegisterClassExW(&options))
        return false;

    WNDCLASSEXW bootstrap{};
    bootstrap.cbSize = sizeof(bootstrap);
    bootstrap.lpfnWndProc = BootstrapWindowProc;
    bootstrap.hInstance = g_instance;
    bootstrap.lpszClassName = kBootstrapClass;
    bootstrap.hCursor = LoadCursorW(nullptr, IDC_WAIT);
    bootstrap.hIcon = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    bootstrap.hIconSm = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    bootstrap.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);

    if (!RegisterClassExW(&bootstrap))
        return false;

    WNDCLASSEXW about{};
    about.cbSize = sizeof(about);
    about.lpfnWndProc = AboutWindowProc;
    about.hInstance = g_instance;
    about.lpszClassName = kAboutClass;
    about.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    about.hIcon = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    about.hIconSm = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    about.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);

    if (!RegisterClassExW(&about))
        return false;

    WNDCLASSEXW request{};
    request.cbSize = sizeof(request);
    request.lpfnWndProc = RequestWindowProc;
    request.hInstance = g_instance;
    request.lpszClassName = kRequestClass;
    request.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    request.hIcon = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    request.hIconSm = g_appIcon ? g_appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    request.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);

    if (!RegisterClassExW(&request))
        return false;

    return true;
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
    SetProcessDPIAware();
    g_instance = instance;
    g_appIcon = static_cast<HICON>(LoadImageW(
        instance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE));

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return 1;

    if (argc >= 3 && _wcsicmp(argv[1], L"/service") == 0)
    {
        const std::wstring configPath = argv[2];
        DWORD parentPid = 0;
        if (argc >= 4)
            parentPid = wcstoul(argv[3], nullptr, 10);

        LocalFree(argv);
        return RunServiceMode(configPath, parentPid);
    }

    if (argc >= 4 && _wcsicmp(argv[1], L"/elevated-start") == 0)
    {
        const std::wstring configPath = argv[2];
        const DWORD parentPid = wcstoul(argv[3], nullptr, 10);
        LocalFree(argv);
        return RunElevatedStart(configPath, parentPid);
    }

    if (argc >= 3 && _wcsicmp(argv[1], L"/elevated-stop") == 0)
    {
        const std::wstring serviceName = argv[2];
        LocalFree(argv);
        return RunElevatedStop(serviceName);
    }

    if (argc >= 3 && _wcsicmp(argv[1], L"/restart-helper") == 0)
    {
        const DWORD parentPid = wcstoul(argv[2], nullptr, 10);
        LocalFree(argv);
        return RunRestartHelper(parentPid);
    }

    LoadSettings();

    bool autostartLaunch = false;
    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"/autostart") == 0)
        {
            autostartLaunch = true;
            continue;
        }

        if (_wcsicmp(argv[i], L"/restarted") == 0)
            continue;

        const std::wstring candidate = FullPath(argv[i]);
        const std::wstring ext = ToLower(fs::path(candidate).extension().wstring());
        if (ext == L".conf" || ext == L".zip")
            g_initialConfig = candidate;
    }

    if (g_initialConfig.empty() && !g_settings.lastConfig.empty())
    {
        const std::wstring resolvedLastConfig = ResolveConfigPath(g_settings.lastConfig);
        if (FileExists(resolvedLastConfig))
            g_initialConfig = resolvedLastConfig;
    }

    if (g_settings.autoConnect)
    {
        const bool hasStartupConfig =
            !g_initialConfig.empty() &&
            FileExists(ResolveConfigPath(g_initialConfig)) &&
            (ToLower(fs::path(ResolveConfigPath(g_initialConfig)).extension().wstring()) == L".conf" ||
             ToLower(fs::path(ResolveConfigPath(g_initialConfig)).extension().wstring()) == L".zip");

        if (!hasStartupConfig)
        {
            g_autoConnectDisabledMissing = true;
            g_missingAutoConnectConfig = g_settings.lastConfig;
            g_settings.autoConnect = false;
            SaveSettings();
        }
    }

    LocalFree(argv);

    g_singleInstance = CreateMutexW(nullptr, TRUE, kSingleInstanceName);
    if (g_singleInstance && GetLastError() == ERROR_ALREADY_EXISTS)
    {
        HWND existing = FindWindowW(kWindowClass, nullptr);
        if (existing)
        {
            ShowWindow(existing, SW_SHOW);
            SetForegroundWindow(existing);
        }
        CloseHandle(g_singleInstance);
        return 0;
    }

    CleanupStaleTemporaryConfigs();

    if (!RegisterWindowClasses())
        return 2;

    std::wstring coreError;
    if (!EnsureCoreComponentsAtStartup(coreError))
    {
        MessageBoxW(
            nullptr,
            coreError.c_str(),
            kAppName,
            MB_ICONERROR | MB_OK);

        if (g_singleInstance)
        {
            CloseHandle(g_singleInstance);
            g_singleInstance = nullptr;
        }
        return 4;
    }

    CreateMainMenu();

    HWND window = CreateWindowExW(
        0,
        kWindowClass,
        kAppName,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        780, 610,
        nullptr, g_mainMenu, instance, nullptr);

    if (!window)
        return 3;

    if (!autostartLaunch)
    {
        ShowWindow(window, showCommand);
        UpdateWindow(window);
    }

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        if ((!g_optionsWindow || !IsDialogMessageW(g_optionsWindow, &msg)) &&
            (!g_requestWindow || !IsDialogMessageW(g_requestWindow, &msg)))
        {
            if (!IsDialogMessageW(window, &msg))
            {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    if (g_singleInstance)
    {
        CloseHandle(g_singleInstance);
        g_singleInstance = nullptr;
    }

    return static_cast<int>(msg.wParam);
}
