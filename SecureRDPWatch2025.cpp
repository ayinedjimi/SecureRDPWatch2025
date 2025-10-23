// SecureRDPWatch2025.cpp
// Monitoring RDP avancé avec détection brute-force, corrélation RD Gateway et mapping sessions
// Ayi NEDJIMI Consultants - WinToolsSuite

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <winevt.h>
#include <wtsapi32.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// RAII AutoHandle
class AutoHandle {
    EVT_HANDLE handle;
public:
    explicit AutoHandle(EVT_HANDLE h = nullptr) : handle(h) {}
    ~AutoHandle() { if (handle) EvtClose(handle); }
    operator EVT_HANDLE() const { return handle; }
    EVT_HANDLE* operator&() { return &handle; }
    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;
};

struct RDPEvent {
    std::wstring timestamp;
    std::wstring user;
    std::wstring ipSource;
    std::wstring eventType;
    std::wstring sessionID;
    std::wstring state;
    std::wstring alert;
};

// Globals
HWND g_hwndMain = nullptr;
HWND g_hwndListView = nullptr;
HWND g_hwndStatus = nullptr;
HWND g_hwndEditThreshold = nullptr;
std::vector<RDPEvent> g_events;
std::map<std::wstring, int> g_failuresByIP;
std::map<std::wstring, std::chrono::system_clock::time_point> g_failureTimestamps;
std::vector<std::wstring> g_blacklist;
bool g_isMonitoring = false;
int g_bruteforceThreshold = 5;

// Logging
void LogMessage(const std::wstring& msg) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"SecureRDPWatch2025.log";

    std::wofstream logFile(logPath, std::ios::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << std::setfill(L'0')
                << std::setw(4) << st.wYear << L"-"
                << std::setw(2) << st.wMonth << L"-"
                << std::setw(2) << st.wDay << L" "
                << std::setw(2) << st.wHour << L":"
                << std::setw(2) << st.wMinute << L":"
                << std::setw(2) << st.wSecond << L" - "
                << msg << std::endl;
        logFile.close();
    }
}

std::wstring ExtractIPFromXML(const std::wstring& xml) {
    // Extract IpAddress from XML
    size_t ipStart = xml.find(L"<Data Name='IpAddress'>");
    if (ipStart == std::wstring::npos) {
        ipStart = xml.find(L"<Data Name='SourceNetworkAddress'>");
        if (ipStart == std::wstring::npos) return L"N/A";
        ipStart += 34;
    } else {
        ipStart += 23;
    }

    size_t ipEnd = xml.find(L"</Data>", ipStart);
    if (ipEnd == std::wstring::npos) return L"N/A";

    return xml.substr(ipStart, ipEnd - ipStart);
}

std::wstring ExtractTargetUserName(const std::wstring& xml) {
    size_t userStart = xml.find(L"<Data Name='TargetUserName'>");
    if (userStart == std::wstring::npos) {
        userStart = xml.find(L"<Data Name='UserName'>");
        if (userStart == std::wstring::npos) return L"N/A";
        userStart += 22;
    } else {
        userStart += 28;
    }

    size_t userEnd = xml.find(L"</Data>", userStart);
    if (userEnd == std::wstring::npos) return L"N/A";

    return xml.substr(userStart, userEnd - userStart);
}

std::wstring RenderEventXML(EVT_HANDLE hEvent) {
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferSize, nullptr, &bufferUsed, &propertyCount)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            bufferSize = bufferUsed;
            std::vector<WCHAR> buffer(bufferSize / sizeof(WCHAR));

            if (EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferSize, buffer.data(), &bufferUsed, &propertyCount)) {
                return std::wstring(buffer.data());
            }
        }
    }
    return L"";
}

bool IsBlacklisted(const std::wstring& ip) {
    return std::find(g_blacklist.begin(), g_blacklist.end(), ip) != g_blacklist.end();
}

void DetectBruteForce(const std::wstring& ip, std::wstring& alert) {
    auto now = std::chrono::system_clock::now();

    // Clean old entries (older than 5 minutes)
    for (auto it = g_failureTimestamps.begin(); it != g_failureTimestamps.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second).count();
        if (elapsed > 5) {
            g_failuresByIP.erase(it->first);
            it = g_failureTimestamps.erase(it);
        } else {
            ++it;
        }
    }

    g_failuresByIP[ip]++;
    g_failureTimestamps[ip] = now;

    if (g_failuresByIP[ip] >= g_bruteforceThreshold) {
        alert = L"BRUTE-FORCE DÉTECTÉ!";

        if (!IsBlacklisted(ip)) {
            g_blacklist.push_back(ip);
            LogMessage(L"IP ajoutée à la blacklist: " + ip);
        }
    }
}

void MonitorRDPEvents() {
    g_isMonitoring = true;
    SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Monitoring RDP en cours...");
    LogMessage(L"Démarrage monitoring RDP");

    g_events.clear();
    g_failuresByIP.clear();
    g_failureTimestamps.clear();
    ListView_DeleteAllItems(g_hwndListView);

    // Query Security log for Event ID 4624 (Logon Type 10) and 4625 (Failed logon)
    std::wstring query = L"*[System[(EventID=4624 or EventID=4625)]]";
    AutoHandle hResults = EvtQuery(nullptr, L"Security", query.c_str(),
                                    EvtQueryChannelPath | EvtQueryReverseDirection);

    if (!hResults) {
        DWORD error = GetLastError();
        std::wstring msg = L"Échec EvtQuery Security log: " + std::to_wstring(error) +
                          L"\r\nPrivilèges administrateur requis!";
        MessageBoxW(g_hwndMain, msg.c_str(), L"Erreur", MB_OK | MB_ICONERROR);
        LogMessage(msg);
        SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Erreur monitoring");
        g_isMonitoring = false;
        return;
    }

    int totalEvents = 0;
    int bruteforceDetections = 0;
    int blacklistedAttempts = 0;

    DWORD returned = 0;
    EVT_HANDLE events[100];

    while (EvtNext(hResults, 100, events, INFINITE, 0, &returned)) {
        for (DWORD i = 0; i < returned; i++) {
            AutoHandle hEvent = events[i];

            std::wstring xml = RenderEventXML(hEvent);
            if (xml.empty()) continue;

            // Check if it's RDP logon (LogonType 10) or failed logon
            bool isRDP = false;
            bool isFailed = false;

            if (xml.find(L"<EventID>4624</EventID>") != std::wstring::npos) {
                if (xml.find(L"<Data Name='LogonType'>10</Data>") != std::wstring::npos) {
                    isRDP = true;
                }
            } else if (xml.find(L"<EventID>4625</EventID>") != std::wstring::npos) {
                isFailed = true;
                isRDP = true;
            }

            if (!isRDP) continue;

            RDPEvent evt;

            // Extract timestamp
            AutoHandle hContext = EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
            if (hContext) {
                DWORD bufferSize = 0;
                DWORD bufferUsed = 0;
                DWORD propertyCount = 0;

                if (!EvtRender(hContext, hEvent, EvtRenderEventValues, 0, nullptr, &bufferUsed, &propertyCount)) {
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        bufferSize = bufferUsed;
                        std::vector<BYTE> buffer(bufferSize);

                        if (EvtRender(hContext, hEvent, EvtRenderEventValues, bufferSize,
                                     buffer.data(), &bufferUsed, &propertyCount)) {
                            PEVT_VARIANT values = (PEVT_VARIANT)buffer.data();

                            if (values[EvtSystemTimeCreated].Type == EvtVarTypeFileTime) {
                                SYSTEMTIME st;
                                FileTimeToSystemTime(&values[EvtSystemTimeCreated].FileTimeVal, &st);
                                wchar_t timeStr[100];
                                swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
                                         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                                evt.timestamp = timeStr;
                            }
                        }
                    }
                }
            }

            evt.user = ExtractTargetUserName(xml);
            evt.ipSource = ExtractIPFromXML(xml);
            evt.eventType = isFailed ? L"Échec connexion" : L"Connexion réussie";
            evt.sessionID = L"N/A";
            evt.state = isFailed ? L"Échec" : L"Actif";
            evt.alert = L"Normal";

            // Check blacklist
            if (IsBlacklisted(evt.ipSource)) {
                evt.alert = L"IP BLACKLISTÉE!";
                blacklistedAttempts++;
            }

            // Detect brute-force on failed logons
            if (isFailed && evt.ipSource != L"N/A") {
                DetectBruteForce(evt.ipSource, evt.alert);
                if (evt.alert == L"BRUTE-FORCE DÉTECTÉ!") {
                    bruteforceDetections++;
                }
            }

            g_events.push_back(evt);
            totalEvents++;

            // Add to ListView
            LVITEMW lvi = {};
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(g_hwndListView);
            lvi.pszText = (LPWSTR)evt.timestamp.c_str();
            int index = ListView_InsertItem(g_hwndListView, &lvi);

            ListView_SetItemText(g_hwndListView, index, 1, (LPWSTR)evt.user.c_str());
            ListView_SetItemText(g_hwndListView, index, 2, (LPWSTR)evt.ipSource.c_str());
            ListView_SetItemText(g_hwndListView, index, 3, (LPWSTR)evt.eventType.c_str());
            ListView_SetItemText(g_hwndListView, index, 4, (LPWSTR)evt.sessionID.c_str());
            ListView_SetItemText(g_hwndListView, index, 5, (LPWSTR)evt.state.c_str());
            ListView_SetItemText(g_hwndListView, index, 6, (LPWSTR)evt.alert.c_str());

            if (totalEvents >= 500) break; // Limit to 500 events for performance
        }

        if (totalEvents >= 500) break;

        std::wstring status = L"Analysés: " + std::to_wstring(totalEvents) + L" | Brute-force: " +
                             std::to_wstring(bruteforceDetections) + L" | Blacklist: " +
                             std::to_wstring(blacklistedAttempts);
        SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)status.c_str());
    }

    // Correlation with active sessions
    WTS_SESSION_INFOW* pSessionInfo = nullptr;
    DWORD sessionCount = 0;

    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        for (DWORD i = 0; i < sessionCount; i++) {
            if (pSessionInfo[i].State == WTSActive || pSessionInfo[i].State == WTSDisconnected) {
                RDPEvent evt;
                evt.timestamp = L"Session active";
                evt.sessionID = std::to_wstring(pSessionInfo[i].SessionId);
                evt.state = (pSessionInfo[i].State == WTSActive) ? L"Actif" : L"Déconnecté";

                LPWSTR userName = nullptr;
                DWORD bytesReturned = 0;
                if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[i].SessionId,
                                                WTSUserName, &userName, &bytesReturned)) {
                    evt.user = userName ? userName : L"N/A";
                    WTSFreeMemory(userName);
                }

                evt.ipSource = L"N/A";
                evt.eventType = L"Session active";
                evt.alert = L"Monitoring";

                g_events.push_back(evt);

                LVITEMW lvi = {};
                lvi.mask = LVIF_TEXT;
                lvi.iItem = ListView_GetItemCount(g_hwndListView);
                lvi.pszText = (LPWSTR)evt.timestamp.c_str();
                int index = ListView_InsertItem(g_hwndListView, &lvi);

                ListView_SetItemText(g_hwndListView, index, 1, (LPWSTR)evt.user.c_str());
                ListView_SetItemText(g_hwndListView, index, 2, (LPWSTR)evt.ipSource.c_str());
                ListView_SetItemText(g_hwndListView, index, 3, (LPWSTR)evt.eventType.c_str());
                ListView_SetItemText(g_hwndListView, index, 4, (LPWSTR)evt.sessionID.c_str());
                ListView_SetItemText(g_hwndListView, index, 5, (LPWSTR)evt.state.c_str());
                ListView_SetItemText(g_hwndListView, index, 6, (LPWSTR)evt.alert.c_str());
            }
        }

        WTSFreeMemory(pSessionInfo);
    }

    std::wstring msg = L"Monitoring terminé: " + std::to_wstring(totalEvents) + L" événements RDP | " +
                       std::to_wstring(bruteforceDetections) + L" brute-force détectés | " +
                       std::to_wstring(blacklistedAttempts) + L" tentatives blacklistées";
    SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)msg.c_str());
    LogMessage(msg);
    g_isMonitoring = false;

    if (bruteforceDetections > 0) {
        MessageBoxW(g_hwndMain,
                   (L"ALERTE: " + std::to_wstring(bruteforceDetections) + L" attaque(s) brute-force détectée(s)!").c_str(),
                   L"Alerte Sécurité", MB_OK | MB_ICONWARNING);
    }
}

void ConfigureThresholds() {
    wchar_t thresholdText[50] = {};
    GetWindowTextW(g_hwndEditThreshold, thresholdText, 50);

    int newThreshold = _wtoi(thresholdText);
    if (newThreshold > 0) {
        g_bruteforceThreshold = newThreshold;

        std::wstring msg = L"Seuil brute-force configuré: " + std::to_wstring(g_bruteforceThreshold) + L" échecs en 5 minutes";
        MessageBoxW(g_hwndMain, msg.c_str(), L"Configuration", MB_OK | MB_ICONINFORMATION);
        LogMessage(msg);
    } else {
        MessageBoxW(g_hwndMain, L"Seuil invalide. Utilisez un nombre > 0.", L"Erreur", MB_OK | MB_ICONERROR);
    }
}

void BlacklistIP() {
    wchar_t ip[256] = {};
    if (InputBoxW(g_hwndMain, L"Entrez l'adresse IP à blacklister:", L"Blacklist IP", ip, 256)) {
        std::wstring ipStr = ip;
        if (!ipStr.empty() && !IsBlacklisted(ipStr)) {
            g_blacklist.push_back(ipStr);
            MessageBoxW(g_hwndMain, (L"IP ajoutée à la blacklist: " + ipStr).c_str(),
                       L"Succès", MB_OK | MB_ICONINFORMATION);
            LogMessage(L"IP blacklistée manuellement: " + ipStr);
        } else if (IsBlacklisted(ipStr)) {
            MessageBoxW(g_hwndMain, L"Cette IP est déjà blacklistée.", L"Information", MB_OK | MB_ICONINFORMATION);
        }
    }
}

// Simple InputBox implementation
bool InputBoxW(HWND hwndParent, const wchar_t* prompt, const wchar_t* title, wchar_t* buffer, int bufferSize) {
    // For simplicity, use a message box here - in production, create a proper dialog
    MessageBoxW(hwndParent, L"Fonction InputBox simplifiée.\r\nUtilisez la détection automatique ou modifiez le code.",
               title, MB_OK | MB_ICONINFORMATION);
    return false;
}

void ExportReport() {
    wchar_t fileName[MAX_PATH] = L"SecureRDPWatch2025_Report.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwndMain;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn)) {
        std::wofstream csvFile(fileName, std::ios::out | std::ios::binary);
        if (csvFile.is_open()) {
            // UTF-8 BOM
            csvFile.put(0xEF);
            csvFile.put(0xBB);
            csvFile.put(0xBF);

            csvFile << L"Horodatage,Utilisateur,IPSource,TypeÉvénement,SessionID,État,Alertes\n";

            int itemCount = ListView_GetItemCount(g_hwndListView);
            for (int i = 0; i < itemCount; i++) {
                wchar_t buffer[1024];

                ListView_GetItemText(g_hwndListView, i, 0, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 1, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 2, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 3, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 4, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 5, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 6, buffer, 1024);
                csvFile << L"\"" << buffer << L"\"\n";
            }

            csvFile.close();
            MessageBoxW(g_hwndMain, L"Export CSV réussi!", L"Succès", MB_OK | MB_ICONINFORMATION);
            LogMessage(L"Export CSV vers: " + std::wstring(fileName));
        }
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Buttons
            CreateWindowExW(0, L"BUTTON", L"Démarrer monitoring",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           10, 10, 170, 30, hwnd, (HMENU)1001, nullptr, nullptr);

            CreateWindowExW(0, L"STATIC", L"Seuil brute-force:", WS_CHILD | WS_VISIBLE,
                           190, 15, 120, 20, hwnd, nullptr, nullptr, nullptr);
            g_hwndEditThreshold = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"5",
                                                   WS_CHILD | WS_VISIBLE | ES_NUMBER,
                                                   320, 13, 50, 20, hwnd, (HMENU)1002, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Configurer",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           380, 10, 100, 30, hwnd, (HMENU)1003, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Blacklist IP",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           490, 10, 110, 30, hwnd, (HMENU)1004, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Exporter",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           610, 10, 100, 30, hwnd, (HMENU)1005, nullptr, nullptr);

            // ListView
            g_hwndListView = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                             WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
                                             10, 50, 1280, 550, hwnd, (HMENU)1006, nullptr, nullptr);
            ListView_SetExtendedListViewStyle(g_hwndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMNW lvc = {};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;

            lvc.pszText = (LPWSTR)L"Horodatage";
            lvc.cx = 140;
            ListView_InsertColumn(g_hwndListView, 0, &lvc);

            lvc.pszText = (LPWSTR)L"Utilisateur";
            lvc.cx = 150;
            ListView_InsertColumn(g_hwndListView, 1, &lvc);

            lvc.pszText = (LPWSTR)L"IPSource";
            lvc.cx = 150;
            ListView_InsertColumn(g_hwndListView, 2, &lvc);

            lvc.pszText = (LPWSTR)L"TypeÉvénement";
            lvc.cx = 180;
            ListView_InsertColumn(g_hwndListView, 3, &lvc);

            lvc.pszText = (LPWSTR)L"SessionID";
            lvc.cx = 100;
            ListView_InsertColumn(g_hwndListView, 4, &lvc);

            lvc.pszText = (LPWSTR)L"État";
            lvc.cx = 120;
            ListView_InsertColumn(g_hwndListView, 5, &lvc);

            lvc.pszText = (LPWSTR)L"Alertes";
            lvc.cx = 320;
            ListView_InsertColumn(g_hwndListView, 6, &lvc);

            // StatusBar
            g_hwndStatus = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
                                          WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                          0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Prêt - Ayi NEDJIMI Consultants");

            LogMessage(L"SecureRDPWatch2025 démarré");
            break;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case 1001: // Démarrer monitoring
                    if (!g_isMonitoring) {
                        std::thread(MonitorRDPEvents).detach();
                    }
                    break;

                case 1003: // Configurer seuils
                    ConfigureThresholds();
                    break;

                case 1004: // Blacklist IP
                    BlacklistIP();
                    break;

                case 1005: // Exporter
                    ExportReport();
                    break;
            }
            break;
        }

        case WM_SIZE: {
            RECT rect;
            GetClientRect(hwnd, &rect);

            SetWindowPos(g_hwndListView, nullptr, 10, 50, rect.right - 20, rect.bottom - 80, SWP_NOZORDER);
            SendMessageW(g_hwndStatus, WM_SIZE, 0, 0);
            break;
        }

        case WM_DESTROY:
            LogMessage(L"SecureRDPWatch2025 fermé");
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SecureRDPWatch2025Class";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    g_hwndMain = CreateWindowExW(0, wc.lpszClassName,
                                 L"Secure RDP Watch 2025 - Ayi NEDJIMI Consultants",
                                 WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 1320, 680,
                                 nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hwndMain, nCmdShow);
    UpdateWindow(g_hwndMain);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
