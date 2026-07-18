#include "easywg_request_protocol.hpp"

#include <algorithm>
#include <chrono>
#include <climits>
#include <iomanip>

namespace easywg_request {
namespace {

std::wstring SocketErrorText(int error = WSAGetLastError()) {
    if (error == 0)
        return L"未取得 Winsock 錯誤碼";
    wchar_t* message = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    FormatMessageW(flags, nullptr, static_cast<DWORD>(error), 0,
                   reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::wstring text = message ? message : L"Winsock error " + std::to_wstring(error);
    if (message) LocalFree(message);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' '))
        text.pop_back();
    return text;
}

bool SendAll(SOCKET socket, const char* data, size_t size) {
    while (size > 0) {
        const int chunk = static_cast<int>((std::min)(size, static_cast<size_t>(INT_MAX)));
        const int sent = send(socket, data, chunk, 0);
        if (sent <= 0) return false;
        data += sent;
        size -= static_cast<size_t>(sent);
    }
    return true;
}

bool SendText(SOCKET socket, const std::string& text) {
    return SendAll(socket, text.data(), text.size());
}

bool ReadHeader(SOCKET socket, std::string& firstLine,
                std::map<std::string, std::string>& fields) {
    std::string buffer;
    buffer.reserve(2048);
    char temp[1024];
    size_t headerEnd = std::string::npos;
    while (buffer.size() < kMaxHeaderBytes) {
        const int received = recv(socket, temp, sizeof(temp), 0);
        if (received <= 0) return false;
        buffer.append(temp, static_cast<size_t>(received));
        headerEnd = buffer.find("\r\n\r\n");
        size_t delimiterSize = 4;
        if (headerEnd == std::string::npos) {
            headerEnd = buffer.find("\n\n");
            delimiterSize = 2;
        }
        if (headerEnd == std::string::npos) continue;
        buffer.resize(headerEnd + delimiterSize);
        break;
    }
    if (headerEnd == std::string::npos) return false;

    std::istringstream input(buffer);
    if (!std::getline(input, firstLine)) return false;
    if (!firstLine.empty() && firstLine.back() == '\r') firstLine.pop_back();
    fields.clear();
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        const size_t equal = line.find('=');
        if (equal == std::string::npos) continue;
        fields[line.substr(0, equal)] = line.substr(equal + 1);
    }
    return true;
}

std::string Field(const std::map<std::string, std::string>& fields,
                  const std::string& name) {
    const auto it = fields.find(name);
    return it == fields.end() ? std::string() : it->second;
}

bool ParseBool(const std::string& value) {
    return value == "1" || value == "true" || value == "yes";
}

std::string CanonicalAuthData(const std::map<std::string, std::string>& hello,
                              const std::string& serverNonce) {
    std::ostringstream out;
    out << "EASYWG-AUTH-V1\n"
        << "client_nonce=" << Field(hello, "client_nonce") << "\n"
        << "server_nonce=" << serverNonce << "\n"
        << "temporary=" << Field(hello, "temporary") << "\n"
        << "full_tunnel=" << Field(hello, "full_tunnel") << "\n"
        << "client_name=" << Field(hello, "client_name") << "\n"
        << "public_key=" << Field(hello, "public_key") << "\n"
        << "preshared_key=" << Field(hello, "preshared_key") << "\n";
    return out.str();
}

std::map<std::string, std::string> ResultFields(const Result& result) {
    return {
        {"status", result.ok ? "ok" : "error"},
        {"temporary", result.temporary ? "1" : "0"},
        {"error", PercentEncode(result.error)},
        {"peer_name", PercentEncode(result.peerName)},
        {"file_name", PercentEncode(result.fileName)},
        {"address", PercentEncode(result.address)},
        {"dns", PercentEncode(result.dns)},
        {"endpoint", PercentEncode(result.endpoint)},
        {"allowed_ips", PercentEncode(result.allowedIps)},
        {"server_public_key", WideToUtf8(result.serverPublicKey)}
    };
}

std::string CanonicalResultData(const std::map<std::string, std::string>& fields,
                                const std::string& clientNonce,
                                const std::string& serverNonce) {
    std::ostringstream out;
    out << "EASYWG-RESULT-AUTH-V1\n"
        << "client_nonce=" << clientNonce << "\n"
        << "server_nonce=" << serverNonce << "\n"
        << "status=" << Field(fields, "status") << "\n"
        << "temporary=" << Field(fields, "temporary") << "\n"
        << "error=" << Field(fields, "error") << "\n"
        << "peer_name=" << Field(fields, "peer_name") << "\n"
        << "file_name=" << Field(fields, "file_name") << "\n"
        << "address=" << Field(fields, "address") << "\n"
        << "dns=" << Field(fields, "dns") << "\n"
        << "endpoint=" << Field(fields, "endpoint") << "\n"
        << "allowed_ips=" << Field(fields, "allowed_ips") << "\n"
        << "server_public_key=" << Field(fields, "server_public_key") << "\n";
    return out.str();
}

std::string BuildResultMessage(const Result& result, const std::string& serverProof = {}) {
    const auto fields = ResultFields(result);
    std::ostringstream out;
    out << "EASYWG-RESULT 1\r\n"
        << "status=" << Field(fields, "status") << "\r\n"
        << "temporary=" << Field(fields, "temporary") << "\r\n"
        << "error=" << Field(fields, "error") << "\r\n"
        << "peer_name=" << Field(fields, "peer_name") << "\r\n"
        << "file_name=" << Field(fields, "file_name") << "\r\n"
        << "address=" << Field(fields, "address") << "\r\n"
        << "dns=" << Field(fields, "dns") << "\r\n"
        << "endpoint=" << Field(fields, "endpoint") << "\r\n"
        << "allowed_ips=" << Field(fields, "allowed_ips") << "\r\n"
        << "server_public_key=" << Field(fields, "server_public_key") << "\r\n"
        << "server_proof=" << serverProof << "\r\n\r\n";
    return out.str();
}

SOCKET ConnectWithTimeout(const std::wstring& host, unsigned short port,
                          DWORD timeoutMs, std::wstring& error) {
    error.clear();
    addrinfoW hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfoW* addresses = nullptr;
    const std::wstring portText = std::to_wstring(port);
    const int gai = GetAddrInfoW(host.c_str(), portText.c_str(), &hints, &addresses);
    if (gai != 0) {
        error = L"無法解析申請伺服器：" + host + L"（" + std::to_wstring(gai) + L"）";
        return INVALID_SOCKET;
    }

    SOCKET connected = INVALID_SOCKET;
    int lastSocketError = 0;
    bool timedOut = false;

    // Public EasyWG endpoints are normally IPv4. Prefer IPv4 first so an
    // unreachable AAAA record does not delay or hide a valid IPv4 service.
    for (int pass = 0; pass < 2 && connected == INVALID_SOCKET; ++pass) {
        for (addrinfoW* it = addresses; it; it = it->ai_next) {
            if ((pass == 0 && it->ai_family != AF_INET) ||
                (pass == 1 && it->ai_family == AF_INET))
                continue;

            SOCKET candidate = WSASocketW(it->ai_family, it->ai_socktype, it->ai_protocol,
                                          nullptr, 0, WSA_FLAG_OVERLAPPED);
            if (candidate == INVALID_SOCKET) {
                lastSocketError = WSAGetLastError();
                continue;
            }

            u_long nonBlocking = 1;
            if (ioctlsocket(candidate, FIONBIO, &nonBlocking) == SOCKET_ERROR) {
                lastSocketError = WSAGetLastError();
                closesocket(candidate);
                continue;
            }

            bool connectionReady = false;
            int rc = connect(candidate, it->ai_addr, static_cast<int>(it->ai_addrlen));
            if (rc == 0) {
                connectionReady = true;
            } else {
                const int connectError = WSAGetLastError();
                if (connectError != WSAEWOULDBLOCK && connectError != WSAEINPROGRESS &&
                    connectError != WSAEINVAL) {
                    lastSocketError = connectError;
                    closesocket(candidate);
                    continue;
                }

                fd_set writeSet, errorSet;
                FD_ZERO(&writeSet);
                FD_ZERO(&errorSet);
                FD_SET(candidate, &writeSet);
                FD_SET(candidate, &errorSet);
                timeval timeout{};
                timeout.tv_sec = static_cast<long>(timeoutMs / 1000);
                timeout.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
                rc = select(0, nullptr, &writeSet, &errorSet, &timeout);
                if (rc == 0) {
                    timedOut = true;
                    lastSocketError = WSAETIMEDOUT;
                } else if (rc == SOCKET_ERROR) {
                    lastSocketError = WSAGetLastError();
                } else {
                    int socketError = 0;
                    int length = sizeof(socketError);
                    if (getsockopt(candidate, SOL_SOCKET, SO_ERROR,
                                   reinterpret_cast<char*>(&socketError), &length) == SOCKET_ERROR) {
                        lastSocketError = WSAGetLastError();
                    } else if (socketError != 0) {
                        lastSocketError = socketError;
                    } else if (FD_ISSET(candidate, &writeSet)) {
                        connectionReady = true;
                    } else {
                        lastSocketError = WSAECONNREFUSED;
                    }
                }
            }

            if (!connectionReady) {
                closesocket(candidate);
                continue;
            }

            nonBlocking = 0;
            ioctlsocket(candidate, FIONBIO, &nonBlocking);
            const DWORD ioTimeout = 15000;
            setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&ioTimeout), sizeof(ioTimeout));
            setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&ioTimeout), sizeof(ioTimeout));
            connected = candidate;
            break;
        }
    }

    FreeAddrInfoW(addresses);
    if (connected == INVALID_SOCKET) {
        const std::wstring reason = timedOut
            ? L"連線逾時"
            : SocketErrorText(lastSocketError);
        error = L"無法連線到申請伺服器 " + host + L":" + portText +
                L"（TCP）：" + reason +
                L"\r\n\r\n請確認 Server 已啟用『EasyWG Portable 自動申請連接』，"
                L"並在分享器與 Windows 防火牆開放 TCP " + portText +
                L"。WireGuard 連線使用 UDP；快速申請使用相同號碼的 TCP，兩種協定都必須開放。";
    }
    return connected;
}

} // namespace

std::string WideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0,
                                         nullptr, nullptr);
    if (size <= 0) return {};
    std::string output(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        output.data(), size, nullptr, nullptr);
    return output;
}

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                         text.data(), static_cast<int>(text.size()),
                                         nullptr, 0);
    if (size <= 0) return {};
    std::wstring output(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), output.data(), size);
    return output;
}

std::string PercentEncode(const std::wstring& text) {
    const std::string utf8 = WideToUtf8(text);
    static const char hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(utf8.size() * 3);
    for (unsigned char ch : utf8) {
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            output.push_back(static_cast<char>(ch));
        } else {
            output.push_back('%');
            output.push_back(hex[(ch >> 4) & 0x0F]);
            output.push_back(hex[ch & 0x0F]);
        }
    }
    return output;
}

std::wstring PercentDecode(const std::string& text) {
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    std::string bytes;
    bytes.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size()) {
            const int hi = nibble(text[i + 1]);
            const int lo = nibble(text[i + 2]);
            if (hi >= 0 && lo >= 0) {
                bytes.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        bytes.push_back(text[i] == '+' ? ' ' : text[i]);
    }
    return Utf8ToWide(bytes);
}

std::string HexEncode(const BYTE* data, size_t size) {
    static const char hex[] = "0123456789abcdef";
    std::string output(size * 2, '\0');
    for (size_t i = 0; i < size; ++i) {
        output[i * 2] = hex[(data[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    return output;
}

bool HexDecode(const std::string& text, BYTE* output, size_t size) {
    if (text.size() != size * 2) return false;
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < size; ++i) {
        const int hi = nibble(text[i * 2]);
        const int lo = nibble(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        output[i] = static_cast<BYTE>((hi << 4) | lo);
    }
    return true;
}

std::string Base64Encode(const BYTE* data, DWORD size) {
    DWORD chars = 0;
    if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              nullptr, &chars)) return {};
    std::string output(chars, '\0');
    if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              output.data(), &chars)) return {};
    if (!output.empty() && output.back() == '\0') output.pop_back();
    return output;
}

bool Base64Decode(const std::string& text, BYTE* output, DWORD expectedSize) {
    DWORD size = expectedSize;
    return CryptStringToBinaryA(text.c_str(), 0, CRYPT_STRING_BASE64, output, &size,
                                nullptr, nullptr) && size == expectedSize;
}

bool GenerateRandom(BYTE* output, ULONG size) {
    return BCryptGenRandom(nullptr, output, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

bool DeriveAuthKey(const std::wstring& password, const std::array<BYTE, 16>& salt,
                   std::array<BYTE, 32>& key) {
    std::string passwordBytes = WideToUtf8(password);
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) return false;
    status = BCryptDeriveKeyPBKDF2(
        algorithm,
        reinterpret_cast<PUCHAR>(passwordBytes.data()),
        static_cast<ULONG>(passwordBytes.size()),
        const_cast<PUCHAR>(salt.data()), static_cast<ULONG>(salt.size()),
        kPbkdf2Iterations, key.data(), static_cast<ULONG>(key.size()), 0);
    if (!passwordBytes.empty()) SecureZeroMemory(passwordBytes.data(), passwordBytes.size());
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0;
}

bool HmacSha256(const BYTE* key, ULONG keySize, const std::string& data,
                std::array<BYTE, 32>& digest) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) return false;
    DWORD objectSize = 0, bytes = 0;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
                               &bytes, 0);
    std::vector<BYTE> object(objectSize);
    if (status >= 0)
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectSize,
                                  const_cast<PUCHAR>(key), keySize, 0);
    if (status >= 0 && !data.empty())
        status = BCryptHashData(hash,
                                reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                                static_cast<ULONG>(data.size()), 0);
    if (status >= 0)
        status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0;
}

bool ConstantTimeEqual(const BYTE* a, const BYTE* b, size_t size) {
    BYTE diff = 0;
    for (size_t i = 0; i < size; ++i) diff |= static_cast<BYTE>(a[i] ^ b[i]);
    return diff == 0;
}

Listener::~Listener() {
    Stop();
}

void Listener::Log(const std::wstring& text) const {
    if (logger_) logger_(text);
}

bool Listener::Start(unsigned short port, const std::wstring& password,
                     RequestHandler handler, LogHandler logger,
                     std::wstring& error) {
    Stop();
    error.clear();
    if (port == 0 || password.empty() || !handler) {
        error = L"自動申請服務的連接埠、密碼或處理函式無效。";
        return false;
    }

    std::lock_guard<std::mutex> lock(stateMutex_);
    password_ = password;
    handler_ = std::move(handler);
    logger_ = std::move(logger);
    port_ = port;

    // Bind IPv4 explicitly. Some Windows/network combinations leave an IPv6
    // socket in V6-only mode even when dual-stack was requested, which makes
    // an IPv4 router forward appear closed to Portable clients.
    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket_ == INVALID_SOCKET) {
        error = L"建立自動申請 TCP/IPv4 Socket 失敗：" + SocketErrorText();
        return false;
    }

    BOOL exclusive = TRUE;
    setsockopt(listenSocket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        const int bindError = WSAGetLastError();
        error = L"綁定自動申請 TCP/IPv4 Port " + std::to_wstring(port) +
                L" 失敗：" + SocketErrorText(bindError);
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return false;
    }

    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        const int listenError = WSAGetLastError();
        error = L"啟動自動申請 TCP/IPv4 監聽失敗：" + SocketErrorText(listenError);
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return false;
    }

    running_ = true;
    acceptThread_ = std::thread(&Listener::AcceptLoop, this);
    return true;
}

void Listener::Stop() {
    running_ = false;
    SOCKET socketToClose = INVALID_SOCKET;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        socketToClose = listenSocket_;
        listenSocket_ = INVALID_SOCKET;
    }
    if (socketToClose != INVALID_SOCKET) {
        shutdown(socketToClose, SD_BOTH);
        closesocket(socketToClose);
    }

    std::vector<SOCKET> clients;
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        clients.swap(clients_);
    }
    for (SOCKET client : clients) {
        shutdown(client, SD_BOTH);
        closesocket(client);
    }

    if (acceptThread_.joinable()) acceptThread_.join();
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> lock(workersMutex_);
        workers.swap(workers_);
    }
    for (auto& worker : workers)
        if (worker.joinable()) worker.join();

    std::lock_guard<std::mutex> lock(stateMutex_);
    if (!password_.empty()) SecureZeroMemory(password_.data(), password_.size() * sizeof(wchar_t));
    password_.clear();
    handler_ = nullptr;
    logger_ = nullptr;
    port_ = 0;
}

void Listener::AcceptLoop() {
    while (running_) {
        SOCKET listener = INVALID_SOCKET;
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            listener = listenSocket_;
        }
        if (listener == INVALID_SOCKET) break;
        SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            if (!running_) break;
            Sleep(100);
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(clientsMutex_);
            if (!running_) {
                shutdown(client, SD_BOTH);
                closesocket(client);
                break;
            }
            clients_.push_back(client);
        }
        std::lock_guard<std::mutex> lock(workersMutex_);
        workers_.emplace_back(&Listener::HandleClient, this, client);
    }
}

void Listener::CloseTrackedClient(SOCKET client) {
    bool owned = false;
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        const auto it = std::find(clients_.begin(), clients_.end(), client);
        if (it != clients_.end()) {
            clients_.erase(it);
            owned = true;
        }
    }
    if (owned) {
        shutdown(client, SD_BOTH);
        closesocket(client);
    }
}

void Listener::HandleClient(SOCKET client) {
    const DWORD timeout = 15000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    auto closeClient = [&]() { CloseTrackedClient(client); };
    Result failure;
    failure.ok = false;

    std::string firstLine;
    std::map<std::string, std::string> hello;
    if (!ReadHeader(client, firstLine, hello) || firstLine != "EASYWG-HELLO 1") {
        failure.error = L"申請協定格式錯誤。";
        SendText(client, BuildResultMessage(failure));
        closeClient();
        return;
    }

    std::array<BYTE, 32> clientNonce{};
    Request request;
    if (!HexDecode(Field(hello, "client_nonce"), clientNonce.data(), clientNonce.size()) ||
        !Base64Decode(Field(hello, "public_key"), request.publicKey.data(), 32) ||
        !Base64Decode(Field(hello, "preshared_key"), request.presharedKey.data(), 32)) {
        failure.error = L"申請金鑰或隨機碼格式錯誤。";
        SendText(client, BuildResultMessage(failure));
        closeClient();
        return;
    }
    request.temporary = ParseBool(Field(hello, "temporary"));
    request.fullTunnel = ParseBool(Field(hello, "full_tunnel"));
    request.clientName = PercentDecode(Field(hello, "client_name"));

    std::array<BYTE, 16> salt{};
    std::array<BYTE, 32> serverNonce{};
    if (!GenerateRandom(salt.data(), static_cast<ULONG>(salt.size())) ||
        !GenerateRandom(serverNonce.data(), static_cast<ULONG>(serverNonce.size()))) {
        failure.error = L"伺服器無法產生安全隨機碼。";
        SendText(client, BuildResultMessage(failure));
        closeClient();
        return;
    }

    const std::string serverNonceHex = HexEncode(serverNonce.data(), serverNonce.size());
    std::ostringstream challenge;
    challenge << "EASYWG-CHALLENGE 1\r\n"
              << "salt=" << HexEncode(salt.data(), salt.size()) << "\r\n"
              << "server_nonce=" << serverNonceHex << "\r\n"
              << "iterations=" << kPbkdf2Iterations << "\r\n\r\n";
    if (!SendText(client, challenge.str())) {
        closeClient();
        return;
    }

    std::map<std::string, std::string> auth;
    if (!ReadHeader(client, firstLine, auth) || firstLine != "EASYWG-AUTH 1") {
        closeClient();
        return;
    }
    std::array<BYTE, 32> providedProof{};
    if (!HexDecode(Field(auth, "proof"), providedProof.data(), providedProof.size())) {
        failure.error = L"申請驗證資料格式錯誤。";
        SendText(client, BuildResultMessage(failure));
        closeClient();
        return;
    }

    std::wstring password;
    RequestHandler handler;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        password = password_;
        handler = handler_;
    }
    std::array<BYTE, 32> authKey{};
    std::array<BYTE, 32> expectedProof{};
    const bool verified = DeriveAuthKey(password, salt, authKey) &&
        HmacSha256(authKey.data(), static_cast<ULONG>(authKey.size()),
                   CanonicalAuthData(hello, serverNonceHex), expectedProof) &&
        ConstantTimeEqual(providedProof.data(), expectedProof.data(), expectedProof.size());
    if (!password.empty()) SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    if (!verified) {
        SecureZeroMemory(authKey.data(), authKey.size());
        // Slow repeated online guesses without making an ordinary typo feel stuck.
        Sleep(750);
        failure.error = L"申請密碼錯誤。";
        SendText(client, BuildResultMessage(failure));
        Log(L"EasyWG Portable 自動申請驗證失敗");
        closeClient();
        return;
    }

    Result result = handler ? handler(request) : Result{};
    if (!handler) {
        result.ok = false;
        result.error = L"自動申請服務尚未就緒。";
    }
    const auto resultFields = ResultFields(result);
    std::array<BYTE, 32> serverProof{};
    std::string serverProofHex;
    if (HmacSha256(authKey.data(), static_cast<ULONG>(authKey.size()),
                   CanonicalResultData(resultFields, Field(hello, "client_nonce"), serverNonceHex),
                   serverProof)) {
        serverProofHex = HexEncode(serverProof.data(), serverProof.size());
    }
    SecureZeroMemory(authKey.data(), authKey.size());
    SendText(client, BuildResultMessage(result, serverProofHex));
    closeClient();
}

bool PerformRequest(const std::wstring& host, unsigned short port,
                    const std::wstring& password, const Request& request,
                    Result& result, std::wstring& error,
                    DWORD connectTimeoutMs) {
    result = {};
    if (host.empty() || port == 0 || password.empty()) {
        error = L"請輸入申請伺服器、連接埠與申請密碼。";
        return false;
    }

    WSADATA wsa{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (startup != 0) {
        error = L"Winsock 初始化失敗：" + std::to_wstring(startup);
        return false;
    }

    SOCKET socket = ConnectWithTimeout(host, port, connectTimeoutMs, error);
    if (socket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    auto cleanup = [&]() {
        shutdown(socket, SD_BOTH);
        closesocket(socket);
        WSACleanup();
    };

    std::array<BYTE, 32> clientNonce{};
    if (!GenerateRandom(clientNonce.data(), static_cast<ULONG>(clientNonce.size()))) {
        error = L"無法產生申請隨機碼。";
        cleanup();
        return false;
    }

    std::map<std::string, std::string> hello;
    hello["client_nonce"] = HexEncode(clientNonce.data(), clientNonce.size());
    hello["temporary"] = request.temporary ? "1" : "0";
    hello["full_tunnel"] = request.fullTunnel ? "1" : "0";
    hello["client_name"] = PercentEncode(request.clientName);
    hello["public_key"] = Base64Encode(request.publicKey.data(), 32);
    hello["preshared_key"] = Base64Encode(request.presharedKey.data(), 32);

    std::ostringstream helloMessage;
    helloMessage << "EASYWG-HELLO 1\r\n"
                 << "client_nonce=" << hello["client_nonce"] << "\r\n"
                 << "temporary=" << hello["temporary"] << "\r\n"
                 << "full_tunnel=" << hello["full_tunnel"] << "\r\n"
                 << "client_name=" << hello["client_name"] << "\r\n"
                 << "public_key=" << hello["public_key"] << "\r\n"
                 << "preshared_key=" << hello["preshared_key"] << "\r\n\r\n";
    if (!SendText(socket, helloMessage.str())) {
        error = L"送出連線申請失敗：" + SocketErrorText();
        cleanup();
        return false;
    }

    std::string firstLine;
    std::map<std::string, std::string> challenge;
    if (!ReadHeader(socket, firstLine, challenge)) {
        error = L"申請伺服器沒有回應。";
        cleanup();
        return false;
    }
    if (firstLine == "EASYWG-RESULT 1") {
        result.ok = Field(challenge, "status") == "ok";
        result.error = PercentDecode(Field(challenge, "error"));
        error = result.error.empty() ? L"申請伺服器拒絕連線。" : result.error;
        cleanup();
        return false;
    }
    if (firstLine != "EASYWG-CHALLENGE 1") {
        error = L"申請伺服器回傳未知協定。";
        cleanup();
        return false;
    }

    std::array<BYTE, 16> salt{};
    if (!HexDecode(Field(challenge, "salt"), salt.data(), salt.size())) {
        error = L"申請伺服器驗證資料格式錯誤。";
        cleanup();
        return false;
    }
    const std::string serverNonce = Field(challenge, "server_nonce");
    std::array<BYTE, 32> authKey{};
    std::array<BYTE, 32> proof{};
    if (!DeriveAuthKey(password, salt, authKey) ||
        !HmacSha256(authKey.data(), static_cast<ULONG>(authKey.size()),
                    CanonicalAuthData(hello, serverNonce), proof)) {
        SecureZeroMemory(authKey.data(), authKey.size());
        error = L"無法建立申請驗證資料。";
        cleanup();
        return false;
    }
    const std::string authMessage = "EASYWG-AUTH 1\r\nproof=" +
                                    HexEncode(proof.data(), proof.size()) + "\r\n\r\n";
    if (!SendText(socket, authMessage)) {
        SecureZeroMemory(authKey.data(), authKey.size());
        error = L"送出申請密碼驗證失敗。";
        cleanup();
        return false;
    }

    std::map<std::string, std::string> response;
    if (!ReadHeader(socket, firstLine, response) || firstLine != "EASYWG-RESULT 1") {
        SecureZeroMemory(authKey.data(), authKey.size());
        error = L"申請伺服器回應格式錯誤。";
        cleanup();
        return false;
    }
    std::array<BYTE, 32> providedServerProof{};
    std::array<BYTE, 32> expectedServerProof{};
    const bool serverVerified =
        HexDecode(Field(response, "server_proof"), providedServerProof.data(), providedServerProof.size()) &&
        HmacSha256(authKey.data(), static_cast<ULONG>(authKey.size()),
                   CanonicalResultData(response, hello["client_nonce"], serverNonce),
                   expectedServerProof) &&
        ConstantTimeEqual(providedServerProof.data(), expectedServerProof.data(), expectedServerProof.size());
    SecureZeroMemory(authKey.data(), authKey.size());
    if (!serverVerified) {
        error = L"申請密碼錯誤，或無法驗證申請伺服器身分；連線已取消。";
        cleanup();
        return false;
    }
    result.ok = Field(response, "status") == "ok";
    result.temporary = ParseBool(Field(response, "temporary"));
    result.error = PercentDecode(Field(response, "error"));
    result.peerName = PercentDecode(Field(response, "peer_name"));
    result.fileName = PercentDecode(Field(response, "file_name"));
    result.address = PercentDecode(Field(response, "address"));
    result.dns = PercentDecode(Field(response, "dns"));
    result.endpoint = PercentDecode(Field(response, "endpoint"));
    result.allowedIps = PercentDecode(Field(response, "allowed_ips"));
    result.serverPublicKey = Field(response, "server_public_key").empty()
        ? L"" : Utf8ToWide(Field(response, "server_public_key"));
    cleanup();

    if (!result.ok) {
        error = result.error.empty() ? L"申請伺服器拒絕連線。" : result.error;
        return false;
    }
    return true;
}

} // namespace easywg_request
