#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace easywg_request {

constexpr int kProtocolVersion = 1;
constexpr ULONG kPbkdf2Iterations = 60000;
constexpr size_t kMaxHeaderBytes = 64 * 1024;

struct Request {
    bool temporary = false;
    bool fullTunnel = false;
    std::wstring clientName;
    std::array<BYTE, 32> publicKey{};
    std::array<BYTE, 32> presharedKey{};
};

struct Result {
    bool ok = false;
    bool temporary = false;
    std::wstring error;
    std::wstring peerName;
    std::wstring fileName;
    std::wstring address;
    std::wstring dns;
    std::wstring endpoint;
    std::wstring allowedIps;
    std::wstring serverPublicKey;
};

using RequestHandler = std::function<Result(const Request&)>;
using LogHandler = std::function<void(const std::wstring&)>;

std::string WideToUtf8(const std::wstring& text);
std::wstring Utf8ToWide(const std::string& text);
std::string PercentEncode(const std::wstring& text);
std::wstring PercentDecode(const std::string& text);
std::string HexEncode(const BYTE* data, size_t size);
bool HexDecode(const std::string& text, BYTE* output, size_t size);
std::string Base64Encode(const BYTE* data, DWORD size);
bool Base64Decode(const std::string& text, BYTE* output, DWORD expectedSize);
bool GenerateRandom(BYTE* output, ULONG size);
bool DeriveAuthKey(const std::wstring& password, const std::array<BYTE, 16>& salt,
                   std::array<BYTE, 32>& key);
bool HmacSha256(const BYTE* key, ULONG keySize, const std::string& data,
                std::array<BYTE, 32>& digest);
bool ConstantTimeEqual(const BYTE* a, const BYTE* b, size_t size);

class Listener {
public:
    Listener() = default;
    ~Listener();
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    bool Start(unsigned short port, const std::wstring& password,
               RequestHandler handler, LogHandler logger,
               std::wstring& error);
    void Stop();
    bool Running() const { return running_.load(); }
    unsigned short Port() const { return port_; }

private:
    void AcceptLoop();
    void HandleClient(SOCKET client);
    void CloseTrackedClient(SOCKET client);
    void Log(const std::wstring& text) const;

    std::atomic<bool> running_{false};
    SOCKET listenSocket_ = INVALID_SOCKET;
    unsigned short port_ = 0;
    std::wstring password_;
    RequestHandler handler_;
    LogHandler logger_;
    std::thread acceptThread_;
    mutable std::mutex stateMutex_;
    std::mutex clientsMutex_;
    std::vector<SOCKET> clients_;
    std::mutex workersMutex_;
    std::vector<std::thread> workers_;
};

bool PerformRequest(const std::wstring& host, unsigned short port,
                    const std::wstring& password, const Request& request,
                    Result& result, std::wstring& error,
                    DWORD connectTimeoutMs = 10000);

} // namespace easywg_request
