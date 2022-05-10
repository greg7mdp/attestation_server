#ifndef SERVER_H_INCLUDED
#define SERVER_H_INCLUDED

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <libxrpl/SecretKey.h>

struct ServerConfig
{
    xrpl::PublicKey public_key;
    xrpl::SecretKey secret_key;

    std::vector<xrpl::PublicKey> peer_public_keys;
    std::vector<xrpl::SecretKey> peer_secret_key;
    std::vector<std::string> sntp_servers;

    std::string db_path;

    xrpl::Port rpc;
    xrpl::Port ws;
};

class Server
{
private:
    ServerConfig cfg_;

public:
    Server();

private:
    void loadConfig();
};

#endif  // SERVER_H_INCLUDED
