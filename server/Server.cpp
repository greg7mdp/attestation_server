#include "Server.h"

Server::Server()
{
    loadConfig();
}

void Server::loadConfig()
{
    // --------------- should be loaded from .cfg file --------------------------
    static std::vector<std::string> peer_public_keys{
        "aKEkMFcHKoLccP3PeMWEKT7LGpCjT9CYwjosmo2f8e1M17KwznxG",
        "aKGWPfe6xHXuH5BAALh1CRZHRKxUf4Lc2sGr5RY7ok68LTeehVQN",
        "aKECvjC2fpvYXwDEjFfM88r6mcTEWi8QLJG4BrwfWxzWocgWDACW",
        "aKEQ5XRxaVq6XQwZ3p3WYrxZCb4SMEW3z4rjYT3LnFtyihm4BreC",
        "aKEyRPH8uRMrXvzuEVXzzjiBH6czFEeytC7QmAaizj5fhAYq7nHS"};

    static std::vector<std::string> peer_secret_keys{
        "sskH8Ap41pXLFoi9RUxV9V4iFURHX",
        "safwSMn1NWC13He3Kde5GXXB52B2K",
        "shA5avWzSCVXfazdtQ1eunYKHZ7WG",
        "ssPS3FAbyhifxYFZeNufya4NsaL5g",
        "shsqhawQM2zGBoYeh8wpHB8c5pEAd"};

    static std::string signing_key{"safwSMn1NWC13He3Kde5GXXB52B2K"};
    static std::string mainchain_account{"rEEw6AmPHD28M5AHyrzFSVoLA3oANcmYas"};
    static std::string mainchain_ip{"127.0.0.1"};
    static std::string mainchain_port_ws{"6007"};
    // --------------------------------------------------------------------------

    cfg_.sntp_servers = {"time.windows.com", "time.apple.com", "time.nist.gov", "pool.ntp.org"};

    cfg_.db_path = "C:/greg/ripple/att_svr/nudb";
}
