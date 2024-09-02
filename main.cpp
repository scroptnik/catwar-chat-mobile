#include "D:/Scripts/Libs/boost_1_86_0/libs/beast/example/common/root_certificates.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <regex>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

class HTTPclient {
private:
    std::string host = "catwar.su";
    const char* port = "443";
    std::string const target = "/ajax/login";
    int version = 11;

    std::string get_token_cookie(const std::string& cookies)
    {
        std::regex rgx("token=.*?;");
        std::smatch match;

        if (std::regex_search(cookies.begin(), cookies.end(), match, rgx))
        {
            return match[0]; //token
        }
        return "";
    }

    std::string extractSid(const std::string& json) {
        std::string key = "\"sid\":\"";
        std::size_t start = json.find(key);
        if (start == std::string::npos) {
            return "";
        }

        start += key.length();
        std::size_t end = json.find("\"", start);

        if (end == std::string::npos) {
            return "";
        }

        return json.substr(start, end - start);
    }

    int json_parse(const std::string& json, const std::string& key) {
        int value = 0;
        std::string keySearch = "\"" + key + "\":";
        size_t pos = json.find(keySearch);

        if (pos != std::string::npos) {
            pos += keySearch.length();

            while (pos < json.length() && (json[pos] == ' ' || json[pos] == ',')) { ++pos; }

            std::stringstream ss;
            while (pos < json.length() && (json[pos] >= '0' && json[pos] <= '9')) {
                ss << json[pos];
                ++pos;
            }
            ss >> value;
        }
        return value;
    }

    void open_ssl() {
        std::cout << "Open SSL connection.\n";

        //load certificates
        load_root_certificates(ctx);
        ctx.set_verify_mode(ssl::verify_peer);

        if (!SSL_set_tlsext_host_name(stream.native_handle(), _strdup(host.c_str())))
        {
            beast::error_code ec{ static_cast<int>(::ERR_get_error()), net::error::get_ssl_category() };
            throw beast::system_error{ ec };
        }
    }

    void connect_ssl() {
        std::cout << "Handshake.\n";
        auto const results = resolver.resolve(host, port);
        beast::get_lowest_layer(stream).connect(results);
        stream.handshake(ssl::stream_base::client);
    }

    void login_post() {
        std::cout << "Send login request.\n";
        std::string data = "mail=" + mail + "&pass=" + pass + "&cat=0";

        http::request<http::string_body> req{ http::verb::post, target, version };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, "application/x-www-form-urlencoded; charset=UTF-8");
        req.body() = data;
        req.prepare_payload();

        http::write(stream, req);
    }

    void get_login_response() {
        std::cout << "Get login response.\n";
        beast::flat_buffer buffer;

        http::read(stream, buffer, res);

        std::stringstream ss;
        ss << beast::make_printable(res.body().data());
        std::string json_response = ss.str();

        
        if (json_response == "") {
            std::cerr << "\n\nEmpty response. Headers:\n\n";
            std::cout << res.base() << std::endl;
        }
        int state_val = json_parse(json_response, "state");

        switch (state_val)
        {
        case 0:
            std::cerr << "Error login. Wrong mail. \n(state=";
            std::cerr << state_val;
            std::cerr << ")" << std::endl;
            return ;
        case 1:
            std::cerr << "Error login. Wrong password. \n(state=";
            std::cerr << state_val;
            std::cerr << ")" << std::endl;
            return ;
        }

        if (res.result_int() == 200) {
            std::cout << "Login successful." << std::endl;
        }
        else {
            std::cout << "Login error. HTTP code: " << res.result_int() << std::endl;
        }
    }

    std::string get_token() {
        std::cout << "\nGet cookies.\n";
        std::string cookies;
        for (const auto& field : res.base()) {
            if (field.name() == http::field::set_cookie) {
                cookies += std::string(field.value()) + "; ";
            }
        }
        std::string token = get_token_cookie(cookies);
        if (token != "") {
            std::cout << token << std::endl;
            return token;
        }
        return "";
    }

    void chat_get() {
        std::cout << "\nSend get chat request.\n";
        {
            http::request<http::string_body> req{ http::verb::get, "/chat", version };
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            req.set(http::field::cookie, token);

            http::write(stream, req);

            beast::flat_buffer buf;

            http::response<http::string_body> response;

            http::read(stream, buf, response);

            if (response.result_int() == 200) {
                std::cout << "Chat get page successful." << std::endl;
            }
            else {
                std::cout << "Chat get page error. HTTP code: " << response.result_int() << std::endl;
            }
        }
    }

    std::string get_sid(std::string token) {
        std::cout << "\nGet socket sid.\n";
        std::string sid;

        std::cout << "Do request.\n";
        http::request<http::string_body> req{ http::verb::get, "/ws/chat/socket.io/?EIO=3&transport=polling", version };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
        req.set(http::field::cookie, "mobile=0; _ym_uid=1723871475115078676; _ym_d=1723871475;" + token + "; dshcheck = 1");
        req.set(http::field::accept_encoding, "gzip, deflate, br, zstd");
        req.set(http::field::accept_language, "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7");
        req.set(http::field::cache_control, "no-cache");
        req.set(http::field::connection, "keep-alive");
        req.set(http::field::origin, "https://catwar.su");
        req.set(http::field::pragma, "no-cache");

        http::write(stream, req);

        beast::flat_buffer buf;

        http::response<http::string_body> response;

        std::cout << "Get response.\n";
        http::read(stream, buf, response);

        if (response.result_int() == 200) {
            std::cout << "Get sid.\n";
            std::string json_response = response.body();
            std::cout << "Extract sid.\n";
            sid = extractSid(json_response);
            std::cout << "sid is " + sid << std::endl;
            return sid;
        }
        else {
            std::cout << "Error getting sid. HTTP code: " << response.result_int() << std::endl;
            std::cout << response.base() << std::endl;
            return "";
        }
    }

public:
    std::string sid;
    std::string token;

    std::string mail;
    std::string pass;

    net::io_context ioc;
    ssl::context ctx{ ssl::context::tlsv12_client };

    tcp::resolver resolver{ ioc };
    beast::ssl_stream<beast::tcp_stream> stream{ioc, ctx};

    http::response<http::dynamic_body> res;

    int login() {
        if (mail == "" || pass == "") {
            std::cerr << "Mail or password can't be empty.\n";
            return 1;
        }

        open_ssl();
        connect_ssl();
        login_post();
        get_login_response();
        token = get_token();
        if (token == "") { 
            std::cerr << "Token is empty.\n";
            return 1; 
        }
        chat_get();
        sid = get_sid(token);
        if (sid == "") {
            std::cerr << "sid is empty.\n";
            return 1;
        }

        beast::error_code ec;
        stream.shutdown(ec);
        if (ec == net::error::eof || ec == boost::asio::ssl::error::stream_truncated)
        {
            ec = {};
        }
        if (ec)
            throw beast::system_error{ ec };

        return 0;
    }

};

class WebSocket_client : public std::enable_shared_from_this<WebSocket_client> {
private:
    std::unique_ptr<websocket::stream<beast::ssl_stream<beast::tcp_stream>>> ws;
    beast::flat_buffer buffer;
public:
    
    int connect(HTTPclient& httpclient) {
        std::cout << "\nWebSocket connecting.\n";
        httpclient.stream.handshake(ssl::stream_base::client);

        ws = std::make_unique<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(std::move(httpclient.stream));
        ws->set_option(websocket::stream_base::decorator(
            [&httpclient](beast::websocket::request_type& req) {
                req.set(beast::http::field::cookie, "mobile=0; _ym_uid=1723871475115078676; _ym_d=1723871475; " + httpclient.token + "; dshcheck = 1");
            }));

        ws->async_handshake("catwar.su", "/ws/chat/socket.io/?EIO=3&transport=websocket&sid=" + httpclient.sid,
            [self = shared_from_this()](beast::error_code ec) {
                if (!ec) {
                    std::cout << "WebSocket connected with SSL." << std::endl;
                }
                else {
                    std::cerr << "Handshake failed: " << ec.message() << std::endl;
                }
            });
        std::cout << "WebSocket connected with SSL." << std::endl;
        return 0;
    }
};

class App {
private:
    std::shared_ptr<WebSocket_client> WSclient;
public:
    HTTPclient httpclient;
    App() : WSclient(std::make_shared<WebSocket_client>()) {}
    void start() {
        httpclient.login();
        WSclient -> connect(httpclient);
    }
};

int main() {
    setlocale(LC_ALL, ".1251");

    App app;
    app.httpclient.mail = "catwar-macros@ya.ru";
    app.httpclient.pass = "kolya123.";

    try { app.start(); } 
    catch (std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

}
