#include "D:/Scripts/Libs/boost_1_86_0/libs/beast/example/common/root_certificates.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <regex>
#include "xpath_static.h"
#include "xpath_processor.h"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;


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

std::string get_token_cookie(const std::string& cookies)
{
    std::regex rgx("token=.*?;");
    std::smatch match;

    if (std::regex_search(cookies.begin(), cookies.end(), match, rgx))
    {
        return match[0]; //token
    }    
}

int main(int argc, char** argv)
{
    setlocale(LC_ALL, "ru_RU.utf-8");

    std::string mail = "catwar-macros@ya.ru";
    std::string pass = "kolya123.";

    std::string data = "mail=" + mail + "&pass=" + pass + "&cat=0";

    try
    {
        auto const host = "catwar.su";
        auto const port = "443";
        auto const target = "/ajax/login";
        int version = 11;

        net::io_context ioc;

        ssl::context ctx(ssl::context::tlsv12_client);

        load_root_certificates(ctx);

        ctx.set_verify_mode(ssl::verify_peer);

        tcp::resolver resolver(ioc);
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

        if (!SSL_set_tlsext_host_name(stream.native_handle(), host))
        {
            beast::error_code ec{ static_cast<int>(::ERR_get_error()), net::error::get_ssl_category() };
            throw beast::system_error{ ec };
        }

        auto const results = resolver.resolve(host, port);

        beast::get_lowest_layer(stream).connect(results);

        stream.handshake(ssl::stream_base::client);

        std::cout << "Send login request.\n";
        http::request<http::string_body> req{ http::verb::post, target, version };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, "application/x-www-form-urlencoded; charset=UTF-8");
        req.body() = data;
        req.prepare_payload();

        http::write(stream, req);

        beast::flat_buffer buffer;

        http::response<http::dynamic_body> res;

        http::read(stream, buffer, res);

      //  std::cout << "\n\n" << std::endl;

        std::stringstream ss;
        ss << beast::make_printable(res.body().data());
        std::string json_response = ss.str();


        int state_val = json_parse(json_response, "state");

        switch (state_val)
        {
        case 0:
            std::cerr << "Error login. Wrong mail. \n(state=";
            std::cerr << state_val;
            std::cerr << ")" << std::endl;
            return 1;
        case 1:
            std::cerr << "Error login. Wrong password. \n(state=";
            std::cerr << state_val;
            std::cerr << ")" << std::endl;
            return 1;
        }

        if (res.result_int() == 200) {
            std::cout << "Login successful." << std::endl; 
        }
        else {
            std::cout << "Login error. HTTP code: " << res.result_int() << std::endl;
        }

        std::cout << "\nGet cookies.\n";
        std::string cookies;
        for (const auto& field : res.base()) {
            if (field.name() == http::field::set_cookie) {
                cookies += std::string(field.value()) + "; ";
            }
        }
        std::string token = get_token_cookie(cookies);
      //  std::cout << cookies << std::endl << std::endl;
        std::cout << "\nSend get chat request.\n";
        for (int i = 0; i < 10; i++) {
            http::request<http::string_body> req_get{ http::verb::get, "/chat", version };
            req_get.set(http::field::host, host);
            req_get.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            req_get.set(http::field::cookie, token);

            http::write(stream, req_get);

            beast::flat_buffer buf;

            http::response<http::string_body> response;

            http::read(stream, buffer, response);

            if (response.result_int() == 200) {
                std::cout << "Chat get page successful." << std::endl;
            }
            else {
                std::cout << "Chat get page error. HTTP code: " << response.result_int() << std::endl;
            }

        }

        beast::error_code ec;
        stream.shutdown(ec);
        if (ec == net::error::eof || ec == boost::asio::ssl::error::stream_truncated)
        {
            ec = {};
        }
        if (ec)
            throw beast::system_error{ ec };

    }
    catch (std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
