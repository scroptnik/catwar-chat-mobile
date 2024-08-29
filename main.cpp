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


#pragma region funcs

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

std::string extractSid(const std::string& json) {
    std::string key = "\"sid\":\"";
    std::size_t start = json.find(key);
    if (start == std::string::npos) {
        return ""; // Возвращаем пустую строку, если ключ не найден
    }

    start += key.length(); // Начинаем после ключа "sid":
    std::size_t end = json.find("\"", start); // Ищем закрывающую кавычку

    if (end == std::string::npos) {
        return ""; // Возвращаем пустую строку, если закрывающая кавычка не найдена
    }

    return json.substr(start, end - start); // Извлекаем значение sid
}
#pragma endregion funcs

int main(int argc, char** argv)
{
    setlocale(LC_ALL, ".1251");

    std::string mail = "";
    std::string pass = "";

    auto host = "catwar.su";
    const char* port = "443";
    auto const target = "/ajax/login";
    int version = 11;

    std::string data = "mail=" + mail + "&pass=" + pass + "&cat=0";

    try
    {
    #pragma region login POST
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
    #pragma endregion login POST

        #pragma region chat GET
        std::cout << "\nGet cookies.\n";
        std::string cookies;
        for (const auto& field : res.base()) {
            if (field.name() == http::field::set_cookie) {
                cookies += std::string(field.value()) + "; ";
            }
        }
        std::string token = get_token_cookie(cookies);

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
        #pragma endregion chat GET

        std::cout << "\nGet socket sid.\n";
        std::string sid;
        { // get sid
            http::request<http::string_body> req{ http::verb::get, "/ws/chat/socket.io/?EIO=3&transport=polling", version };
            req.set(http::field::host, host);
            req.set(http::field::user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
            req.set(http::field::cookie, "mobile=0; _ym_uid=1723871475115078676; _ym_d=1723871475; token=; dshcheck=1");
            req.set(http::field::accept_encoding, "gzip, deflate, br, zstd");
            req.set(http::field::accept_language, "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7");
            req.set(http::field::cache_control, "no-cache");
            req.set(http::field::connection, "keep-alive");
            req.set(http::field::origin, "https://catwar.su");
            req.set(http::field::pragma, "no-cache");


            http::write(stream, req);

            beast::flat_buffer buf;

            http::response<http::string_body> response;

            http::read(stream, buf, response);

            if (response.result_int() == 200) {
                std::string json_response = response.body();
                sid = extractSid(json_response);
            }
            else {
                std::cout << "Error getting sid. HTTP code: " << response.result_int() << std::endl;
                std::cout << response.base() << std::endl;
                return 1;
            }
            
        }

        { // websocket
            stream.handshake(ssl::stream_base::client);

            beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws(std::move(stream));

            ws.set_option(beast::websocket::stream_base::decorator(
                [](beast::websocket::request_type& req) {
                    req.set(beast::http::field::cookie, "mobile=0; _ym_uid=1723871475115078676; _ym_d=1723871475; token=; dshcheck=1");
                }));

            ws.handshake("catwar.su", "/ws/chat/socket.io/?EIO=3&transport=websocket&sid="+sid);

            std::cout << "WebSocket подключение установлено через SSL!" << std::endl;

            ws.write(net::buffer(std::string("2probe")));

            // Буфер для хранения принятого сообщения
            beast::flat_buffer buffer;

            // Читаем сообщение
            ws.read(buffer);

            // Выводим полученное сообщение
            std::cout << "Received: " << beast::make_printable(buffer.data()) << std::endl;

            // Закрываем WebSocket соединение
            ws.close(websocket::close_code::normal);
        }
         

    #pragma region end
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
    #pragma endregion end

    return EXIT_SUCCESS;
}
