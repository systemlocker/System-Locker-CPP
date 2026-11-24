#include "syslocker/http.hpp"
#include "util.hpp"

#include <curl/curl.h>

#include <atomic>
#include <mutex>
#include <limits>

namespace syslocker
{

    namespace
    {

        std::once_flag g_curlInit;

        void ensureCurlInit()
        {
            std::call_once(g_curlInit, []
                           {
                               ::curl_global_init(CURL_GLOBAL_DEFAULT);
                               // We deliberately never call curl_global_cleanup. It is not safe in
                               // process-shutdown contexts where other libraries may also be using
                               // libcurl, and the OS will reclaim the resources anyway.
                           });
        }

        struct WriteState
        {
            std::string &body;
            std::size_t maximum;
        };

        std::size_t writeCb(char *ptr, std::size_t size, std::size_t nmemb, void *userdata)
        {
            auto &out = *static_cast<WriteState *>(userdata);
            if (size && nmemb > (std::numeric_limits<std::size_t>::max)() / size)
                return 0;
            const std::size_t bytes = size * nmemb;
            if (bytes > out.maximum || out.body.size() > out.maximum - bytes)
                return 0;
            try { out.body.append(ptr, bytes); }
            catch (...) { return 0; }
            return bytes;
        }

        std::size_t headerCb(char *ptr, std::size_t size, std::size_t nmemb, void *userdata)
        {
            auto &response = *static_cast<HttpResponse *>(userdata);
            const std::string_view line(ptr, size * nmemb);
            // A proxy may send an intermediate CONNECT/header block.
            if (detail::startsWith(line, "HTTP/"))
                response.headers.clear();
            const auto colon = line.find(':');
            if (colon != std::string_view::npos)
                response.headers[detail::toLowerCopy(detail::trim(line.substr(0, colon)))] =
                    std::string(detail::trim(line.substr(colon + 1)));
            return size * nmemb;
        }

        class CurlHttpClient final : public IHttpClient
        {
        public:
            explicit CurlHttpClient(CurlHttpOptions opts) : opts_(std::move(opts))
            {
                ensureCurlInit();
            }

            HttpResponse post(std::string_view url, const FormFields &form) override
            {
                return request("POST", url, detail::encodeForm(form),
                               {{"Content-Type", "application/x-www-form-urlencoded"},
                                {"Accept", "text/plain, */*"}});
            }

            HttpResponse request(std::string_view method, std::string_view url,
                                 std::string_view requestBody, const HttpHeaders &requestHeaders) override
            {
                HttpResponse resp;

                if (!detail::startsWith(url, "https://"))
                {
                    resp.error = "refusing non-https url";
                    return resp;
                }

                CURL *curl = ::curl_easy_init();
                if (!curl)
                {
                    resp.error = "curl_easy_init failed";
                    return resp;
                }

                const std::string body(requestBody);
                const std::string verb(method);
                const std::string urlStr(url);
                // Auth and management envelopes are bounded before parsing.
                // File bytes retain the legacy in-memory download behavior.
                bool download = false;
                for (const auto &[name, value] : requestHeaders)
                    if (name == "X-Invisiblefolder-Download" && value == "1") download = true;
                WriteState writeState{resp.body, download ? (std::numeric_limits<std::size_t>::max)() : 1024 * 1024};

                ::curl_easy_setopt(curl, CURLOPT_URL, urlStr.c_str());
                if (verb != "GET")
                {
                    ::curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
                    ::curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
                }
                ::curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, verb.c_str());
                ::curl_easy_setopt(curl, CURLOPT_USERAGENT, opts_.userAgent.c_str());
                ::curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(opts_.timeout.count()));
                ::curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
                ::curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
                ::curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
                ::curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeState);
                ::curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCb);
                ::curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp);

                // Strict TLS settings — defend against TLS-MITM proxies and
                // attackers who might attempt to replace systemlocker.net with a
                // spoofed endpoint.
                ::curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
                ::curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
                ::curl_easy_setopt(curl, CURLOPT_SSLVERSION,
                                   static_cast<long>(CURL_SSLVERSION_TLSv1_2));

                if (!opts_.pinnedPublicKey.empty())
                {
                    ::curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY,
                                       opts_.pinnedPublicKey.c_str());
                }

                struct curl_slist *headers = nullptr;
                for (const auto &[name, value] : requestHeaders)
                {
                    if (name.find_first_of("\r\n") != std::string::npos ||
                        value.find_first_of("\r\n") != std::string::npos)
                    {
                        resp.error = "invalid HTTP header";
                        ::curl_slist_free_all(headers);
                        ::curl_easy_cleanup(curl);
                        return resp;
                    }
                    headers = ::curl_slist_append(headers, (name + ": " + value).c_str());
                }
                // Refuse cleartext fallbacks at the protocol level too.
                ::curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                char errbuf[CURL_ERROR_SIZE]{};
                ::curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

                const CURLcode rc = ::curl_easy_perform(curl);
                if (rc != CURLE_OK)
                {
                    resp.error = errbuf[0] ? errbuf : ::curl_easy_strerror(rc);
                }
                else
                {
                    long code = 0;
                    ::curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
                    resp.status = code;
                }

                ::curl_slist_free_all(headers);
                ::curl_easy_cleanup(curl);
                return resp;
            }

        private:
            CurlHttpOptions opts_;
        };

    } // namespace

    std::unique_ptr<IHttpClient> makeCurlHttpClient(CurlHttpOptions opts)
    {
        return std::make_unique<CurlHttpClient>(std::move(opts));
    }

} // namespace syslocker
