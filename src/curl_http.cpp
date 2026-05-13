#include "syslocker/http.hpp"
#include "util.hpp"

#include <curl/curl.h>

#include <atomic>
#include <mutex>

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

        std::size_t writeCb(char *ptr, std::size_t size, std::size_t nmemb, void *userdata)
        {
            auto *out = static_cast<std::string *>(userdata);
            const std::size_t bytes = size * nmemb;
            out->append(ptr, bytes);
            return bytes;
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

                const std::string body = detail::encodeForm(form);
                const std::string urlStr(url);

                ::curl_easy_setopt(curl, CURLOPT_URL, urlStr.c_str());
                ::curl_easy_setopt(curl, CURLOPT_POST, 1L);
                ::curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
                ::curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
                ::curl_easy_setopt(curl, CURLOPT_USERAGENT, opts_.userAgent.c_str());
                ::curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(opts_.timeout.count()));
                ::curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
                ::curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
                ::curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
                ::curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);

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
                headers = ::curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
                headers = ::curl_slist_append(headers, "Accept: text/plain, */*");
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
