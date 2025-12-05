#include "keystore_client.h"

#include "common/common.h"
#include "common/shared_library.h"
#include "keystore.pb.h"
#include "webapp/app_resolver_handle.h"

#include <thread>

NDSEC_NAMESPACE_BEGIN(cert::keystore)

class KeystoreClientImpl:public KeystoreClient{
public:
  explicit KeystoreClientImpl(const std::string &resolver_library_file,
                    const std::string &resolver_config)
      : resolver_library_handle_(resolver_library_file),
        resolver_impl_(make_app_resolver(resolver_config)) {}

  std::string submit_internal_task(const std::string &query_name, const std::string &content) override{
    webapp::AppRequest request{};
    request.query_name = query_name;
    request.content = content;
    request.content_type = "application/protobuf";
    webapp::AppResponse response{};
    resolver_impl_->resolve(request, response);
    return response.content.to_str();
  }

  std::string send_request_raw(const std::string &query_name,
                         const std::string &content) const override{
    webapp::AppRequest request{};

    request.query_name = query_name;
    request.content = content;
    request.content_type = "application/protobuf";

    webapp::AppResponse response{};
    resolver_impl_->resolve(request, response);

    return response.content.to_str();
  }

private:
  std::shared_ptr<webapp::AppResolver>
  make_app_resolver(const std::string &config_content) const {
#define stringify(s) stringify_(s)
#define stringify_(s) #s
    auto resolver_init_api_name = stringify(WEBAPP_RESOLVER_FUNC_resolver_init);
#undef stringify
#undef stringify_

    using ResolverInitFunc = webapp::NativeAppResolver(const char *json_config,
                                                       size_t json_config_size);
    const std::function<ResolverInitFunc> resolver_init_func =
        resolver_library_handle_.get<ResolverInitFunc>(resolver_init_api_name);
    if (!resolver_init_func) {
      throw common::Exception{0x1, "failed to load resolver library"};
    }

    auto native_app_resolver = resolver_init_func(config_content.c_str(), config_content.size());
    auto native=webapp::AppResolver::from_native(native_app_resolver);
    return native;
  }

private:
  common::SharedLibrary resolver_library_handle_;
  std::shared_ptr<webapp::AppResolver> resolver_impl_;
};

std::shared_ptr<KeystoreClient>
KeystoreClient::make(const std::string &resolver_library_file,
               const std::string &resolver_config) {
  return std::make_shared<KeystoreClientImpl>(resolver_library_file, resolver_config);
}

template <typename Response, typename Request>
    Response KeystoreClient::send_request(const std::string &query_name, const Request &request) const{
  auto response_string =
      this->send_request_raw(query_name, request.SerializePartialAsString());

  Response response{};
  if (!response.ParsePartialFromString(response_string)) {
    throw common::Exception{0x1, "failed to parse response"};
  }
  return response;
}

template ndsec::keystore::payload::KeyAccessResponse
KeystoreClient::send_request<ndsec::keystore::payload::KeyAccessResponse,
                             ndsec::keystore::payload::KeyAccessRequest>(
    const std::string &query_name,
    const ndsec::keystore::payload::KeyAccessRequest &request) const;

template ndsec::keystore::payload::VirtFileOperationResponse
KeystoreClient::send_request<ndsec::keystore::payload::VirtFileOperationResponse,
                             ndsec::keystore::payload::VirtFileOperationRequest>(
    const std::string &query_name,
    const ndsec::keystore::payload::VirtFileOperationRequest &request) const;

template ndsec::keystore::payload::CertByUniqueResponse
KeystoreClient::send_request<ndsec::keystore::payload::CertByUniqueResponse,
                             ndsec::keystore::payload::CertByUniqueRequest>(
    const std::string &query_name,
    const ndsec::keystore::payload::CertByUniqueRequest &request) const;

template ndsec::keystore::payload::CertByChainResponse
KeystoreClient::send_request<ndsec::keystore::payload::CertByChainResponse,
                             ndsec::keystore::payload::CertByChainRequest>(
    const std::string &query_name,
    const ndsec::keystore::payload::CertByChainRequest &request) const;

template ndsec::keystore::payload::CertByCaResponse
KeystoreClient::send_request<ndsec::keystore::payload::CertByCaResponse,
                             ndsec::keystore::payload::CertByCaRequest>(
    const std::string &query_name,
    const ndsec::keystore::payload::CertByCaRequest &request) const;

template ndsec::keystore::payload::FileByNameResponse
KeystoreClient::send_request<ndsec::keystore::payload::FileByNameResponse,
                             ndsec::keystore::payload::FileByNameRequest>(
    const std::string &query_name,
    const ndsec::keystore::payload::FileByNameRequest &request) const;

NDSEC_NAMESPACE_END
