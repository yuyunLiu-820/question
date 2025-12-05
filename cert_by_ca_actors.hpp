
struct cert_ca_actor : public actor_t {
  explicit cert_ca_actor(cert::keystore::KeystoreClient& client)
    : client_(client), alias_name_(), result_cert_(), result_ocsp_() {}

  void init(const std::vector<param_t> &params) override {
    alias_name_ = params[0].value_name;
  }

  result_t run() override {
    int rv = KS_SUCCESS;
    ndsec::keystore::payload::CertByCaRequest req;
    ndsec::keystore::payload::CertByCaResponse resp;

    try {
      req.set_alias_name(alias_name_);

      resp = client_.send_request<ndsec::keystore::payload::CertByCaResponse>(
                "/internal/cert/ca", req);

      result_cert_ = resp.cert_pem();
      result_ocsp_ = resp.ocsp_url();
    } catch (common::Exception &e) {
      rv = static_cast<int>(e.get_error_code());
    }

    return {
      .rv = rv,
      .request_bytes = req.ByteSizeLong(),
      .response_bytes = resp.ByteSizeLong(),
    };
  }

protected:
  cert::keystore::KeystoreClient& client_;
  std::string alias_name_;
  std::string result_cert_;
  std::string result_ocsp_;
};
