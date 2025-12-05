// CERT BY CA CASES

TEST_F(SvsPerf, CertByCa) {

  std::vector<std::string> alias_names{
    "sign_cert",
    "ca_cert",
  };

  for (const auto &alias : alias_names) {
    std::vector<param_t> params{
          {.name="alias_name", .value_name=alias},
      };

    benchmark->add({
      .name = fmt::format("cert_ca_{}", alias),
      .max_times = max_times,
      .params = params,
      .actor = std::make_unique<cert_ca_actor>(*client_),
    });
  }
}
