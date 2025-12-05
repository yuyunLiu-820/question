#include "perf/perf_common.hpp"
#include "keystore_client.h"
#include "keystore.pb.h"
#include <argparse/arg_parser.h>
#include <argparse/argparse.hpp>
#include <fmt/format.h>
#include <gtest/gtest.h>
#include "util/error_code.h"
#include "util/util.h"
#include <iostream>
#include <csignal>
#include <execinfo.h>
#include <unistd.h>

#define KS_SUCCESS 0

NDSEC_NAMESPACE_BEGIN(cert::keystore)

class ApiPerfTest : public testing::Test {
public:
  void SetUp() override {
    //resolver_file_ = "libgm_cert_resolver.so";
    resolver_file_ = "libkeystore.so";
    resolver_config_={
      {"storage_host","mariadb"},
      {"storage_port","3306"},
      {"storage_database","totp-admin"},
      {"storage_user","root"},
      {"storage_pwd","root"},
      {"log_resolver_name", "__stub__"},
      {"crypto_device_resolver_name", "__stub__"},
      {"system_resolver_name", "__stub__"},
      {"task_manager_name", "__stub__"},
    };
    /*resolver_config_={
          {"storage_file", "sysconf.db"},
          {"storage_password", "12345678"},
          {"log_resolver_name", "__stub__"},
          {"crypto_device_resolver_name", "__stub__"},
          {"system_resolver_name", "__stub__"},
          {"task_manager_name", "__stub__"},
    };*/

    setenv("GM_CERT_KEY_JSON_FILE", "keys.json", 1);

    client_ = KeystoreClient::make(resolver_file_, resolver_config_.dump());
    benchmark = std::make_unique<Benchmark>();
  }
  void TearDown() override {
    benchmark->run(num_threads);
    std::cout << "it's over one"<<std::endl;
    benchmark.reset();
  }

protected:
  std::unique_ptr<Benchmark> benchmark;
  std::shared_ptr<KeystoreClient> client_;
  std::string resolver_file_;
  common::json resolver_config_;
public:
  inline static size_t max_times;
  inline static size_t num_threads;
};

using SvsPerf = ApiPerfTest;
// #include "perf/key_export_actors.hpp"
// #include "perf/key_export_cases.hpp"
// #include "perf/file_operation_actors.hpp"
// #include "perf/file_operation_cases.hpp"
// #include "perf/cert_by_unique_actions.hpp"
// #include "perf/cert_by_unique_cases.hpp"
// #include "perf/cert_by_chain_actors.hpp"
// #include "perf/cert_by_chain_cases.hpp"
#include "perf/cert_by_ca_actors.hpp"
#include "perf/cert_by_ca_cases.hpp"
// #include "perf/file_name_actions.hpp"
// #include "perf/file_name_cases.hpp"

NDSEC_NAMESPACE_END

void init_gtest(const std::vector<std::string> &args) {
  auto argc = static_cast<int>(args.size());
  std::vector<char *> raw_args;
  std::transform(args.begin(), args.end(), std::back_inserter(raw_args),
                 [](const auto &x) { return const_cast<char *>(x.c_str()); });
  ::testing::InitGoogleTest(&argc, raw_args.data());
}

/*void sigsegv_handler(int sig) {
  void* array[50];
  size_t size = backtrace(array, 50);
  std::cerr << "Caught signal " << sig << " (SIGSEGV / 139), stack trace:\n";
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  _exit(1); // 立即退出
}*/

#include <iostream>
#include <thread>
#include <fstream>
#include <string>

/*void print_system_info() {
  unsigned int n_threads = std::thread::hardware_concurrency();
  std::cout << "CPU逻辑核心数: " << n_threads << std::endl;
  std::ifstream meminfo("/proc/meminfo");
  std::string line;
  while (std::getline(meminfo, line)) {
    if (line.find("MemTotal") != std::string::npos) {
      std::cout << "系统内存: " << line << std::endl;
      break;
    }
  }
  std::ifstream cpuinfo("/proc/cpuinfo");
  while (std::getline(cpuinfo, line)) {
    if (line.find("model name") != std::string::npos) {
      std::cout << "CPU型号: " << line.substr(line.find(":") + 2) << std::endl;
      break;
    }
  }
}*/

int main(int argc, char *argv[]) {
  // --- 注册 SIGSEGV 处理 ---
  /*struct sigaction sa;
  sa.sa_handler = sigsegv_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGSEGV, &sa, nullptr);*/

  /*unsigned int n_cpus = std::thread::hardware_concurrency();
  std::cout << "========================================" << std::endl;
  std::cout << "性能测试 - 系统信息" << std::endl;
  std::cout << "========================================" << std::endl;
  std::cout << "CPU逻辑核心数: " << n_cpus << std::endl;
  std::ifstream meminfo("/proc/meminfo");
  std::string line;
  while (std::getline(meminfo, line)) {
    if (line.find("MemTotal") != std::string::npos) {
      std::cout << "系统总内存: " << line.substr(line.find(":") + 2) << std::endl;
      break;
    }
  }
  std::ifstream cpuinfo("/proc/cpuinfo");
  while (std::getline(cpuinfo, line)) {
    if (line.find("model name") != std::string::npos) {
      std::cout << "CPU型号: " << line.substr(line.find(":") + 2) << std::endl;
      break;
    }
  }
  std::cout << "========================================" << std::endl << std::endl;*/


  args::ArgumentParser parser("NDSec SVS/STF performance benchmark tool");
  args::HelpFlag help(parser, "help", "display this help menu", {'h', "help"});

  args::ValueFlag<std::string> device_config_file_(
      parser, "", "path of device config json file", {'c', "config"});
  args::ValueFlag<size_t> max_times_(
      parser, "", "loop times of each test (default: 10000)", {"times"}, 10000);
  args::ValueFlag<size_t> loop_times_(
      parser, "", "loop times of all tests (default: 1)", {'l', "loop"}, 1);
  auto num_cpus = std::thread::hardware_concurrency();
  args::ValueFlag<size_t> num_threads_(
      parser, "", fmt::format("num threads (default: {})", num_cpus),
      {"num_threads", "num-threads"}, num_cpus);

  args::parse(parser, argc, argv);

  namespace perf = ndsec::cert::keystore;
  perf::ApiPerfTest::max_times = args::get(max_times_);
  perf::ApiPerfTest::num_threads = args::get(num_threads_);
  init_gtest({argv[0],fmt::format("--gtest_repeat={}", args::get(loop_times_)),
  });

  return RUN_ALL_TESTS();
}
