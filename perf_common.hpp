#pragma once

#include "common/common.h"
#include "common/exception.h"
#include "common/filesystem.h"
#include "common/timer.h"

#include "util/util.h"

#include <atomic>
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <future>
#include <iostream>
#include <numeric>
#include <sstream>

#include <fmt/format.h>

NDSEC_NAMESPACE_BEGIN(cert::keystore)

std::string stringify_size(size_t value) {
  if (value < 1024UL) {
    return fmt::format("{}B", value);
  } else if (value < 1024 * 1024UL) {
    return fmt::format("{}KB", value / 1024);
  } else if (value < 1024 * 1024 * 1024UL) {
    return fmt::format("{}MB", value / 1024 / 1024);
  } else if (value < 1024 * 1024 * 1024 * 1024UL) {
    return fmt::format("{}GB", value / 1024 / 1024 / 1024);
  }

  return fmt::format("{}B", value);
}

size_t parse_size_literal(const std::string &literal) {
  char *end_ptr{};
  auto value = std::strtod(literal.c_str(), &end_ptr);
  if (end_ptr < literal.c_str() + literal.size()) {
    std::string unit{end_ptr, literal.size() - (end_ptr - literal.c_str())};
    boost::to_upper(unit);
    if (unit == "B") {
      value *= 1;
    } else if (unit == "KB") {
      value *= 1024;
    } else if (unit == "MB") {
      value *= 1024 * 1024;
    } else if (unit == "GB") {
      value *= 1024 * 1024 * 1024;
    } else {
      throw common::Exception{0x1, "size unit is not supported: {}", unit};
    }
  }

  return std::floor(value);
}

using handle_t = void *;
using return_t = int;

struct param_t {
  std::string name;
  size_t value{};
  std::string value_name{}; ///< optional for logging
  bool flag;
};

struct result_t {
  int rv;
  size_t request_bytes;
  size_t response_bytes;
};

class actor_t {
public:
  actor_t(){}

  virtual ~actor_t() = default;

  void init_params(const std::vector<param_t> &params) {
    init(params);
  }

  virtual result_t run() = 0;

protected:
  virtual void init(const std::vector<param_t> &params) = 0;
};

struct item_t {
  std::string name;
  size_t max_times;
  std::vector<param_t> params;
  std::unique_ptr<actor_t> actor;

  struct ItemResult {
    double time_secs;
    size_t request_bytes;
    size_t response_bytes;
    size_t num_passed_tasks;
  };

  ItemResult run(size_t num_threads) const {
    actor->init_params(params);

    struct PartialResult {
      size_t request_bytes;
      size_t response_bytes;
      size_t num_passed_tasks;
    };

    size_t tasks_per_thread =
        max_times / num_threads + (max_times % num_threads != 0);
    std::vector<std::thread> threads{};
    std::vector<PartialResult> thread_results(num_threads);

    // for thread synchronization
    std::atomic<size_t> num_ready_threads{0};
    std::atomic<bool> emit_task_signal{false};

    // create task threads
    for (size_t i = 0; i < num_threads; ++i) {
      auto &thread_result = thread_results[i];
      threads.emplace_back([this, tasks_per_thread, &thread_result,
                            &num_ready_threads, &emit_task_signal]() {
        ++num_ready_threads;
        while (!emit_task_signal) {
          std::this_thread::yield();
        }

        for (size_t j = 0; j < tasks_per_thread; ++j) {
          auto task_result = actor->run();
          if (task_result.rv != 0) {
            printf("error code: %x\n", task_result.rv);
            continue;
          }

          thread_result.request_bytes += task_result.request_bytes;
          thread_result.response_bytes += task_result.response_bytes;
          thread_result.num_passed_tasks++;
        }
      });
    }

    common::Timer timer{};
    {
      // wait all threads to be ready
      while (num_ready_threads != num_threads) {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
      }
      // notify all threads to do tasks
      timer.reset();
      emit_task_signal = true;
      // wait all threads to be done
      for (auto &t : threads) {
        t.join();
      }
    }
    auto total_time_secs = timer.peek_msf() / 1e3;

    // merge thread results
    auto result = std::accumulate(
        thread_results.begin(), thread_results.end(), PartialResult{},
        [](const PartialResult &x, const PartialResult &y) {
          return PartialResult{
              .request_bytes = x.request_bytes + y.request_bytes,
              .response_bytes = x.response_bytes + y.response_bytes,
              .num_passed_tasks = x.num_passed_tasks + y.num_passed_tasks,
          };
        });

    // evaluate results
    auto get_xps = [&](size_t num_bytes) {
      return static_cast<double>(num_bytes) / total_time_secs;
    };
    fmt::print("[{}]: OUT={:.3f}MBps IN={:.3f}MBps {:>8.3f}Tps\n", to_str(),
               get_xps(result.request_bytes) / 1048576,
               get_xps(result.response_bytes) / 1048576,
               get_xps(result.num_passed_tasks));
    return ItemResult{total_time_secs, result.request_bytes, result.response_bytes, result.num_passed_tasks};
  }

  [[nodiscard]] std::string to_str() const {
    fmt::memory_buffer out;
    fmt::format_to(out, "{}", name);

    for (const auto &param : params) {
      if (param.value_name.empty()) {
        fmt::format_to(out, "/{}={}", param.name, param.value);
      } else {
        fmt::format_to(out, "/{}={}", param.name, param.value_name);
      }
    }
    return fmt::to_string(out);
  }
};

class Benchmark {

public:
  explicit Benchmark(){}

  ~Benchmark() {std::cout<<"~Benchmark"<<std::endl;}

  void add(item_t item) { items_.emplace_back(std::move(item)); }

  void run(size_t num_threads) {
    size_t total_req_bytes = 0;
    size_t total_resp_bytes = 0;
    size_t total_tasks = 0;
    double total_time = 0.0;

    std::unordered_map<std::string,item_t::ItemResult> key_type_results;  // 导出按照type分类

    for (const auto &item : items_) {
      auto r=item.run( num_threads);
      total_req_bytes += r.request_bytes;
      total_resp_bytes += r.response_bytes;
      total_tasks += r.num_passed_tasks;
      total_time += r.time_secs;

      /*if (item.name.find("export_key") == 0) {
        std::string key_type;
        for (const auto &p : item.params) {
          if (p.name == "key_type") {
            key_type = p.value_name.empty() ? std::to_string(p.value) : p.value_name;
            break;
          }
        }
        if (!key_type.empty()) {
          auto &acc = key_type_results[key_type];
          acc.request_bytes += r.request_bytes;
          acc.response_bytes += r.response_bytes;
          acc.num_passed_tasks += r.num_passed_tasks;
          acc.time_secs += r.time_secs;
        }
      }*/
    }

    // auto get_xps = [&](size_t n, double t) { return static_cast<double>(n) / t; };
    auto get_xps = [&](size_t n){ return static_cast<double>(n)/total_time; };

    /*for (const auto &kv : key_type_results) {
      const auto &k = kv.first;
      const auto &v = kv.second;
      fmt::print("[{} TOTAL]: OUT={:.3f}MBps IN={:.3f}MBps {:>8.3f}Tps\n",
                 k,
                 get_xps(v.request_bytes, v.time_secs) / 1048576,
                 get_xps(v.response_bytes, v.time_secs) / 1048576,
                 get_xps(v.num_passed_tasks, v.time_secs));
    }*/

    /*fmt::print("[OVERALL TOTAL]: OUT={:.3f}MBps IN={:.3f}MBps {:>8.3f}Tps\n",
              get_xps(total_req_bytes, total_time) / 1048576,
              get_xps(total_resp_bytes, total_time) / 1048576,
              get_xps(total_tasks, total_time));*/
    fmt::print("[TOTAL]: OUT={:.3f}MBps IN={:.3f}MBps {:>8.3f}Tps\n",
               get_xps(total_req_bytes)/1048576,
               get_xps(total_resp_bytes)/1048576,
               get_xps(total_tasks));
  }

private:
  std::vector<item_t> items_;
};

NDSEC_NAMESPACE_END
