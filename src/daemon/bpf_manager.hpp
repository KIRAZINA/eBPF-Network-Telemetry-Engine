#pragma once

// bpf_manager.hpp — strict RAII owner for libbpf resources.
//
// Owns: struct bpf_object (bpf_object__close) + every struct bpf_link
// (bpf_link__destroy) created by auto-attach. Move-only, exception-safe:
// the destructor and detach() are noexcept and idempotent, so early returns
// and exceptions never leak handles. Without HAVE_LIBBPF the same API
// compiles to a portable stub (non-Linux configure) that records intent
// instead of touching the kernel.

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#ifdef HAVE_LIBBPF
struct bpf_object;
struct bpf_link;
#endif

namespace telemetry {

#ifdef HAVE_LIBBPF
struct BpfObjectDeleter {
    void operator()(struct bpf_object* obj) const noexcept;
};
struct BpfLinkDeleter {
    void operator()(struct bpf_link* link) const noexcept;
};
using BpfObjectPtr = std::unique_ptr<struct bpf_object, BpfObjectDeleter>;
using BpfLinkPtr = std::unique_ptr<struct bpf_link, BpfLinkDeleter>;
#endif

class BpfManager {
public:
    // object_path: compiled .bpf.o; ifindex: target netdev for XDP
    // (0 = skip XDP attach, attach tracepoints only).
    explicit BpfManager(std::filesystem::path object_path, int ifindex = 0);
    ~BpfManager();

    BpfManager(const BpfManager&) = delete;
    BpfManager& operator=(const BpfManager&) = delete;
    BpfManager(BpfManager&&) noexcept;
    BpfManager& operator=(BpfManager&&) noexcept;

    // Open the .bpf.o (bpf_object__open_file). Idempotent.
    [[nodiscard]] bool open();
    // Load programs/maps into the kernel (bpf_object__load). Idempotent.
    [[nodiscard]] bool load();
    // Auto-attach every known program: xdp_telemetry via XDP (needs
    // ifindex_ != 0), trace_connect / trace_execve via generic attach.
    // Idempotent; partial failures detach what was attached.
    [[nodiscard]] bool attach();
    // Attach XDP explicitly (useful when ifindex arrives late).
    [[nodiscard]] bool attach_xdp(int ifindex);
    // Tear down links first, then the object. Noexcept + idempotent.
    void detach() noexcept;

    [[nodiscard]] bool is_open() const noexcept { return opened_; }
    [[nodiscard]] bool is_loaded() const noexcept { return loaded_; }
    [[nodiscard]] bool is_attached() const noexcept { return attached_; }

    // File descriptor of a BPF map by name ("events"); -1 when unavailable.
    [[nodiscard]] int map_fd(const char* name) const noexcept;
    [[nodiscard]] int event_map_fd() const noexcept { return map_fd("events"); }

    [[nodiscard]] std::size_t link_count() const noexcept { return link_count_; }
    [[nodiscard]] const std::string& last_error() const noexcept
    {
        return last_error_;
    }
    [[nodiscard]] const std::filesystem::path& object_path() const noexcept
    {
        return object_path_;
    }

private:
    std::filesystem::path object_path_;
    int ifindex_ = 0;
    bool opened_ = false;
    bool loaded_ = false;
    bool attached_ = false;
    std::size_t link_count_ = 0;
    std::string last_error_;
#ifdef HAVE_LIBBPF
    BpfObjectPtr object_;
    std::vector<BpfLinkPtr> links_;
#endif
};

} // namespace telemetry
