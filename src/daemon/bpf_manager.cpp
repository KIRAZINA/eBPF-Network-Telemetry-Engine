// bpf_manager.cpp — RAII libbpf owner (real implementation + portable stub).

#include "bpf_manager.hpp"

#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>

#ifdef HAVE_LIBBPF
#include <cerrno>
#include <bpf/libbpf.h>

namespace telemetry {

void BpfObjectDeleter::operator()(struct bpf_object* obj) const noexcept
{
    if (obj != nullptr) {
        ::bpf_object__close(obj);
    }
}

void BpfLinkDeleter::operator()(struct bpf_link* link) const noexcept
{
    if (link != nullptr) {
        ::bpf_link__destroy(link);
    }
}

BpfManager::BpfManager(std::filesystem::path object_path, int ifindex)
    : object_path_(std::move(object_path))
    , ifindex_(ifindex)
{
}

BpfManager::~BpfManager()
{
    detach();
}

BpfManager::BpfManager(BpfManager&& other) noexcept
    : object_path_(std::move(other.object_path_))
    , ifindex_(other.ifindex_)
    , opened_(other.opened_)
    , loaded_(other.loaded_)
    , attached_(other.attached_)
    , link_count_(other.link_count_)
    , last_error_(std::move(other.last_error_))
    , object_(std::move(other.object_))
    , links_(std::move(other.links_))
{
    other.ifindex_ = 0;
    other.opened_ = false;
    other.loaded_ = false;
    other.attached_ = false;
    other.link_count_ = 0;
}

BpfManager& BpfManager::operator=(BpfManager&& other) noexcept
{
    if (this != &other) {
        detach();
        object_path_ = std::move(other.object_path_);
        ifindex_ = other.ifindex_;
        opened_ = other.opened_;
        loaded_ = other.loaded_;
        attached_ = other.attached_;
        link_count_ = other.link_count_;
        last_error_ = std::move(other.last_error_);
        object_ = std::move(other.object_);
        links_ = std::move(other.links_);
        other.ifindex_ = 0;
        other.opened_ = false;
        other.loaded_ = false;
        other.attached_ = false;
        other.link_count_ = 0;
    }
    return *this;
}

bool BpfManager::open()
{
    if (opened_) {
        return true;
    }
    last_error_.clear();
    struct bpf_object* raw =
        ::bpf_object__open_file(object_path_.c_str(), nullptr);
    if (raw == nullptr) {
        const int ec = errno;
        last_error_ = "bpf_object__open_file(" + object_path_.string() +
                      "): " + std::generic_category().message(ec);
        return false;
    }
    object_.reset(raw);
    opened_ = true;
    return true;
}

bool BpfManager::load()
{
    if (loaded_) {
        return true;
    }
    if (!opened_ && !open()) {
        return false;
    }
    last_error_.clear();
    if (::bpf_object__load(object_.get()) != 0) {
        const int ec = errno;
        last_error_ =
            "bpf_object__load: " + std::generic_category().message(ec);
        return false;
    }
    loaded_ = true;
    return true;
}

namespace {
// Attach one program by name with the generic (tracepoint) attacher.
// Returns nullptr on failure with errno set; appends context to err.
struct bpf_link* attach_generic(struct bpf_object* obj, const char* prog_name,
                                std::string& err)
{
    struct bpf_program* prog =
        ::bpf_object__find_program_by_name(obj, prog_name);
    if (prog == nullptr) {
        return nullptr; // program not in object: skip silently
    }
    // Autodetect (tracepoint/syscall) attach; libbpf selects bpf_link type.
    struct bpf_link* link = ::bpf_program__attach(prog);
    if (::libbpf_get_error(link) != 0) {
        const int ec = errno;
        err += std::string("attach(") + prog_name + "): " +
               std::generic_category().message(ec) + "; ";
        return nullptr;
    }
    return link;
}
} // namespace

bool BpfManager::attach()
{
    if (attached_) {
        return true;
    }
    if (!loaded_ && !load()) {
        return false;
    }
    last_error_.clear();

    // Tracepoints first (no ifindex needed).
    static const char* const kTraceProgs[] = {"trace_connect", "trace_execve"};
    for (const char* name : kTraceProgs) {
        struct bpf_link* link = attach_generic(object_.get(), name, last_error_);
        if (link != nullptr) {
            links_.emplace_back(link);
        }
    }

    // XDP needs an explicit interface index. It is best-effort: many NICs
    // (notably virtual ones such as WSL2's eth0) reject XDP attach while
    // tracepoints work fine. A failed XDP attach must NOT tear down the
    // tracepoint links collected above — partial telemetry beats none.
    if (ifindex_ != 0) {
        if (!attach_xdp(ifindex_)) {
            last_error_ += "continuing with tracepoints only; ";
        }
    }

    if (links_.empty()) {
        last_error_ += "attach: no programs attached (missing progs?)";
        return false;
    }
    link_count_ = links_.size();
    attached_ = true;
    return true;
}

bool BpfManager::attach_xdp(int ifindex)
{
    if (!loaded_ && !load()) {
        return false;
    }
    struct bpf_program* prog =
        ::bpf_object__find_program_by_name(object_.get(), "xdp_telemetry");
    if (prog == nullptr) {
        last_error_ += "attach_xdp: program 'xdp_telemetry' not found; ";
        return false;
    }
    struct bpf_link* link = ::bpf_program__attach_xdp(prog, ifindex);
    if (::libbpf_get_error(link) != 0) {
        const int ec = errno;
        last_error_ += "attach_xdp(ifindex=" + std::to_string(ifindex) +
                       "): " + std::generic_category().message(ec) + "; ";
        return false;
    }
    ifindex_ = ifindex;
    links_.emplace_back(link);
    link_count_ = links_.size();
    attached_ = true;
    return true;
}

int BpfManager::map_fd(const char* name) const noexcept
{
    if (!loaded_ || object_ == nullptr || name == nullptr) {
        return -1;
    }
    return ::bpf_object__find_map_fd_by_name(object_.get(), name);
}

void BpfManager::detach() noexcept
{
    // Destroy links BEFORE closing the object (link depends on object).
    links_.clear();
    object_.reset();
    link_count_ = 0;
    attached_ = false;
    loaded_ = false;
    opened_ = false;
}

} // namespace telemetry

#else /* !HAVE_LIBBPF — portable stub: same API, no kernel touch */

#include <system_error>

namespace telemetry {

BpfManager::BpfManager(std::filesystem::path object_path, int ifindex)
    : object_path_(std::move(object_path))
    , ifindex_(ifindex)
{
}

BpfManager::~BpfManager()
{
    detach();
}

BpfManager::BpfManager(BpfManager&& other) noexcept
    : object_path_(std::move(other.object_path_))
    , ifindex_(other.ifindex_)
    , opened_(other.opened_)
    , loaded_(other.loaded_)
    , attached_(other.attached_)
    , link_count_(other.link_count_)
    , last_error_(std::move(other.last_error_))
{
    other.ifindex_ = 0;
    other.opened_ = false;
    other.loaded_ = false;
    other.attached_ = false;
    other.link_count_ = 0;
}

BpfManager& BpfManager::operator=(BpfManager&& other) noexcept
{
    if (this != &other) {
        detach();
        object_path_ = std::move(other.object_path_);
        ifindex_ = other.ifindex_;
        opened_ = other.opened_;
        loaded_ = other.loaded_;
        attached_ = other.attached_;
        link_count_ = other.link_count_;
        last_error_ = std::move(other.last_error_);
        other.ifindex_ = 0;
        other.opened_ = false;
        other.loaded_ = false;
        other.attached_ = false;
        other.link_count_ = 0;
    }
    return *this;
}

bool BpfManager::open()
{
    // Off-Linux the .bpf.o may not exist (kernel build is Linux-only);
    // record intent and let the pipeline self-test proceed.
    std::error_code ec;
    const bool exists = std::filesystem::exists(object_path_, ec) && !ec;
    opened_ = true;
    last_error_ =
        exists ? std::string{} : std::string{"stub: object not present off-Linux"};
    return true;
}

bool BpfManager::load()
{
    if (!opened_ && !open()) {
        return false;
    }
    loaded_ = true;
    return true;
}

bool BpfManager::attach()
{
    if (!loaded_ && !load()) {
        return false;
    }
    attached_ = true;
    link_count_ = 0;
    return true;
}

bool BpfManager::attach_xdp(int ifindex)
{
    ifindex_ = ifindex;
    return attach();
}

int BpfManager::map_fd(const char* /*name*/) const noexcept
{
    return -1; // no kernel maps off-Linux
}

void BpfManager::detach() noexcept
{
    link_count_ = 0;
    attached_ = false;
    loaded_ = false;
    opened_ = false;
}

} // namespace telemetry

#endif /* HAVE_LIBBPF */
