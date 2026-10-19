/* Windows x64 host virtual-memory backend.
 *
 * Owns only the narrow platform calls (VirtualAlloc / VirtualFree /
 * VirtualProtect / VirtualQuery / FlushInstructionCache) and the owning
 * region handle that bounds-checks every mutating request before it reaches
 * the OS (only read-only `VirtualQuery` preflight runs first).
 * See host_vm.h for the contract, the Mac reference points and the scope
 * limits (anonymous private mapping only; no guest address strategy).
 *
 * The reservation is an anonymous, private range. Windows rounds a
 * reservation up to a whole number of pages (GetSystemInfo.dwPageSize) and
 * hands the base back on an allocation-granularity boundary
 * (GetSystemInfo.dwAllocationGranularity). Both values are reported by the
 * API rather than assumed, because the page size and granularity are host
 * properties.
 *
 * Every decommit/protect request is checked against the OS's actual page
 * state first (VirtualQuery), so "decommit a reserved page" and "protect a
 * reserved page" are reported as invalid state instead of being handed to a
 * platform call whose behaviour would otherwise be implicit.
 */

#include "host_vm.h"

#if !defined(_WIN32)
#  error "host_vm.c is the Windows x64 backend; the Mac path keeps Mach/mmap."
#endif

#include <windows.h>

#include <stdlib.h>

#define HOST_VM_REGION_LIVE 0x564D5231u   /* "VMR1" */
#define HOST_VM_REGION_DEAD 0x564D5232u   /* "VMR2" */

struct host_vm_region {
    void *base;
    size_t size;
    uint32_t state;
};

/* ---- platform value translation -------------------------------------- */

static host_vm_result map_platform_failure(void)
{
    DWORD error = GetLastError();

    if (error == ERROR_INVALID_ADDRESS) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    if (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_COMMITMENT_LIMIT) {
        return HOST_VM_ERR_ALLOCATION;
    }
    return HOST_VM_ERR_PLATFORM;
}

/* OS protection -> host_vm_prot bits. Guard/uncached attributes are not part
 * of the G1 model, so the underlying access bits are what is reported. */
static unsigned protection_from_os(DWORD protect)
{
    switch (protect & 0xFFu) {
    case PAGE_NOACCESS:
        return HOST_VM_PROT_NONE;
    case PAGE_READONLY:
        return HOST_VM_PROT_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return HOST_VM_PROT_READ | HOST_VM_PROT_WRITE;
    case PAGE_EXECUTE:
        return HOST_VM_PROT_EXEC;
    case PAGE_EXECUTE_READ:
        return HOST_VM_PROT_EXEC | HOST_VM_PROT_READ;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return HOST_VM_PROT_EXEC | HOST_VM_PROT_READ | HOST_VM_PROT_WRITE;
    default:
        return HOST_VM_PROT_NONE;
    }
}

static int protection_to_os(unsigned protection, DWORD *out_os)
{
    if ((protection & ~(unsigned)(HOST_VM_PROT_READ | HOST_VM_PROT_WRITE |
                                  HOST_VM_PROT_EXEC)) != 0u) {
        return 0;
    }
    /* The platform has no write-without-read protection. */
    if ((protection & HOST_VM_PROT_WRITE) != 0u) {
        protection |= HOST_VM_PROT_READ;
    }

    switch (protection) {
    case HOST_VM_PROT_NONE:
        *out_os = PAGE_NOACCESS;
        return 1;
    case HOST_VM_PROT_READ:
        *out_os = PAGE_READONLY;
        return 1;
    case HOST_VM_PROT_READ | HOST_VM_PROT_WRITE:
        *out_os = PAGE_READWRITE;
        return 1;
    case HOST_VM_PROT_EXEC:
        *out_os = PAGE_EXECUTE;
        return 1;
    case HOST_VM_PROT_EXEC | HOST_VM_PROT_READ:
        *out_os = PAGE_EXECUTE_READ;
        return 1;
    case HOST_VM_PROT_EXEC | HOST_VM_PROT_READ | HOST_VM_PROT_WRITE:
        *out_os = PAGE_EXECUTE_READWRITE;
        return 1;
    default:
        return 0;
    }
}

static unsigned state_from_os(DWORD state)
{
    switch (state) {
    case MEM_FREE:
        return HOST_VM_STATE_FREE;
    case MEM_RESERVE:
        return HOST_VM_STATE_RESERVE;
    case MEM_COMMIT:
        return HOST_VM_STATE_COMMIT;
    default:
        return HOST_VM_STATE_FREE;
    }
}

static unsigned type_from_os(DWORD type)
{
    switch (type) {
    case MEM_PRIVATE:
        return HOST_VM_TYPE_PRIVATE;
    case MEM_MAPPED:
        return HOST_VM_TYPE_MAPPED;
    case MEM_IMAGE:
        return HOST_VM_TYPE_IMAGE;
    default:
        return HOST_VM_TYPE_FREE;
    }
}

/* ---- reservation bounds helpers -------------------------------------- */

static int region_is_live(const host_vm_region *region)
{
    return region != NULL && region->state == HOST_VM_REGION_LIVE;
}

static int range_inside(const host_vm_region *region, size_t offset,
                        size_t size)
{
    if (size == 0) {
        return 0;
    }
    if (offset > region->size) {
        return 0;
    }
    if (size > region->size - offset) {
        return 0;
    }
    return 1;
}

static int range_aligned(size_t offset, size_t size)
{
    size_t page = (size_t)host_vm_page_size();

    return (offset % page) == 0 && (size % page) == 0;
}

static unsigned char *region_address(host_vm_region *region, size_t offset)
{
    return (unsigned char *)region->base + offset;
}

/* Result of walking the OS's own page map over a range. A query failure is
 * kept distinct from "the range is in the wrong state" so the caller can
 * report HOST_VM_ERR_PLATFORM instead of HOST_VM_ERR_INVALID_STATE. */
enum range_state {
    RANGE_QUERY_FAILED = -1, /* VirtualQuery failed or made no progress */
    RANGE_NOT_ALL = 0,       /* at least one page is not in the wanted state */
    RANGE_ALL = 1            /* every page is in the wanted state */
};

/* Walk the OS's own page map and classify every page in the range against
 * `want_state` (MEM_RESERVE or MEM_COMMIT). Returns RANGE_QUERY_FAILED on a
 * query failure or a map that fails to make progress, RANGE_NOT_ALL if any
 * page is in another state, else RANGE_ALL. */
static int range_all_state(host_vm_region *region, size_t offset, size_t size,
                           DWORD want_state)
{
    uintptr_t address = (uintptr_t)region_address(region, offset);
    uintptr_t end = address + size;

    while (address < end) {
        MEMORY_BASIC_INFORMATION info;
        uintptr_t next;

        if (VirtualQuery((LPCVOID)address, &info, sizeof(info)) == 0) {
            return RANGE_QUERY_FAILED;
        }
        if (info.State != want_state) {
            return RANGE_NOT_ALL;
        }
        next = (uintptr_t)info.BaseAddress + info.RegionSize;
        if (next <= address) {
            return RANGE_QUERY_FAILED; /* no forward progress */
        }
        address = next;
    }
    return RANGE_ALL;
}

/* ---- public API ------------------------------------------------------ */

uint64_t host_vm_page_size(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return (uint64_t)info.dwPageSize;
}

uint64_t host_vm_allocation_granularity(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return (uint64_t)info.dwAllocationGranularity;
}

host_vm_result host_vm_reserve(size_t size, host_vm_region **out_region)
{
    size_t page;
    size_t rounded;
    void *base;
    host_vm_region *region;

    if (out_region == NULL || size == 0) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }

    page = (size_t)host_vm_page_size();
    /* Round up to a page with an explicit overflow check. */
    if (size > (size_t)(SIZE_MAX - (page - 1))) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    rounded = (size + page - 1) & ~(page - 1);

    base = VirtualAlloc(NULL, rounded, MEM_RESERVE, PAGE_NOACCESS);
    if (base == NULL) {
        return map_platform_failure();
    }

    region = (host_vm_region *)malloc(sizeof(*region));
    if (region == NULL) {
        VirtualFree(base, 0, MEM_RELEASE);
        return HOST_VM_ERR_ALLOCATION;
    }
    region->base = base;
    region->size = rounded;
    region->state = HOST_VM_REGION_LIVE;

    *out_region = region;
    return HOST_VM_OK;
}

host_vm_result host_vm_release(host_vm_region *region)
{
    if (region == NULL) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!region_is_live(region)) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    if (!VirtualFree(region->base, 0, MEM_RELEASE)) {
        return map_platform_failure();
    }

    region->state = HOST_VM_REGION_DEAD;
    free(region);
    return HOST_VM_OK;
}

host_vm_result host_vm_base(const host_vm_region *region, void **out_base,
                            size_t *out_size)
{
    if (region == NULL || out_base == NULL || out_size == NULL) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!region_is_live(region)) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    *out_base = region->base;
    *out_size = region->size;
    return HOST_VM_OK;
}

host_vm_result host_vm_commit(host_vm_region *region, size_t offset,
                              size_t size)
{
    int state;

    if (region == NULL) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!region_is_live(region)) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    if (size == 0) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!range_inside(region, offset, size) || !range_aligned(offset, size)) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    /* Require the WHOLE range reserved and reject before any mutation. An
     * already-committed or mixed range must not reach VirtualAlloc: a
     * MEM_COMMIT over an RX/read-only page would reset it to read/write,
     * which is exactly the preservation this wrapper promises. */
    state = range_all_state(region, offset, size, MEM_RESERVE);
    if (state == RANGE_QUERY_FAILED) {
        return HOST_VM_ERR_PLATFORM;
    }
    if (state != RANGE_ALL) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    if (VirtualAlloc(region_address(region, offset), size, MEM_COMMIT,
                     PAGE_READWRITE) == NULL) {
        return map_platform_failure();
    }
    return HOST_VM_OK;
}

host_vm_result host_vm_decommit(host_vm_region *region, size_t offset,
                                size_t size)
{
    int state;

    if (region == NULL) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!region_is_live(region)) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    if (size == 0) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!range_inside(region, offset, size) || !range_aligned(offset, size)) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    /* Only committed pages may be decommitted; check the real page state so a
     * reserved range is reported rather than passed to the OS, and a query
     * failure is reported as a platform error. */
    state = range_all_state(region, offset, size, MEM_COMMIT);
    if (state == RANGE_QUERY_FAILED) {
        return HOST_VM_ERR_PLATFORM;
    }
    if (state != RANGE_ALL) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    if (!VirtualFree(region_address(region, offset), size, MEM_DECOMMIT)) {
        return map_platform_failure();
    }
    return HOST_VM_OK;
}

host_vm_result host_vm_protect(host_vm_region *region, size_t offset,
                               size_t size, unsigned protection,
                               unsigned *out_old_protection)
{
    DWORD os_protection = 0;
    DWORD old_protection = 0;
    int state;

    if (region == NULL) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!region_is_live(region)) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    if (size == 0) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!protection_to_os(protection, &os_protection)) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!range_inside(region, offset, size) || !range_aligned(offset, size)) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    /* Protection applies to committed pages only; a reserved range is
     * reported rather than handed to VirtualProtect, and a query failure is
     * reported as a platform error. */
    state = range_all_state(region, offset, size, MEM_COMMIT);
    if (state == RANGE_QUERY_FAILED) {
        return HOST_VM_ERR_PLATFORM;
    }
    if (state != RANGE_ALL) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    if (!VirtualProtect(region_address(region, offset), size, os_protection,
                        &old_protection)) {
        return map_platform_failure();
    }

    if (out_old_protection != NULL) {
        *out_old_protection = protection_from_os(old_protection);
    }
    return HOST_VM_OK;
}

host_vm_result host_vm_query(const host_vm_region *region, size_t offset,
                             host_vm_info *out_info)
{
    MEMORY_BASIC_INFORMATION info;
    host_vm_info result;

    if (region == NULL || out_info == NULL) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!region_is_live(region)) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    if (offset >= region->size) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    if (VirtualQuery((LPCVOID)((const unsigned char *)region->base + offset),
                     &info, sizeof(info)) == 0) {
        return HOST_VM_ERR_PLATFORM;
    }

    result.base = info.BaseAddress;
    result.size = (size_t)info.RegionSize;
    result.state = state_from_os(info.State);
    result.protection =
        (info.State == MEM_COMMIT) ? protection_from_os(info.Protect) : 0u;
    result.type = type_from_os(info.Type);

    *out_info = result;
    return HOST_VM_OK;
}

host_vm_result host_vm_flush_instruction_cache(host_vm_region *region,
                                               size_t offset, size_t size)
{
    if (region == NULL) {
        return HOST_VM_ERR_INVALID_ARGUMENT;
    }
    if (!region_is_live(region)) {
        return HOST_VM_ERR_INVALID_STATE;
    }
    if (!range_inside(region, offset, size)) {
        return HOST_VM_ERR_INVALID_STATE;
    }

    if (!FlushInstructionCache(GetCurrentProcess(),
                               region_address(region, offset), size)) {
        return HOST_VM_ERR_PLATFORM;
    }
    return HOST_VM_OK;
}
