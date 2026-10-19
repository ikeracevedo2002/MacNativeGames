/* Host virtual-memory probe (G1 memory row).
 *
 * Drives the real backend from src/host_vm.c against an anonymous private
 * reservation and checks the OS's own page map independently (raw
 * VirtualQuery, not the wrapper's bookkeeping), plus guarded accesses for the
 * protection transitions:
 *
 *   - reserve: OS shows a private reserved range, no access;
 *   - commit: OS shows committed read/write, and a guarded write succeeds;
 *   - decommit/recommit: OS shows reserved again and a re-commit returns
 *     zero-filled pages;
 *   - protect: a read-only page faults a written access but not a read; a
 *     no-access page faults a read; an execute/read page faults a write and
 *     still allows a read; protection is restored afterwards;
 *   - release: the range is free again.
 *
 * Bounds/overflow checks are positive controls for argument validation:
 * misaligned or out-of-range offsets, zero sizes, SIZE_MAX-style overflow and
 * unknown protection bits must be rejected without changing anything.
 *
 * The guarded-access pair is the negative control for the protection checks:
 * the same helper must report "no fault" on a writable page and "fault" on a
 * read-only page. A helper that always returned the same answer (or a
 * protection check that never actually tried an access) would fail one half
 * of that pair. The helper is a local SEH fixture in this probe only; it does
 * not install, register or define any process fault/exception handling, so
 * the runtime fault row remains untouched.
 *
 * Exit status is the result. No PASS_REGULAR_EXPRESSION, no WILL_FAIL, no
 * assert(). Infrastructure failures (reserve/commit failures that the probe
 * needs to proceed) fail the run explicitly; they are never counted as a
 * protection verdict.
 */

#include "host_vm.h"

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct checks {
    const char *label;
    int failures;
} checks;

static void note(checks *c, const char *what)
{
    c->failures++;
    fprintf(stderr, "[%s] FAIL: %s\n", c->label, what);
}

static void expect_ok(checks *c, host_vm_result got, const char *what)
{
    if (got != HOST_VM_OK) {
        note(c, what);
    }
}

static void expect_result(checks *c, host_vm_result got, host_vm_result want,
                          const char *what)
{
    if (got != want) {
        c->failures++;
        fprintf(stderr, "[%s] FAIL: %s returned %d, want %d\n", c->label,
                what, (int)got, (int)want);
    }
}

/* 1 == the access faulted, 0 == it completed. Only an access violation is
 * treated as the guarded-access verdict; any other exception continues the
 * search so this probe never swallows an unrelated fault. */
static int faulted_write(volatile unsigned char *address)
{
    __try {
        *address = 0x5Au;
        return 0;
    } __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION)
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        return 1;
    }
}

static int faulted_read(volatile const unsigned char *address)
{
    __try {
        volatile unsigned char value = *address;
        (void)value;
        return 0;
    } __except ((GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION)
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        return 1;
    }
}

/* Raw independent query of the OS protection word; returns 0 on failure. */
static int raw_protect(const void *address, DWORD *out_protect)
{
    MEMORY_BASIC_INFORMATION info;

    if (VirtualQuery((LPCVOID)address, &info, sizeof(info)) == 0) {
        return 0;
    }
    *out_protect = info.Protect;
    return 1;
}

static size_t page_size(void)
{
    return (size_t)host_vm_page_size();
}

static void run_granularity_checks(checks *c)
{
    uint64_t page = host_vm_page_size();
    uint64_t granularity = host_vm_allocation_granularity();

    if (page == 0 || (page & (page - 1)) != 0 || page < 4096) {
        note(c, "host page size is not a plausible power of two");
    }
    if (granularity < page || (granularity % page) != 0) {
        note(c, "allocation granularity is not a multiple of the page size");
    }
}

static void run_argument_checks(checks *c)
{
    host_vm_region *region = NULL;
    void *base = NULL;
    size_t size = 0;
    host_vm_info info;

    expect_result(c, host_vm_reserve(0, &region),
                  HOST_VM_ERR_INVALID_ARGUMENT, "reserve(zero)");
    expect_result(c, host_vm_reserve(page_size(), NULL),
                  HOST_VM_ERR_INVALID_ARGUMENT, "reserve(NULL out)");
    expect_result(c, host_vm_reserve((size_t)SIZE_MAX, &region),
                  HOST_VM_ERR_INVALID_ARGUMENT, "reserve overflow");
    expect_result(c, host_vm_reserve((size_t)SIZE_MAX - 3u, &region),
                  HOST_VM_ERR_INVALID_ARGUMENT, "reserve overflow near max");
    expect_result(c, host_vm_release(NULL),
                  HOST_VM_ERR_INVALID_ARGUMENT, "release(NULL)");
    expect_result(c, host_vm_commit(NULL, 0, page_size()),
                  HOST_VM_ERR_INVALID_ARGUMENT, "commit(NULL)");
    expect_result(c, host_vm_decommit(NULL, 0, page_size()),
                  HOST_VM_ERR_INVALID_ARGUMENT, "decommit(NULL)");
    expect_result(c, host_vm_protect(NULL, 0, page_size(),
                                     HOST_VM_PROT_READ, NULL),
                  HOST_VM_ERR_INVALID_ARGUMENT, "protect(NULL)");
    expect_result(c, host_vm_query(NULL, 0, &info),
                  HOST_VM_ERR_INVALID_ARGUMENT, "query(NULL)");
    expect_result(c, host_vm_flush_instruction_cache(NULL, 0, page_size()),
                  HOST_VM_ERR_INVALID_ARGUMENT, "flush(NULL)");
    expect_result(c, host_vm_base(NULL, &base, &size),
                  HOST_VM_ERR_INVALID_ARGUMENT, "base(NULL)");
}

static void run_reserve_commit_checks(checks *c)
{
    host_vm_region *region = NULL;
    void *base = NULL;
    size_t size = 0;
    size_t page = page_size();
    size_t granularity = (size_t)host_vm_allocation_granularity();
    host_vm_info info;
    DWORD raw = 0;
    volatile unsigned char *bytes;
    int i;

    if (host_vm_reserve(1, &region) != HOST_VM_OK) {
        note(c, "reserve(1) failed (probe cannot continue this phase)");
        return;
    }
    if (host_vm_base(region, &base, &size) != HOST_VM_OK) {
        note(c, "base() failed");
        (void)host_vm_release(region);
        return;
    }
    if (base == NULL || size < page || size % page != 0) {
        note(c, "reservation base/size is not page-rounded");
    }
    if (granularity != 0 && ((uintptr_t)base % granularity) != 0) {
        note(c, "reservation base is not allocation-granularity aligned");
    }

    /* The OS itself must report a private, reserved, no-access range. */
    if (!raw_protect(base, &raw)) {
        note(c, "raw VirtualQuery on the reservation failed");
    } else {
        MEMORY_BASIC_INFORMATION raw_info;
        (void)VirtualQuery((LPCVOID)base, &raw_info, sizeof(raw_info));
        if (raw_info.State != MEM_RESERVE || raw_info.Type != MEM_PRIVATE) {
            note(c, "reservation is not private/reserved in the OS map");
        }
    }
    if (host_vm_query(region, 0, &info) != HOST_VM_OK || info.state !=
            HOST_VM_STATE_RESERVE || info.type != HOST_VM_TYPE_PRIVATE ||
        info.protection != HOST_VM_PROT_NONE) {
        note(c, "query() did not report the reserved private no-access range");
    }

    /* Uncommitted access must fail at the OS level. */
    if (!faulted_write((volatile unsigned char *)base)) {
        note(c, "a write to a reserved (uncommitted) page did not fault");
    }

    /* Commit the first page. */
    expect_ok(c, host_vm_commit(region, 0, page), "commit first page");
    if (host_vm_query(region, 0, &info) != HOST_VM_OK ||
        info.state != HOST_VM_STATE_COMMIT ||
        info.protection != (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE)) {
        note(c, "query() did not report a committed read/write page");
    }
    if (!raw_protect(base, &raw) || raw != PAGE_READWRITE) {
        note(c, "raw OS protection is not PAGE_READWRITE after commit");
    }
    bytes = (volatile unsigned char *)base;
    if (faulted_write(bytes)) {
        note(c, "a write to a committed read/write page faulted");
    }
    for (i = 0; i < 16; i++) {
        bytes[i] = (unsigned char)(0x11 + i);
    }
    for (i = 0; i < 16; i++) {
        if (bytes[i] != (unsigned char)(0x11 + i)) {
            note(c, "committed page did not retain written bytes");
            break;
        }
    }

    /* Argument validation on the owning handle. */
    expect_result(c, host_vm_commit(region, 1, page),
                  HOST_VM_ERR_INVALID_STATE, "commit misaligned offset");
    expect_result(c, host_vm_commit(region, 0, 1),
                  HOST_VM_ERR_INVALID_STATE, "commit misaligned size");
    expect_result(c, host_vm_commit(region, 0, 0),
                  HOST_VM_ERR_INVALID_ARGUMENT, "commit zero size");
    expect_result(c, host_vm_commit(region, size - page, 2 * page),
                  HOST_VM_ERR_INVALID_STATE, "commit beyond reservation");
    expect_result(c, host_vm_commit(region, (size_t)SIZE_MAX - 10u, page),
                  HOST_VM_ERR_INVALID_STATE, "commit overflow offset");
    expect_result(c, host_vm_query(region, size, &info),
                  HOST_VM_ERR_INVALID_STATE, "query beyond reservation");

    (void)host_vm_release(region);
}

static void run_decommit_zero_checks(checks *c)
{
    host_vm_region *region = NULL;
    void *base = NULL;
    size_t size = 0;
    size_t page = page_size();
    host_vm_info info;
    volatile unsigned char *bytes;
    int i;

    if (host_vm_reserve(page, &region) != HOST_VM_OK ||
        host_vm_base(region, &base, &size) != HOST_VM_OK) {
        note(c, "decommit reserve failed");
        if (region != NULL) {
            (void)host_vm_release(region);
        }
        return;
    }
    bytes = (volatile unsigned char *)base;

    /* Decommitting a reserved page is invalid state, not an OS call. */
    expect_result(c, host_vm_decommit(region, 0, page),
                  HOST_VM_ERR_INVALID_STATE, "decommit reserved page");
    expect_result(c, host_vm_decommit(region, 0, 0),
                  HOST_VM_ERR_INVALID_ARGUMENT, "decommit zero size");
    /* Protecting a reserved page is invalid state too. */
    expect_result(c, host_vm_protect(region, 0, page, HOST_VM_PROT_READ, NULL),
                  HOST_VM_ERR_INVALID_STATE, "protect reserved page");
    expect_result(c, host_vm_protect(region, 0, 0, HOST_VM_PROT_READ, NULL),
                  HOST_VM_ERR_INVALID_ARGUMENT, "protect zero size");

    expect_ok(c, host_vm_commit(region, 0, page), "commit for decommit");
    for (i = 0; i < (int)page; i++) {
        bytes[i] = 0xA5u;
    }
    expect_ok(c, host_vm_decommit(region, 0, page), "decommit committed page");
    if (host_vm_query(region, 0, &info) != HOST_VM_OK ||
        info.state != HOST_VM_STATE_RESERVE) {
        note(c, "query() after decommit is not reserved");
    }
    if (!faulted_read(bytes)) {
        note(c, "a read of a decommitted page did not fault");
    }

    expect_ok(c, host_vm_commit(region, 0, page), "recommit page");
    for (i = 0; i < (int)page; i++) {
        if (bytes[i] != 0) {
            note(c, "a recommitted page was not zero-filled");
            break;
        }
    }
    (void)host_vm_release(region);
}

static void run_protect_checks(checks *c)
{
    host_vm_region *region = NULL;
    void *base = NULL;
    size_t size = 0;
    size_t page = page_size();
    volatile unsigned char *bytes;
    unsigned old = 0;
    DWORD raw = 0;

    if (host_vm_reserve(page, &region) != HOST_VM_OK ||
        host_vm_base(region, &base, &size) != HOST_VM_OK ||
        host_vm_commit(region, 0, page) != HOST_VM_OK) {
        note(c, "protect reserve/commit failed");
        if (region != NULL) {
            (void)host_vm_release(region);
        }
        return;
    }
    bytes = (volatile unsigned char *)base;

    /* Negative control pair: the same guarded write must be allowed here and
     * denied below. This is what makes the protection checks meaningful. */
    if (faulted_write(bytes)) {
        note(c, "guarded write faulted on a committed read/write page");
    }

    /* Read-only: writes fault, reads succeed. */
    old = 0;
    expect_ok(c, host_vm_protect(region, 0, page, HOST_VM_PROT_READ, &old),
              "protect read-only");
    if (old != (HOST_VM_PROT_READ | HOST_VM_PROT_WRITE)) {
        note(c, "protect() did not report the previous read/write protection");
    }
    if (!faulted_write(bytes)) {
        note(c, "a write to a read-only page did not fault");
    }
    if (faulted_read(bytes)) {
        note(c, "a read of a read-only page faulted");
    }
    if (!raw_protect(base, &raw) || raw != PAGE_READONLY) {
        note(c, "raw OS protection is not PAGE_READONLY");
    }

    /* No access: reads fault too. */
    expect_ok(c, host_vm_protect(region, 0, page, HOST_VM_PROT_NONE, NULL),
              "protect no-access");
    if (!faulted_read(bytes)) {
        note(c, "a read of a no-access page did not fault");
    }

    /* Execute/read: reads succeed, writes fault, flush succeeds. */
    expect_ok(c, host_vm_protect(region, 0, page,
                                 HOST_VM_PROT_EXEC | HOST_VM_PROT_READ, NULL),
              "protect execute/read");
    if (faulted_read(bytes)) {
        note(c, "a read of an execute/read page faulted");
    }
    if (!faulted_write(bytes)) {
        note(c, "a write to an execute/read page did not fault");
    }
    expect_ok(c, host_vm_flush_instruction_cache(region, 0, page),
              "flush executable page");

    /* Write-only request must be upgraded to read/write. */
    expect_ok(c, host_vm_protect(region, 0, page, HOST_VM_PROT_WRITE, NULL),
              "protect write-only");
    if (faulted_write(bytes)) {
        note(c, "write-only protection did not allow a write");
    }

    /* Unknown bits are rejected and change nothing. */
    expect_result(c,
                  host_vm_protect(region, 0, page, 0x8u, NULL),
                  HOST_VM_ERR_INVALID_ARGUMENT, "protect unknown bits");
    if (faulted_write(bytes)) {
        note(c, "a failed protect changed the current protection");
    }

    (void)host_vm_release(region);
}

static void run_release_checks(checks *c)
{
    host_vm_region *region = NULL;
    void *base = NULL;
    size_t size = 0;
    MEMORY_BASIC_INFORMATION info;

    if (host_vm_reserve(page_size(), &region) != HOST_VM_OK ||
        host_vm_base(region, &base, &size) != HOST_VM_OK) {
        note(c, "release reserve failed");
        if (region != NULL) {
            (void)host_vm_release(region);
        }
        return;
    }

    expect_ok(c, host_vm_release(region), "release reservation");
    if (VirtualQuery((LPCVOID)base, &info, sizeof(info)) == 0 ||
        info.State != MEM_FREE) {
        note(c, "the released range is not free in the OS map");
    }
}

static void run_recommit_regression_checks(checks *c)
{
    host_vm_region *region = NULL;
    void *base = NULL;
    size_t size = 0;
    size_t page = page_size();
    volatile unsigned char *bytes;
    host_vm_info info;
    DWORD raw = 0;
    unsigned old = 0;

    if (host_vm_reserve(2 * page, &region) != HOST_VM_OK ||
        host_vm_base(region, &base, &size) != HOST_VM_OK) {
        note(c, "recommit regression reserve failed");
        if (region != NULL) {
            (void)host_vm_release(region);
        }
        return;
    }
    bytes = (volatile unsigned char *)base;

    /* Page 0 committed read/write with known contents. */
    expect_ok(c, host_vm_commit(region, 0, page), "recommit: commit page 0");
    bytes[0] = 0xC3u;
    bytes[page - 1] = 0x3Cu;

    /* Read-only page 0: a re-commit must be rejected and must NOT reset it to
     * read/write or disturb its contents. Independent VirtualQuery plus a
     * content check are the evidence, not the wrapper's own bookkeeping. */
    expect_ok(c, host_vm_protect(region, 0, page, HOST_VM_PROT_READ, &old),
              "recommit: protect page 0 read-only");
    expect_result(c, host_vm_commit(region, 0, page),
                  HOST_VM_ERR_INVALID_STATE, "recommit read-only page");
    if (!raw_protect(base, &raw) || raw != PAGE_READONLY) {
        note(c, "a rejected re-commit changed a read-only protection");
    }
    if (bytes[0] != 0xC3u || bytes[page - 1] != 0x3Cu) {
        note(c, "a rejected re-commit changed a read-only page's contents");
    }

    /* Execute/read page 0: the protection must survive a rejected re-commit. */
    expect_ok(c, host_vm_protect(region, 0, page,
                                 HOST_VM_PROT_EXEC | HOST_VM_PROT_READ, NULL),
              "recommit: protect page 0 execute/read");
    expect_result(c, host_vm_commit(region, 0, page),
                  HOST_VM_ERR_INVALID_STATE, "recommit execute/read page");
    if (!raw_protect(base, &raw) || raw != PAGE_EXECUTE_READ) {
        note(c, "a rejected re-commit changed an execute/read protection");
    }

    /* All-committed range (page 0 RX, page 1 RW): rejected with both pages
     * unchanged, so no partial re-commit can have happened. */
    expect_ok(c, host_vm_commit(region, page, page), "recommit: commit page 1");
    expect_result(c, host_vm_commit(region, 0, 2 * page),
                  HOST_VM_ERR_INVALID_STATE, "recommit all-committed range");
    if (!raw_protect(base, &raw) || raw != PAGE_EXECUTE_READ) {
        note(c, "rejected all-committed re-commit changed page 0");
    }
    if (!raw_protect((const unsigned char *)base + page, &raw) ||
        raw != PAGE_READWRITE) {
        note(c, "rejected all-committed re-commit changed page 1");
    }

    /* Mixed reserved/committed range: decommit page 0, then a commit over
     * both pages must be rejected and leave page 0 reserved and page 1
     * committed. */
    expect_ok(c, host_vm_decommit(region, 0, page),
              "recommit: decommit page 0");
    if (host_vm_query(region, 0, &info) != HOST_VM_OK ||
        info.state != HOST_VM_STATE_RESERVE) {
        note(c, "recommit: page 0 is not reserved after decommit");
    }
    expect_result(c, host_vm_commit(region, 0, 2 * page),
                  HOST_VM_ERR_INVALID_STATE, "recommit mixed range");
    if (host_vm_query(region, 0, &info) != HOST_VM_OK ||
        info.state != HOST_VM_STATE_RESERVE) {
        note(c, "a rejected mixed re-commit committed a reserved page");
    }
    if (!raw_protect((const unsigned char *)base + page, &raw) ||
        raw != PAGE_READWRITE) {
        note(c, "a rejected mixed re-commit changed the committed page");
    }

    (void)host_vm_release(region);
}

int main(void)
{
    checks c;

    c.label = "real";
    c.failures = 0;

    run_granularity_checks(&c);
    run_argument_checks(&c);
    run_reserve_commit_checks(&c);
    run_decommit_zero_checks(&c);
    run_protect_checks(&c);
    run_recommit_regression_checks(&c);
    run_release_checks(&c);

    if (c.failures != 0) {
        fprintf(stderr, "FAIL: host VM probe failed %d check(s)\n", c.failures);
        return 1;
    }

    printf("PASS: host VM reserve/commit/decommit/protect/release/query/flush "
           "battery with independent OS query and guarded-access control\n");
    return 0;
}
