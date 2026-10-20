/*
 * G3 increment 1: guest address-space contract probe.
 *
 * Drives src/aot/aot_as.c (and the Program-mode path of src/aot/aot_mem.c)
 * against tiny, explicitly described regions. No game data, no ARM bytes, no
 * translation. NOT translation coverage.
 *
 * Exit protocol (the mutant driver depends on it):
 *   0 = every contract check passed
 *   2 = at least one semantic check failed (prints "FAIL: <check>")
 *   1 = infrastructure failure (prints "FATAL: <reason>")
 */
#include "aot_as.h"
#include "aot_mem.h"
#include "host_vm.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;

static void check(int cond, const char *msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void fatal(const char *msg) {
    printf("FATAL: %s\n", msg);
    exit(1);
}

#define PG 0x1000ull

/* Deliberately added out of address order so the sorted insert is exercised. */
#define BASE_MISC 0x100020000ull   /* 4 pages, RW, data */
#define BASE_DATA 0x100000000ull   /* 2 pages, RW then page1 -> R  */
#define BASE_ADJ  0x100002000ull   /* 2 pages, RW (adjacent to DATA) */
#define BASE_RO   0x100004000ull   /* 2 pages, R (next to ADJ) */
#define BASE_CODE 0x100010000ull   /* 2 pages, R-X, state text */
#define BASE_NONE 0x100018000ull   /* 1 page, --- */
#define UNMAPPED  0x100030000ull

static uint8_t g_fill[0x8000];

static void fill_bytes(uint8_t *dst, uint8_t v, size_t n) {
    memset(dst, v, n);
}

int main(void) {
    AotMemDomain *dom;
    AotAddressSpace *as;
    AotMem mem;
    void *host = NULL;
    uint64_t v = 0;
    uint8_t buf[64], back[64];
    uint32_t token;

    dom = aot_mem_domain_create();
    if (dom == NULL) fatal("domain create");
    as = aot_as_create(dom);
    if (as == NULL) fatal("address space create");
    if (aot_as_domain(as) != dom) fatal("address space domain");

    /* ---- region add rules ------------------------------------------------ */
    check(aot_as_add_region(as, 0x1000ull, PG, AOT_AS_PERM_RW, 4u, NULL) ==
              AOT_MEM_ERR_RANGE,
          "region below 4 GiB is rejected");
    check(aot_as_add_region(as, 0xfffff000ull, 0x2000ull, AOT_AS_PERM_RW, 4u,
                            NULL) == AOT_MEM_ERR_RANGE,
          "region straddling 4 GiB is rejected");
    check(aot_as_add_region(as, AOT_AS_MAX_ADDR, PG, AOT_AS_PERM_RW, 4u, NULL) ==
              AOT_MEM_ERR_RANGE,
          "region at 2^39 is rejected");
    check(aot_as_add_region(as, AOT_AS_MAX_ADDR - PG, 0x2000ull, AOT_AS_PERM_RW,
                            4u, NULL) == AOT_MEM_ERR_RANGE,
          "region ending past 2^39 is rejected");
    /* Upper bound is EXCLUSIVE but not off by one: a region whose end is
     * exactly 2^39 is inside the admissible window. */
    if (aot_as_add_region(as, AOT_AS_MAX_ADDR - PG, PG, AOT_AS_PERM_R,
                          AOT_AS_STATE_DATA, &host) != AOT_MEM_OK)
        fatal("add region ending exactly at 2^39");
    check(aot_as_add_region(as, BASE_MISC + 0x800ull, PG, AOT_AS_PERM_RW, 4u,
                            NULL) == AOT_MEM_ERR_RANGE,
          "misaligned guest base is rejected");
    check(aot_as_add_region(as, BASE_MISC, 0x800ull, AOT_AS_PERM_RW, 4u, NULL) ==
              AOT_MEM_ERR_RANGE,
          "misaligned region size is rejected");
    check(aot_as_add_region(as, BASE_MISC, 0ull, AOT_AS_PERM_RW, 4u, NULL) ==
              AOT_MEM_ERR_RANGE,
          "zero-size region is rejected");
    check(aot_as_add_region(as, BASE_MISC, PG, AOT_AS_PERM_W, 4u, NULL) ==
              AOT_MEM_ERR_WIDTH,
          "write-without-read region permission is rejected");
    check(aot_as_add_region(as, BASE_MISC, PG, AOT_AS_PERM_RW | AOT_AS_PERM_X,
                            4u, NULL) == AOT_MEM_ERR_WIDTH,
          "write+execute region permission is rejected");

    if (aot_as_add_region(as, BASE_MISC, 4ull * PG, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, &host) != AOT_MEM_OK)
        fatal("add MISC region");
    check(host != NULL, "add region returns a host backing pointer");
    if (aot_as_add_region(as, BASE_DATA, 2ull * PG, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, &host) != AOT_MEM_OK)
        fatal("add DATA region");
    /* Adjacent to DATA, so a region-straddling access is a pure region
     * boundary failure (both pages writable), not a permission failure. */
    if (aot_as_add_region(as, BASE_ADJ, 2ull * PG, AOT_AS_PERM_RW,
                          AOT_AS_STATE_DATA, &host) != AOT_MEM_OK)
        fatal("add ADJ region");
    if (aot_as_add_region(as, BASE_RO, 2ull * PG, AOT_AS_PERM_R,
                          AOT_AS_STATE_DATA, &host) != AOT_MEM_OK)
        fatal("add RO region");
    /* RO was mapped read-only; populate it through the init-only host pointer
     * (aot_as_write would (correctly) be refused). */
    fill_bytes((uint8_t *)host, 0xcc, 0x2000);
    if (aot_as_add_region(as, BASE_CODE, 2ull * PG, AOT_AS_PERM_RX,
                          AOT_AS_STATE_TEXT, &host) != AOT_MEM_OK)
        fatal("add CODE region");
    fill_bytes((uint8_t *)host, 0x5a, 0x2000);
    if (aot_as_add_region(as, BASE_NONE, PG, AOT_AS_PERM_NONE,
                          AOT_AS_STATE_DATA, &host) != AOT_MEM_OK)
        fatal("add NONE region");
    check(aot_as_add_region(as, BASE_DATA + 0x3000ull, 0x2000ull, AOT_AS_PERM_RW,
                            4u, NULL) == AOT_MEM_ERR_RANGE,
          "overlapping region is rejected");

    /* ---- init-time population + seal ------------------------------------ */
    fill_bytes(g_fill, 0xaa, 0x1000);
    check(aot_as_write(as, BASE_DATA, g_fill, PG) == AOT_MEM_OK,
          "init write of DATA page0");
    fill_bytes(g_fill, 0xbb, 0x1000);
    check(aot_as_write(as, BASE_DATA + PG, g_fill, PG) == AOT_MEM_OK,
          "init write of DATA page1");
    /* Sentinels for the page-straddling store test. */
    check(aot_as_write(as, BASE_DATA + 0xfffull, "\x11", 1) == AOT_MEM_OK,
          "sentinel at DATA page0 end");
    check(aot_as_write(as, BASE_DATA + 0x1000ull, "\x22", 1) == AOT_MEM_OK,
          "sentinel at DATA page1 start");
    /* Sentinels for the cross-region (two adjacent RW regions) test. */
    check(aot_as_write(as, BASE_DATA + 0x1fffull, "\x33", 1) == AOT_MEM_OK,
          "sentinel at DATA page1 end");
    check(aot_as_write(as, BASE_ADJ, "\x44", 1) == AOT_MEM_OK,
          "sentinel at ADJ page0 start");

    check(aot_as_seal(as) == AOT_MEM_OK, "seal");
    check(aot_as_seal(as) == AOT_MEM_OK, "seal is idempotent");
    /* A region whose last byte is 2^39-1 is fully addressable after seal. */
    memset(back, 0, sizeof(back));
    check(aot_as_read(as, AOT_AS_MAX_ADDR - 1ull, back, 1) == AOT_MEM_OK,
          "last byte below 2^39 is readable");
    check(aot_as_read(as, AOT_AS_MAX_ADDR, back, 1) == AOT_MEM_ERR_RANGE,
          "first byte at 2^39 is not mapped");
    check(aot_as_add_region(as, 0x100040000ull, PG, AOT_AS_PERM_RW, 4u, NULL) ==
              AOT_MEM_ERR_RANGE,
          "region added after seal is rejected");
    check(aot_mem_init_aspace(&mem, as) == AOT_MEM_OK, "mem handle over the AS");

    /* ---- cross-region access (both regions still RW) --------------------- */
    check(aot_mem_st16(&mem, BASE_DATA + 0x1fffull, 0x1234u) ==
              AOT_MEM_ERR_RANGE,
          "access straddling two regions is a range error");
    v = 0;
    check(aot_mem_ld8(&mem, BASE_DATA + 0x1fffull, (uint8_t *)&v) == AOT_MEM_OK &&
              (v & 0xffu) == 0x33u,
          "straddling access wrote nothing (DATA last byte)");
    v = 0;
    check(aot_mem_ld8(&mem, BASE_ADJ, (uint8_t *)&v) == AOT_MEM_OK &&
              (v & 0xffu) == 0x44u,
          "straddling access wrote nothing (ADJ first byte)");
    {
        uint64_t pair[2] = { 0x0102030405060708ull, 0x1112131415161718ull };
        check(aot_mem_st128(&mem, BASE_DATA + 0x1ff8ull, pair) ==
                  AOT_MEM_ERR_RANGE,
              "16-byte store straddling two regions is a range error");
        v = 0;
        check(aot_mem_ld8(&mem, BASE_DATA + 0x1fffull, (uint8_t *)&v) ==
                      AOT_MEM_OK && (v & 0xffu) == 0x33u,
              "16-byte cross-region store wrote nothing (DATA last byte)");
        v = 0;
        check(aot_mem_ld8(&mem, BASE_ADJ, (uint8_t *)&v) == AOT_MEM_OK &&
                  (v & 0xffu) == 0x44u,
              "16-byte cross-region store wrote nothing (ADJ first byte)");
    }

    /* Data page 1 becomes read-only AFTER the seal (RELRO-style). */
    check(aot_as_protect(as, BASE_DATA + PG, PG, AOT_AS_PERM_R) == AOT_MEM_OK,
          "protect DATA page1 to R");

    /* ---- permission matrix ---------------------------------------------- */
    check(aot_mem_st64(&mem, BASE_DATA, 0x1122334455667788ull) == AOT_MEM_OK,
          "store to an RW page");
    check(aot_mem_ld64(&mem, BASE_DATA, &v) == AOT_MEM_OK &&
              v == 0x1122334455667788ull,
          "load from an RW page");
    check(aot_mem_ld64(&mem, BASE_RO, &v) == AOT_MEM_OK &&
              v == 0xccccccccccccccccull,
          "load from an R-only page");
    check(aot_mem_st64(&mem, BASE_RO, 0ull) == AOT_MEM_ERR_PERM,
          "store to an R-only page is rejected");
    check(aot_mem_ld64(&mem, BASE_CODE, &v) == AOT_MEM_OK &&
              v == 0x5a5a5a5a5a5a5a5aull,
          "load from an R-X page is allowed (code readable as data)");
    check(aot_mem_st64(&mem, BASE_CODE, 0ull) == AOT_MEM_ERR_PERM,
          "store to an R-X page is rejected");
    check(aot_mem_ld64(&mem, BASE_NONE, &v) == AOT_MEM_ERR_PERM,
          "load from a --- page is rejected");
    check(aot_mem_st64(&mem, BASE_NONE, 0ull) == AOT_MEM_ERR_PERM,
          "store to a --- page is rejected");
    check(aot_mem_ld64(&mem, UNMAPPED, &v) == AOT_MEM_ERR_RANGE,
          "load from an unmapped address is a range error");
    check(aot_mem_st64(&mem, UNMAPPED, 0ull) == AOT_MEM_ERR_RANGE,
          "store to an unmapped address is a range error");

    /* ---- page-straddling store must write NOTHING ------------------------ */
    check(aot_mem_st16(&mem, BASE_DATA + 0xfffull, 0xabcd) == AOT_MEM_ERR_PERM,
          "store across a RW->R page boundary is rejected");
    v = 0;
    check(aot_mem_ld8(&mem, BASE_DATA + 0xfffull, (uint8_t *)&v) == AOT_MEM_OK &&
              (v & 0xffu) == 0x11u,
          "store across a RW->R page boundary writes zero bytes (first page)");
    v = 0;
    check(aot_mem_ld8(&mem, BASE_DATA + 0x1000ull, (uint8_t *)&v) == AOT_MEM_OK &&
              (v & 0xffu) == 0x22u,
          "store across a RW->R page boundary writes zero bytes (second page)");

    /* A 16-byte store straddling the same boundary must also write nothing. */
    {
        uint64_t pair[2] = { 0x0102030405060708ull, 0x1112131415161718ull };
        check(aot_mem_st128(&mem, BASE_DATA + 0xff8ull, pair) == AOT_MEM_ERR_PERM,
              "16-byte store across a RW->R page boundary is rejected");
        v = 0;
        check(aot_mem_ld8(&mem, BASE_DATA + 0xfffull, (uint8_t *)&v) ==
                      AOT_MEM_OK && (v & 0xffu) == 0x11u,
              "16-byte store across a page boundary writes zero bytes");
    }

    /* ---- protect --------------------------------------------------------- */
    check(aot_as_protect(as, BASE_DATA + 0x800ull, PG, AOT_AS_PERM_R) ==
              AOT_MEM_ERR_ALIGN,
          "protect with a misaligned address is rejected");
    check(aot_as_protect(as, BASE_DATA, 0ull, AOT_AS_PERM_R) ==
              AOT_MEM_ERR_ALIGN,
          "protect with a zero size is rejected");
    check(aot_as_protect(as, BASE_DATA, PG, AOT_AS_PERM_RX) ==
              AOT_MEM_ERR_WIDTH,
          "protect to an executable permission is rejected");
    check(aot_as_protect(as, BASE_DATA, PG, AOT_AS_PERM_W) == AOT_MEM_ERR_WIDTH,
          "protect to write-without-read is rejected");
    check(aot_as_protect(as, UNMAPPED, PG, AOT_AS_PERM_R) == AOT_MEM_ERR_RANGE,
          "protect outside every region is rejected");
    check(aot_as_protect(as, BASE_DATA + PG, 2ull * PG, AOT_AS_PERM_R) ==
              AOT_MEM_ERR_RANGE,
          "protect spanning two regions is rejected");
    check(aot_as_protect(as, BASE_CODE, PG, AOT_AS_PERM_R) == AOT_MEM_ERR_PERM,
          "protect of an executable page is rejected");
    check(aot_as_protect(as, BASE_MISC + PG, PG, AOT_AS_PERM_RW) == AOT_MEM_OK,
          "protect to the same permission is accepted");
    check(aot_as_protect(as, BASE_MISC, PG, AOT_AS_PERM_R) == AOT_MEM_OK,
          "protect MISC page0 to R");
    check(aot_mem_st32(&mem, BASE_MISC, 0ull) == AOT_MEM_ERR_PERM,
          "store after protect-to-R is rejected");
    check(aot_as_protect(as, BASE_MISC, PG, AOT_AS_PERM_RW) == AOT_MEM_OK,
          "protect MISC page0 back to RW");
    check(aot_mem_st32(&mem, BASE_MISC, 0x1234u) == AOT_MEM_OK,
          "store after protect-back-to-RW succeeds");

    /* ---- lock / query ---------------------------------------------------- */
    check(aot_as_lock(as, BASE_MISC + 0x800ull, PG) == AOT_MEM_ERR_ALIGN,
          "lock with a misaligned address is rejected");
    check(aot_as_lock(as, UNMAPPED, PG) == AOT_MEM_ERR_RANGE,
          "lock outside every region is rejected");
    check(aot_as_lock(as, BASE_MISC + 3ull * PG, PG) == AOT_MEM_OK,
          "lock MISC page3");
    check(aot_as_protect(as, BASE_MISC + 3ull * PG, PG, AOT_AS_PERM_R) ==
              AOT_MEM_ERR_PERM,
          "protect of a locked page is rejected");
    check(aot_mem_st32(&mem, BASE_MISC + 3ull * PG, 0x55u) == AOT_MEM_OK,
          "lock does not change the permission");

    {
        AotAsQuery q;
        memset(&q, 0, sizeof(q));
        check(aot_as_query(as, BASE_MISC, &q) == 1, "query MISC page0 is mapped");
        check(q.base == BASE_MISC && q.size == 3ull * PG && q.perm == 3u &&
                  q.state == 4u && q.attr == 0u,
              "query reports the maximal identical run (3 RW pages)");
        check(aot_as_query(as, BASE_MISC + 3ull * PG, &q) == 1,
              "query MISC page3 is mapped");
        check(q.base == BASE_MISC + 3ull * PG && q.size == PG && q.perm == 3u &&
                  q.attr == 16u,
              "query reports the locked attribute and a 1-page run");
        check(aot_as_query(as, BASE_DATA, &q) == 1, "query DATA page0 is mapped");
        check(q.base == BASE_DATA && q.size == PG && q.perm == 3u &&
                  q.state == 4u,
              "query DATA page0 run");
        check(aot_as_query(as, BASE_DATA + PG, &q) == 1,
              "query DATA page1 is mapped");
        check(q.base == BASE_DATA + PG && q.size == PG && q.perm == 1u,
              "query DATA page1 run is R-only");
        check(aot_as_query(as, BASE_CODE, &q) == 1, "query CODE is mapped");
        check(q.perm == 5u && q.state == 3u,
              "query CODE reports R-X and state text");
        check(aot_as_query(as, BASE_NONE, &q) == 1, "query NONE is mapped");
        check(q.perm == 0u, "query NONE reports no permission");
        check(aot_as_query(as, UNMAPPED, &q) == 0, "query unmapped returns 0");
        check(aot_as_query(as, BASE_RO + 0x1000ull, &q) == 1,
              "query RO second page is mapped");
        check(q.base == BASE_RO && q.size == 2ull * PG,
              "query RO run covers both R pages");
    }

    /* ---- HOST protection (lead finding): guest X is never host EXECUTE --- */
    /* aot_as_seal applies the declared guest permissions to the host pages. The
     * guest X bit must NOT reach the host mapping: guest text holds ARM64 bytes
     * that the host CPU can never execute, and no dynamically created
     * host-executable memory is allowed. Query the OS (host_vm_query AND
     * VirtualQuery) for every permission class, not the software table. */
    {
        static const struct {
            uint64_t addr;
            const char *what;
            unsigned want_host;   /* expected host_vm_prot bits */
        } host_cases[] = {
            { BASE_CODE, "R-X text page", HOST_VM_PROT_READ },
            { BASE_DATA, "RW data page", HOST_VM_PROT_READ | HOST_VM_PROT_WRITE },
            { BASE_RO, "R-- rodata page", HOST_VM_PROT_READ },
            { BASE_NONE, "--- reserved page", HOST_VM_PROT_NONE },
        };
        char msg[160];
        size_t i;

        for (i = 0; i < sizeof(host_cases) / sizeof(host_cases[0]); i++) {
            host_vm_region *vm = NULL;
            const uint8_t *page = NULL;
            size_t off = 0;
            host_vm_info info;
            int mapped = aot_as_host_page(as, host_cases[i].addr, &vm, &page,
                                          &off);

            (void)snprintf(msg, sizeof msg, "host locator resolves the %s",
                           host_cases[i].what);
            check(mapped == 1 && vm != NULL && page != NULL, msg);
            if (mapped != 1) {
                continue;
            }
            memset(&info, 0, sizeof info);
            (void)snprintf(msg, sizeof msg,
                           "host_vm_query reports the %s protection",
                           host_cases[i].what);
            check(host_vm_query(vm, off, &info) == HOST_VM_OK, msg);
            /* The no-EXECITE assertion is checked FIRST so its text is the
             * mutant's first failure and stays independent of the value. */
            (void)snprintf(msg, sizeof msg,
                           "%s has no HOST_VM_PROT_EXEC bit",
                           host_cases[i].what);
            check((info.protection & HOST_VM_PROT_EXEC) == 0u, msg);
            (void)snprintf(msg, sizeof msg,
                           "%s carries exactly host protection %u (got %u)",
                           host_cases[i].what, host_cases[i].want_host,
                           (unsigned)info.protection);
            check(info.protection == host_cases[i].want_host, msg);
        }

        /* The same page through the OS's own API: an ARM64 text page must be
         * PAGE_READONLY (never PAGE_EXECUTE_READ / _WRITECOPY / _EXECUTE). */
        {
            host_vm_region *vm = NULL;
            const uint8_t *page = NULL;
            MEMORY_BASIC_INFORMATION mbi;

            check(aot_as_host_page(as, BASE_CODE, &vm, &page, NULL) == 1 &&
                      page != NULL,
                  "host locator resolves the R-X text page");
            if (page != NULL) {
                memset(&mbi, 0, sizeof mbi);
                check(VirtualQuery((LPCVOID)page, &mbi, sizeof mbi) ==
                          sizeof mbi,
                      "VirtualQuery on the text page succeeds");
                check(mbi.Protect == PAGE_READONLY,
                      "guest text page is host READ-ONLY (no EXECUTE)");
                check((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                      PAGE_EXECUTE_READWRITE |
                                      PAGE_EXECUTE_WRITECOPY)) == 0u,
                      "guest text page carries no PAGE_EXECUTE* bit");
            }
        }
    }

    /* ---- exclusive / ordered -------------------------------------------- */
    token = aot_mem_domain_attach(dom);
    check(token != 0u, "attach exclusive-monitor token");
    check(aot_mem_ldx(&mem, token, BASE_DATA, 8, &v) == AOT_MEM_OK,
          "exclusive load from an RW page");
    {
        uint32_t st = 0xee;
        check(aot_mem_stx(&mem, token, BASE_DATA, 8, v, &st) == AOT_MEM_OK &&
                  st == 0u,
              "exclusive store to an RW page succeeds");
    }
    check(aot_mem_ldx(&mem, token, BASE_RO, 8, &v) == AOT_MEM_OK,
          "exclusive load from an R-only page");
    {
        uint32_t st = 0xee;
        uint64_t before = 0;
        check(aot_mem_stx(&mem, token, BASE_RO, 8, 0x77ull, &st) ==
                      AOT_MEM_ERR_PERM && st == 1u,
              "exclusive store to an R-only page is rejected");
        check(aot_mem_ld64(&mem, BASE_RO, &before) == AOT_MEM_OK &&
                  before == 0xccccccccccccccccull,
              "rejected exclusive store changed nothing");
    }
    check(aot_mem_ldx(&mem, token, BASE_NONE, 8, &v) == AOT_MEM_ERR_PERM,
          "exclusive load from a --- page is rejected");
    check(aot_mem_ldar(&mem, BASE_CODE, 8, &v) == AOT_MEM_OK,
          "ordered load from an R-X page is allowed");
    check(aot_mem_stlr(&mem, BASE_CODE, 8, 0ull) == AOT_MEM_ERR_PERM,
          "ordered store to an R-X page is rejected");
    aot_mem_domain_detach(dom, token);

    /* ---- bulk helpers ---------------------------------------------------- */
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i * 7u + 3u);
    check(aot_as_write(as, BASE_DATA + 0x10ull, buf, sizeof(buf)) == AOT_MEM_OK,
          "aot_as_write into an RW page");
    memset(back, 0, sizeof(back));
    check(aot_as_read(as, BASE_DATA + 0x10ull, back, sizeof(back)) ==
                  AOT_MEM_OK && memcmp(buf, back, sizeof(buf)) == 0,
          "aot_as_read returns what was written");
    memset(buf, 0x99, sizeof(buf));
    check(aot_as_write(as, BASE_RO, buf, 8) == AOT_MEM_ERR_PERM,
          "aot_as_write into an R-only page is rejected");
    check(aot_as_read(as, BASE_RO, back, 8) == AOT_MEM_OK &&
              back[0] == 0xcc,
          "rejected aot_as_write changed nothing");
    check(aot_as_read(as, BASE_NONE, back, 8) == AOT_MEM_ERR_PERM,
          "aot_as_read from a --- page is rejected");
    check(aot_as_read(as, UNMAPPED, back, 8) == AOT_MEM_ERR_RANGE,
          "aot_as_read from unmapped memory is a range error");
    check(aot_as_write(as, UNMAPPED, buf, 8) == AOT_MEM_ERR_RANGE,
          "aot_as_write to unmapped memory is a range error");
    check(aot_as_read(as, BASE_DATA, NULL, 0) == AOT_MEM_OK,
          "aot_as_read of zero bytes is a no-op");

    /* ---- multi-page copy across an RW|RW page boundary ------------------- */
    {
        /* BASE_MISC has four RW pages. A 64-byte access at page0+0xfe0 spans
         * the page 0/page 1 boundary; every byte on BOTH pages must travel. */
        const uint64_t at = BASE_MISC + PG - 32ull;
        uint8_t expect[64];
        for (size_t i = 0; i < sizeof(expect); i++)
            expect[i] = (uint8_t)(0xa0u + i);
        /* Pre-poison both pages so a byte that is not copied is detected. */
        memset(buf, 0x5c, sizeof(buf));
        check(aot_as_write(as, BASE_MISC + PG - 32ull, buf, 64) == AOT_MEM_OK,
              "pre-poison across the MISC page boundary");
        if (aot_mem_st64(&mem, at, 0x0102030405060708ull) != AOT_MEM_OK)
            fatal("multi-page st64 setup");
        check(aot_mem_ld64(&mem, at, &v) == AOT_MEM_OK &&
                  v == 0x0102030405060708ull,
              "64-bit store/load across an RW|RW page boundary round-trips");
        /* Byte-exact check of BOTH pages after a 64-byte bulk write. */
        check(aot_as_write(as, at, expect, sizeof(expect)) == AOT_MEM_OK,
              "bulk write across an RW|RW page boundary");
        memset(back, 0, sizeof(back));
        check(aot_as_read(as, at, back, sizeof(back)) == AOT_MEM_OK &&
                  memcmp(back, expect, sizeof(expect)) == 0,
              "bulk read across an RW|RW page boundary returns every byte");
        memset(back, 0, sizeof(back));
        check(aot_as_read(as, BASE_MISC + PG - 32ull, back, 32) == AOT_MEM_OK &&
                  memcmp(back, expect, 32) == 0,
              "page0 half of the boundary copy is byte-exact");
        memset(back, 0, sizeof(back));
        check(aot_as_read(as, BASE_MISC + PG, back, 32) == AOT_MEM_OK &&
                  memcmp(back, expect + 32, 32) == 0,
              "page1 half of the boundary copy is byte-exact");
    }

    /* ---- aot_mem_check in Program mode ----------------------------------- */
    check(aot_mem_check(&mem, BASE_DATA, 16) == AOT_MEM_OK,
          "mem check inside one region");
    check(aot_mem_check(&mem, UNMAPPED, 16) == AOT_MEM_ERR_RANGE,
          "mem check outside every region");
    check(aot_mem_check(&mem, BASE_DATA + 0x1ff8ull, 16) == AOT_MEM_ERR_RANGE,
          "mem check straddling two regions is a range error");

    /* A forged handle whose domain is NOT the address space's domain must fail
     * closed: taking a different lock would serialize against nothing and read
     * the page table unordered. (Non-trivial: an implementation without the
     * identity check performs the access successfully.) */
    {
        AotMem forged = mem;
        AotMemDomain *other = aot_mem_domain_create();
        if (other == NULL) fatal("second domain create");
        forged.domain = other;
        check(aot_mem_ld64(&forged, BASE_DATA, &v) == AOT_MEM_ERR_RANGE,
              "handle with a foreign domain cannot access guest memory");
        check(aot_mem_st64(&forged, BASE_DATA, 1ull) == AOT_MEM_ERR_RANGE,
              "forged handle cannot store into guest memory");
        check(aot_mem_check(&forged, BASE_DATA, 8) == AOT_MEM_ERR_RANGE,
              "forged handle fails the range check closed");
        check(aot_mem_is_aligned(BASE_DATA, 8) == 1,
              "forged handle did not disturb the genuine one");
        aot_mem_domain_destroy(other);
    }

    aot_as_destroy(as);
    aot_mem_domain_destroy(dom);

    if (g_fail) {
        printf("aot_as_probe: semantic failures\n");
        return 2;
    }
    printf("aot_as_probe: all address-space contract checks passed\n");
    return 0;
}
