#ifndef VULNCHECK_H
#define VULNCHECK_H
#include <stdio.h>
#include <time.h>
#include "output.h"

struct TemplatePacket;

struct MassVulnCheck
{
    const char *name;
    
    /**
     * A list of default port ranges that should be used in case that none
     * are specified.
     */
    const char *ports;
    
    /**
     * The hello packet template
     */
    const unsigned char *packet;
    
    /**
     * The hello packet template length
     */
    unsigned packet_length;
    
    
    /**
     * Called to change the template based upon the target
     */
    void (*set_target)(struct TemplatePacket *tmpl,
                         unsigned ip_them, unsigned port_them,
                         unsigned ip_me, unsigned port_me,
                         unsigned seqno,
                         unsigned char *px, size_t sizeof_px, 
                         size_t *r_length);
    
    /**
     * Called at startup to change the template according to options
     */
    void (*init)(struct TemplatePacket *tmpl);
};

/**
 * Lookup the vuln based on the name
 * @param name
 *      The name of the vuln to check.
 * @return
 *      The desired vuln check if found, NULL if the vuln check doesn't exist
 */
struct MassVulnCheck *
vulncheck_lookup(const char *name);

/**
 * The function which will be invoked before printing the banner. Should
 * return not 0 to print grabbed banner.
 */
typedef unsigned int (BANNER_CHECKER_FUNC)(
        unsigned proto,
        const unsigned char *banner, unsigned length);
typedef BANNER_CHECKER_FUNC* BANNER_CHECKER;

/**
 * Invokes @check_func before to decide whether the grabbed info should be
 * sent to @output.
 * @param check_func
 *      Called on the banner content to check whether banner contains
 *      vulnerability flag.
 * @param @output_func
 *      Original output fucnction being wrapped.
 *
 */
OUTPUT_REPORT_BANNER checked_output_report_banner(
        BANNER_CHECKER check_func,
        OUTPUT_REPORT_BANNER output_func);

/**
 * List of defined checkers
 */
extern BANNER_CHECKER_FUNC check_netscaller_fixed_cert;
#endif
