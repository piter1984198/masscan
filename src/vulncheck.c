#include "vulncheck.h"
#include "string_s.h"

extern struct MassVulnCheck vuln_ntp_monlist;


struct MassVulnCheck *
vulncheck_lookup(const char *name)
{
    if (strcmp(name, vuln_ntp_monlist.name) == 0)
        return &vuln_ntp_monlist;
    return 0;
}

static BANNER_CHECKER vuln_check_func;
static OUTPUT_REPORT_BANNER vuln_output_func;

void _checked_output_report_banner(
        struct Output *output,
        time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        unsigned proto,
        unsigned ttl,
        const unsigned char *px, unsigned length)
{
    if (vuln_check_func(proto, px, length)) {
        vuln_output_func(output, timestamp, ip, ip_proto, port, proto, ttl, px, length);
    }
}

OUTPUT_REPORT_BANNER checked_output_report_banner(
        BANNER_CHECKER check_func,
        OUTPUT_REPORT_BANNER output_func)
{
    vuln_check_func = check_func;
    vuln_output_func = output_func;
    return _checked_output_report_banner;
}
