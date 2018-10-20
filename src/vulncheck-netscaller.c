#include "vulncheck.h"
#include "string_s.h"

static const char netscaller_hardcoded_cert[] = {
        "MIICyDCCAjGgAwIBAgIJAIrHOW7lh0g5MA0GCSqGSIb3DQEBBQUAMH0xEDAOBgNVBAMMBy"
        "ouKi4qLioxHjAcBgNVBAoMFVRhbGFyaSBOZXR3b3JrcywgSW5jLjEUMBIGA1UECwwLRW5n"
        "aW5lZXJpbmcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMREwDwYDVQQHDA"
        "hTYW4gSm9zZTAeFw0xMzAzMjEyMDE4NDZaFw0yMzAzMTkyMDE4NDZaMH0xEDAOBgNVBAMM"
        "ByouKi4qLioxHjAcBgNVBAoMFVRhbGFyaSBOZXR3b3JrcywgSW5jLjEUMBIGA1UECwwLRW"
        "5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMREwDwYDVQQH"
        "DAhTYW4gSm9zZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2LtF/WLhKhTbllCVPF"
        "AZLNaBbkArk1hGl+ZZrl6YwB2ZYVwqY7DjKO/SQZd6EL9ORpdbKrX135Y0nomYog8GI9vZ"
        "8ml80yCxu3JnN4tC4UOVF+z6YxNdbwFUT5qzqZNrJU2Y0n5MoJ6nufYtcx8tfyQC8YElmk"
        "EWwg+lW+cJtAkCAwEAAaNQME4wHQYDVR0OBBYEFO6r2z43lGyop3VsoZgADVkZ1l9LMB8G"
        "A1UdIwQYMBaAFO6r2z43lGyop3VsoZgADVkZ1l9LMAwGA1UdEwQFMAMBAf8wDQYJKoZIhv"
        "cNAQEFBQADgYEAIlwchlhzxGvJdACgCgEhdvlZQh8NGZRYWk5632fXIKrbHBgzOJOqh5q2"
        "FExszo58T7RgasG42TrboYHvvaManbqSdp2SpIVAoHj3VRBn95XWNRiIipmMfw12hMjdsf"
        "sAV1nHy0kF8MmL/6Dhzp41/uYE9sx/blWePm/E18jcuuc="
};

unsigned int check_netscaller_fixed_cert(unsigned proto, const unsigned char *cert, unsigned length) {
    if (proto == PROTO_X509_CERT) {
        if (strncmp((const char *) cert, netscaller_hardcoded_cert, length) == 0) {
            return 1;
        }
    }
    return 0;
}