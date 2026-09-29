import logging

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

PUBLIC_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]


def _resolver(use_public: bool) -> dns.resolver.Resolver:
    if use_public:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = PUBLIC_NAMESERVERS
    else:
        resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 6.0
    return resolver


def query(name: str, record_type: str) -> tuple[list[str], str]:
    """
    Look up one record type. Returns (values, status), where status is:
      "ok"     records were found
      "empty"  the lookup worked and there is no such record (or no such domain)
      "failed" the lookup itself failed (timeout, SERVFAIL, no resolver)

    Keeping "empty" and "failed" apart is what stops a flaky lookup from
    being reported as a missing SPF/DMARC record.
    First attempt uses the system resolver, the retry uses public resolvers.
    """
    for attempt in range(2):
        try:
            resolver = _resolver(use_public=(attempt == 1))
            answers = resolver.resolve(name, record_type)
            return [str(r) for r in answers], "ok"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return [], "empty"
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
            logger.warning("DNS %s lookup for %s failed (attempt %s): %s", record_type, name, attempt + 1, e)
        except Exception as e:
            logger.error("DNS %s lookup for %s errored (attempt %s): %s", record_type, name, attempt + 1, e)
    return [], "failed"