- `lint` rules L-11 (a sub-delegation to the current provider's servers is lame after the exit; blocker), L-12
  (a CNAME, MX, SRV, DNAME, SVCB or HTTPS target under the current provider's own domain; risk), L-16 (an answer
  larger than 1232 bytes with its signatures truncates over UDP; note) and L-20 (apex nameservers that share an
  address, a /24 or a /48 prefix; risk). Provider domains use the public suffix list.
- `parity` reports shared fate between providers (`shared-fate`, risk): servers of two providers that share an
  address, a /24 or a /48 prefix. IPv4 and IPv6 alike; AS numbers are not checked yet.
