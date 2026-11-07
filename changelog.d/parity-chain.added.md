- `parity --parent ADDR[,ADDR]` checks the chain from the parent's DS RRset to every server's DNSKEY RRset: a served
  key must match a DS and sign the DNSKEY RRset validly. A parent without DS is a note (insecure delegation); a signed
  zone checked without `--parent` gives no verdict.
