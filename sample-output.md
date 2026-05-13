# apple.com

**Customer:** Apple Inc  
**Last updated:** 2026-05-13  
**Domain expires:** 2027-02-20 (283 days)  
**Notes:** Demo output  

## Risk Flags

- ⚠ DNSSEC not enabled

## Registration

**Registrar:** NOM-IQ Ltd dba Com Laude  
**Registrant org:** Apple Inc.  
**Created:** 1987-02-19  
**Updated:** 2026-02-09  
**Expires:** 2027-02-20  
**DNSSEC:** unsigned  
**Status:**  
- clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
- clientTransferProhibited https://icann.org/epp#clientTransferProhibited
- clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
- serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
- serverTransferProhibited https://icann.org/epp#serverTransferProhibited
- serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited

## TLS Certificate

**Checked host:** apple.com  
**Subject CN:** apple.com  
**Issuer:** Apple Inc.  
**Not before:** 2026-04-23  
**Not after:** 2026-07-16 (64 days)  
**SANs:** apple.com  

## Hosting

**DNS provider:** a.ns.apple.com  
**Web host:** icloud.com (17.253.144.10)  
**Email provider:** mx-in-hfd.apple.com  

## HTTP Redirects

**HTTP → HTTPS:** Yes  
**www redirect:** apple.com → www.apple.com (301)  

## Email Security

**SPF:** ✓  
```
v=spf1 include:_spf.apple.com include:_spf-txn.apple.com ~all
```

**DMARC:** ✓  
```
v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;
```

**DKIM:** ✓ (selectors: selector1, selector2)  
```
selector1._domainkey
  v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGh555cVTGrCFyGsKqZyAehAhyNLVzwSCNdtgBSol5e/KboxA6edyqdfl1EL279hNdHM9UWcXcgk/HhKPQdmgzMTA927ZXxrsHxMHjVl7Bid78qOIebr75prj3jxuH8KrZfNe14l/dh6TJZt/SkEncmhbVx/tNy9lrHkN5T7LXjQIDAQAB; n=1024,1483209771,1498848171
selector2._domainkey
  v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw9ZicGGW3gn0iKQfcnOsMVy+uLl+YMFonHmEslnpniYxIZ8z0Fn5nY2Gx/m69EHq05WQ8zQ0hRP8d/B0lrPIm6O3c2hiO1sQrJUnwH3jo0/asN6kRFXjTiU/PdlmWhyLdYSv80zNlKpq7qWnsvtlTfJhatEJATM1gZOtspjqLzQIDAQAB; n=1024,1483209771,1
```

## DNS Records

### A  (TTL: 623)

```
17.253.144.10
```

### AAAA  (TTL: 388)

```
2620:149:af0::10
```

### MX  (TTL: 1519)

```
20 mx-in-hfd.apple.com.
20 mx-in-vib.apple.com.
20 mx-in-sg.apple.com.
20 mx-in-rn.apple.com.
20 mx-in-ma.apple.com.
10 mx-in.g.apple.com.
```

### TXT  (TTL: 1519)

```
atlassian-domain-verification=qZD4TfnCAoAjCFQgafhoKQpOs9tviekNK4wYE4a5eK3XoRP06hXAvEp8SLU0v7fI
facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v
adobe-idp-site-verification=6bd5e74c-a3a0-4781-b2e1-e95399b5e11c
apple-domain-verification=X5Jt76bn3Dnmgzjj
google-site-verification=8M6XjQCzydT62jk8HY3VXPAG-nKDllTRV-JpA3-Ktyw
cisco-ci-domain-verification=6f3bfb849796a518061f8e8c4356f687a138502d86db742791685059176547dd
webexdomainverification.8C462=b728ec3f-dfc9-42f9-92cb-9ba8853cbee8
v=spf1 include:_spf.apple.com include:_spf-txn.apple.com ~all
(...trimmed: 22 TXT records total...)
```

### NS  (TTL: 18037)

```
a.ns.apple.com.
c.ns.apple.com.
b.ns.apple.com.
d.ns.apple.com.
```

### SOA  (TTL: 300)

```
ns-ext-prod.jackfruit.apple.com. dnscontact.apple.com. 2026051204 300 300 3628800 300
```

### CAA  (TTL: 299)

```
0 issuewild "pki.apple.com"
0 issue "pki.apple.com"
0 iodef "mailto:contact_pki@apple.com"
```

## Subdomains (via crt.sh)

```
app.apple.com
  A:     17.167.225.11
  AAAA:  —
  CNAME: —

autodiscover.apple.com
  A:     17.32.214.19
  AAAA:  —
  CNAME: mailpex.apple.com.

shop.apple.com
  A:     23.219.36.111, 23.219.36.113
  AAAA:  2600:141b:e800:25::1721:2ad8, 2600:141b:e800:25::1721:2ac9
  CNAME: shop.lb-apple.com.akadns.net.

store.apple.com
  A:     23.52.158.58
  AAAA:  —
  CNAME: store-apple-com.v.aaplimg.com.

www.apple.com
  A:     23.222.125.27
  AAAA:  2600:141b:e800:128b::1aca, 2600:141b:e800:1289::1aca
  CNAME: www-apple-com.v.aaplimg.com.
```
