---
title: Http request and response
description: HTTP request and response fingerprinting and signatures.
---

HTTP requests and responses are another critical component analyzed to gather information about client and server interactions. The library analyzes the characteristics of HTTP traffic to reveal useful details about the browser that influenced certain patterns.

Huginn Net collects all TCP packets that are part of HTTP requests and responses and analyzes them to gather information about client and server interactions.

## HTTP signature

For HTTP traffic, signature layout is as follows:

```
sig = ver:horder:habsent:expsw
```

| Key       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ver`     | 0 for HTTP/1.0, 1 for HTTP/1.1, or '\*' for any.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `horder`  | Comma-separated, ordered list of headers that should appear in matching traffic. Substrings to match within each of these headers may be specified using a name=[value] notation. The signature will be matched even if other headers appear in between, as long as the list itself is matched in the specified sequence. Headers that usually do appear in the traffic, but may go away (e.g. Accept-Language if the user has no languages defined, or Referer if no referring site exists) should be prefixed with '?', e.g. "?Referer". P0f will accept their disappearance, but will not allow them to appear at any other location. |
| `habsent` | Comma-separated list of headers that must \*not\* appear in matching traffic. This is particularly useful for noting the absence of standard headers (e.g. 'Host'), or for differentiating between otherwise very similar signatures.                                                                                                                                                                                                                                                                                                       |
| `expsw`   | Expected substring in 'User-Agent' or 'Server'. This is not used to match traffic, and merely serves to detect dishonest software. If you want to explicitly match User-Agent, you need to do this in the 'horder' section.                                                                                                                                                                                                                                                                                                               |

## HTTP Request

These are sent by the client (typically a web browser) to request resources from a server. The request includes information such as the HTTP method (GET, POST, etc.), headers, and sometimes cookies or other client-specific data.

### HTTP Request Analyzed

```bash
[HTTP Request] 1.2.3.4:1524 → 4.3.2.1:80
  Browser: Firefox:10.x or newer
  Lang:    English
  Params:  none
  Sig:     1:Host,User-Agent,Accept=[,*/*;q=],?Accept-Language=[;q=],Accept-Encoding=[gzip, deflate],?DNT=[1],Connection=[keep-alive],?Referer:Accept-Charset,Keep-Alive:Firefox/
```

### HTTP Request Key Fields

- **Browser**: The identified browser matched from the database signature.
- **Lang**: The detected language from Accept-Language header.
- **Params**: Additional parameters or optional data included in the headers.
- **Sig**: The HTTP request signature showing header order and values.

## HTTP Response

These are sent by the server in reply to the client's request, containing the requested resource (HTML page, image, etc.) or a status message indicating the success or failure of the request.

### HTTP Response Analyzed

```bash
[HTTP Response] 192.168.1.22:58494 → 91.189.91.21:80
  Server:  nginx/1.14.0 (Ubuntu)
  Params:  anonymous
  Sig:     server=[nginx/1.14.0 (Ubuntu)],date=[Tue, 17 Dec 2024 13:54:16 GMT],x-cache-status=[from content-cache-1ss/0],connection=[close]:Server,Date,X-Cache-Status,Connection:
```

### HTTP Response Key Fields

- **Server**: The identified web server matched from the database signature.
- **Params**: Additional parameters or optional data included in the headers.
- **Sig**: The HTTP response signature showing header order and values.
