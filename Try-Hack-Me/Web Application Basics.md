
---
```yml
---
date: 2025-09-17
author: Sameer Saini  
reason: 0x45 
title: Web Overview  
tags: [web, http, security, networking]
---
```


# 🌐 Web Overview

The **Web** consists of two main parts:  

- **Frontend** → What the user sees (client side)  
- **Backend** → What runs in the background (server side)  

---

## 🖥️ Frontend

The **frontend** is everything a user interacts with in the browser. It uses:

- **HTML** → Structure of the page (headings, text, links, forms)  
- **CSS** → Style and layout (colors, fonts, positioning)  
- **JavaScript** → Adds interactivity (animations, validation, dynamic updates)  

**Example:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>Frontend Example</title>
  <style>
    body { background: #222; color: #fff; font-family: Arial; }
    h1 { color: cyan; }
  </style>
</head>
<body>
  <h1>Hello World 🌍</h1>
  <button onclick="alert('Clicked!')">Click Me</button>
</body>
</html>
````

---

## ⚙️ Backend

The **backend** is not visible to the user but powers the application. It includes:

- **Database** → Stores data (e.g., users, passwords, transactions). Examples: MySQL, MongoDB.
    
- **Infrastructure** → The servers and operating systems that host the app.
    
- **WAF (Web Application Firewall)** → Protects against attacks like SQLi, XSS by filtering traffic.
    

---

# 🔗 Uniform Resource Locator (URL)

A **URL** is the address of a web resource.  
It has **7 parts**:

1. **Scheme** → Protocol used → `http://`, `https://`
    
2. **User** → Optional login details in the format `user:password@`
    
3. **Host/Domain** → The website name → `example.com`
    
4. **Port** → Service port (default: 80 for HTTP, 443 for HTTPS)
    
5. **Path** → File/directory → `/about/team.html`
    
6. **Query String** → Starts with `?` → `/search?q=test`
    
7. **Fragment** → Starts with `#`, jumps to a page section → `/docs#install`
    

**Example URL:**

```
https://user:pass@example.com:8080/products/list?id=123#reviews
```

---

# 📩 HTTP Messages

HTTP communication is based on **Requests** (client → server) and **Responses** (server → client).

### HTTP Request Example

```http
GET /login HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0
```

### HTTP Response Example

```http
HTTP/1.1 200 OK
Content-Type: text/html

<html><body>Welcome!</body></html>
```

---

# 📜 HTTP Request Line & Methods

The **Request Line** specifies:  
`METHOD /path HTTP/version`

### Methods with Examples

- **GET** → Retrieve data
    
    ```http
    GET /index.html HTTP/1.1
```
    
- **POST** → Send data (e.g., form submission)
    
    ```http
    POST /login HTTP/1.1
    Body: username=sam&password=1234
```
    
- **PUT** → Replace a resource
    
    ```http
    PUT /user/1 HTTP/1.1
    Body: {"name": "Sam"}
```
    
- **DELETE** → Remove a resource
    
    ```http
    DELETE /user/1 HTTP/1.1
```
    
- **PATCH** → Update part of a resource
    
    ```http
    PATCH /user/1 HTTP/1.1
    Body: {"age": 25}
```
    
- **HEAD** → Same as GET but only headers (no body)
    
- **OPTIONS** → Ask which methods are allowed
    
- **TRACE** → Debug, shows request loopback
    
- **CONNECT** → Establish tunnel (used in HTTPS proxies)
    

---

# 📩 Request Headers & Body

### Common Request Headers

|Header|Example|Description|
|---|---|---|
|Host|`Host: tryhackme.com`|Target domain/server|
|User-Agent|`User-Agent: Mozilla/5.0`|Browser/device info|
|Referer|`Referer: https://google.com/`|Where the request came from|
|Cookie|`Cookie: session=abc123`|Stores session data|
|Content-Type|`Content-Type: application/json`|Format of request body|

### Body Formats (Examples inside request)

- **Form Encoded** → `name=Sam&age=25`
    
- **Form Data (file upload)** → multipart with boundary
    
- **JSON** → `{ "name": "Sam", "age": 25 }`
    
- **XML** → `<user><name>Sam</name></user>`
    

---

# 📤 HTTP Response

### Status Line

Format: `HTTP/version status_code reason_phrase`

### Common Status Codes

- `100 Continue` → Informational
    
- `200 OK` → Success
    
- `301 Moved Permanently` → Redirect
    
- `404 Not Found` → Resource missing
    
- `500 Internal Server Error` → Server crash
    

### Common Response Headers

- `Date: Fri, 23 Aug 2024 10:43:21 GMT`
    
- `Content-Type: text/html; charset=utf-8`
    
- `Server: nginx`
    
- `Set-Cookie: sessionId=38af1337; HttpOnly; Secure`
    
- `Cache-Control: max-age=600`
    
- `Location: /login`
    

---

# 🛡️ Security Headers

### ✅ Content-Security-Policy (CSP)

Restricts where scripts, styles, or resources can load from. Prevents XSS.

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.site.com
```

---

### ✅ Strict-Transport-Security (HSTS)

Forces HTTPS only.

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

---

### ✅ X-Content-Type-Options

Prevents MIME type sniffing (browser guessing file type).

👉 Why?  
Attackers might upload a file like `evil.js` but rename it `evil.png`. Without this header, some browsers could "sniff" it as JavaScript and execute it.

```http
X-Content-Type-Options: nosniff
```

---

### ✅ Referrer-Policy

Controls how much referrer info is shared.

- `no-referrer` → Sends no referrer info
    
- `same-origin` → Sends referrer only if same site
    
- `strict-origin` → Sends only protocol + domain (HTTPS → HTTPS)
    
- `strict-origin-when-cross-origin` → Full referrer for same site, limited for external
    

```http
Referrer-Policy: strict-origin-when-cross-origin
```

---
