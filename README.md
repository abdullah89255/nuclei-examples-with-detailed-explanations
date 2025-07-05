# nuclei-examples-with-detailed-explanations
Here are some **important and practical `nuclei` examples** with **detailed explanations** to help you use it effectively in real-world situations.

---

## 🔍 1. **Scan a Single URL**

```bash
nuclei -u https://example.com
```

* **`-u`**: Specifies the single target URL.
* Scans the site using all default templates.

---

## 🌐 2. **Scan Multiple URLs from a File**

```bash
nuclei -l urls.txt
```

* **`-l`**: Reads a list of URLs from a file.
* Useful for scanning many domains quickly (e.g., from subdomain enumeration).

---

## 🎯 3. **Scan for Specific CVEs (Critical Vulns)**

```bash
nuclei -u https://example.com -t cves/
```

* **`-t cves/`**: Use templates from the `cves` directory.
* Targets known vulnerabilities like Log4j, Spring4Shell, etc.

---

## 🚨 4. **Filter by Severity (High/Critical Only)**

```bash
nuclei -u https://example.com -severity high,critical
```

* **`-severity`**: Filters by severity level.
* Good for focusing only on major threats.

---

## 🧪 5. **Test for Exposed Panels (Admin, Login Pages, etc.)**

```bash
nuclei -u https://example.com -t exposed-panels/
```

* Scans for things like exposed admin dashboards, CMS panels, etc.

---

## 🔑 6. **Test for Exposed APIs and Secrets**

```bash
nuclei -u https://example.com -t exposed-tokens/
```

* Detects API keys, tokens, and credentials leaked in headers, responses, etc.

---

## 📁 7. **Scan for Open Redirect Vulnerabilities**

```bash
nuclei -u https://example.com -t vulnerabilities/redirect.yaml
```

* Checks if the URL is vulnerable to open redirects.
* Can lead to phishing or malicious redirection attacks.

---

## 🧱 8. **WAF Detection (Firewall)**

```bash
nuclei -u https://example.com -t technologies/waf-detect.yaml
```

* Helps you identify if a web application is protected by a Web Application Firewall.

---

## 📤 9. **Export Results to File (JSON or Plaintext)**

```bash
nuclei -u https://example.com -json -o output.json
```

OR

```bash
nuclei -u https://example.com -o result.txt
```

* Useful for saving scan results for later review or reporting.

---

## 🔁 10. **Scan in Silent Mode**

```bash
nuclei -u https://example.com -silent
```

* Suppresses extra output, showing only important results.
* Useful for scripting or automation.

---

## ⚡ 11. **Speed Up with More Threads**

```bash
nuclei -u https://example.com -c 50
```

* **`-c`**: Sets concurrency (50 threads here).
* Great for faster scanning, especially for large URL lists.

---

## ⚙️ 12. **Update Nuclei and Templates**

```bash
nuclei -update
nuclei -update-templates
```

* Always keep your tool and templates updated for best coverage.

---

## 🔄 13. **Scan with Custom Templates**

```bash
nuclei -u https://example.com -t /path/to/my-templates/
```

* If you’ve written or downloaded specific custom templates.

---

## 🎯 Bonus: **Use in Subdomain Enumeration Workflow**

Example:

```bash
subfinder -d example.com -silent | httpx -silent | nuclei -l -
```

* Chains tools together:

  1. `subfinder`: Finds subdomains.
  2. `httpx`: Resolves to HTTP/HTTPS.
  3. `nuclei`: Scans for vulnerabilities.

---

Great! Here's a **rich list of advanced and useful Nuclei examples**, categorized by use case, so you can get the most out of it during bug bounty, penetration testing, or red teaming.

---

## 🧩 CATEGORY-WISE NUCLEI EXAMPLES (WITH DETAILS)

---

### 🔐 1. **Authentication Issues**

```bash
nuclei -u https://target.com -t misconfiguration/basic-auth-detect.yaml
```

* Detects basic auth protection that may be bypassed or brute-forced.

---

### 💣 2. **RCE Vulnerability Detection**

```bash
nuclei -u https://target.com -t cves/2021/CVE-2021-41773.yaml
```

* Detects Apache HTTP Server RCE via path traversal.
* Real-world exploit used in Apache 2.4.49.

---

### 🔍 3. **Detect JavaScript Exposures**

```bash
nuclei -u https://target.com -t expose-js/
```

* Detects exposed `.js` files that might contain secrets, API keys, or endpoints.

---

### 🕵️‍♂️ 4. **Information Disclosure**

```bash
nuclei -u https://target.com -t exposures/files/git-config.yaml
```

* Checks if `.git/config` is exposed — can leak repo history and internal code.

```bash
nuclei -u https://target.com -t exposures/files/env.yaml
```

* Checks if `.env` file is exposed — may contain credentials.

---

### 🧪 5. **SQL Injection Detection**

```bash
nuclei -u https://target.com/page.php?id=1 -t vulnerabilities/sql-injection/
```

* Scans for known SQLi payload responses.
* Note: Passive detection only — doesn't exploit or use heavy payloads like sqlmap.

---

### 🎛️ 6. **Tech Stack Fingerprinting**

```bash
nuclei -u https://target.com -t technologies/
```

* Detects web frameworks, languages, platforms like WordPress, Apache, React, etc.

---

### 🔑 7. **JWT and Token Disclosure**

```bash
nuclei -u https://target.com -t tokens/jwt-token.yaml
```

* Finds JWT tokens in response headers or body.
* Could be used for privilege escalation or replay attacks.

---

### 🧰 8. **CORS Misconfiguration**

```bash
nuclei -u https://target.com -t misconfiguration/cors-misconfig.yaml
```

* Looks for overly permissive CORS headers (e.g., `Access-Control-Allow-Origin: *`)
* Dangerous for APIs with sensitive data.

---

### 🔁 9. **Chain Recon with Other Tools**

```bash
cat domains.txt | httpx -silent | nuclei -t cves/ -severity critical -o critical_findings.txt
```

* Combines `httpx` for live URL probing + nuclei for CVE scanning.

---

### 📑 10. **Scan for Common Sensitive Files**

```bash
nuclei -u https://target.com -t exposures/configs/
```

Includes:

* `.env`
* `config.php`
* `web.config`
* `wp-config.php`

---

### ⚠️ 11. **Detect Cloud Bucket Misconfiguration**

```bash
nuclei -u https://target.com -t cloud/
```

* Detects misconfigured S3, Azure, or GCP buckets.

---

### 🌐 12. **CVE Year Range Specific Scans**

```bash
nuclei -u https://target.com -t cves/2022/
```

* Focuses only on CVEs from 2022.

---

### 📊 13. **Scan for WordPress Vulnerabilities**

```bash
nuclei -u https://target.com -t vulnerabilities/wordpress/
```

* Checks plugins, themes, version disclosure, XML-RPC issues, etc.

---

### 🔍 14. **Favicon Hashing (Service Detection)**

```bash
nuclei -u https://target.com/favicon.ico -t fingerprints/favicon.yaml
```

* Uses favicon hash to detect technologies like Shodan does.

---

### 📁 15. **Find Backup Files (.bak, .zip, etc.)**

```bash
nuclei -u https://target.com -t exposures/backups/
```

* Detects `.zip`, `.bak`, `.tar.gz`, `.rar`, `.old`, etc.
* Often leaks entire source code or database.

---

### 💾 16. **Scan with Specific Template Tags**

```bash
nuclei -u https://target.com -tags exposure,misconfig
```

* Use tag-based filtering instead of directories.
* Useful for grouped scans.

---

## 🛠️ BONUS: Custom Scan Template Example

Create your own template:

```bash
nano my-custom.yaml
```

```yaml
id: custom-header-check
info:
  name: Check for X-Powered-By Header
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "X-Powered-By:.*"
```

Run it:

```bash
nuclei -u https://target.com -t my-custom.yaml
```

---

Would you like a **filtered list of top templates**, or instructions on how to **write automated scan scripts** using Nuclei + bash/Python?

