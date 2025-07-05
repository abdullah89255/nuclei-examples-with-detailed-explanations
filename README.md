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

Would you like a list of **top templates** or help writing **custom Nuclei templates** for your targets?
