In this repository, I am developing a web application security scanner focused on the OWASP Top 10 vulnerabilities. Updates will be added progressively.

The first component, bcrawler, is designed for crawling web applications. This script uses Selenium to bypass client-side JavaScript-based link generators and capture dynamically generated URLs. During crawling, it categorizes sensitive resources such as backup files and login paths, and performs basic security checks, including HTTP security headers validation and session misconfiguration detection.

All collected data is stored in a MySQL database, which is used as the primary backend for managing crawl results, identified endpoints, and security findings.
