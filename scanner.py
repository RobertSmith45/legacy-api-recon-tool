import requests
import json
import time
from urllib.parse import urljoin
from .utils import logger, SecurityHeaders, VulnerabilityCheck

class APIScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.found_endpoints = []
        self.vulnerabilities = []
        
    def load_endpoints(self):
        """Load known endpoints list"""
        try:
            with open('src/endpoints.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "legacy_endpoints": [
                    "/api/legacy/search_customers",
                    "/api/legacy/user_profile",
                    "/api/legacy/admin_panel",
                    "/api/legacy/backup",
                    "/api/legacy/debug"
                ],
                "common_endpoints": [
                    "/api/v1/users",
                    "/api/v1/admin",
                    "/api/health",
                    "/debug",
                    "/backup"
                ]
            }
    
    def discover_endpoints(self):
        """Discover available endpoints"""
        logger.info(f"Scanning {self.target_url}")
        
        endpoints = self.load_endpoints()
        all_endpoints = endpoints["legacy_endpoints"] + endpoints["common_endpoints"]
        
        for endpoint in all_endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code != 404:
                    self.found_endpoints.append({
                        'url': url,
                        'status_code': response.status_code,
                        'method': 'GET',
                        'headers': dict(response.headers)
                    })
                    logger.success(f"Discovered: {url} [{response.status_code}]")
                    
            except requests.RequestException as e:
                logger.error(f"Error scanning {url}: {e}")
    
    def test_sql_injection(self, endpoint):
        """Test for SQL Injection vulnerabilities"""
        test_payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--"
        ]
        
        for payload in test_payloads:
            test_url = f"{endpoint['url']}?q={payload}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if any(indicator in response.text.lower() for indicator in ['error', 'sql', 'syntax', 'mysql']):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'endpoint': endpoint['url'],
                        'payload': payload,
                        'confidence': 'High'
                    })
                    logger.warning(f"Potential SQLi found: {endpoint['url']}")
                    break
            except:
                pass
    
    def test_xss(self, endpoint):
        """Test for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>"
        ]
        
        for payload in xss_payloads:
            test_url = f"{endpoint['url']}?search={payload}"
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'endpoint': endpoint['url'],
                        'payload': payload,
                        'confidence': 'Medium'
                    })
                    logger.warning(f"Potential XSS found: {endpoint['url']}")
                    break
            except:
                pass
    
    def scan(self):
        """Main scanning function"""
        logger.info("Starting comprehensive scan...")
        
        # Discover endpoints
        self.discover_endpoints()
        
        # Test each found endpoint
        for endpoint in self.found_endpoints:
            self.test_sql_injection(endpoint)
            self.test_xss(endpoint)
            # Add more tests here
        
        return {
            'target': self.target_url,
            'endpoints_found': self.found_endpoints,
            'vulnerabilities': self.vulnerabilities
        }
    
    def generate_report(self):
        """Generate scan report"""
        report = {
            'scan_date': time.ctime(),
            'target': self.target_url,
            'summary': {
                'endpoints_discovered': len(self.found_endpoints),
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'details': {
                'endpoints': self.found_endpoints,
                'vulnerabilities': self.vulnerabilities
            }
        }
        
        with open('scan_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.success("Report generated: scan_report.json")
        return report
