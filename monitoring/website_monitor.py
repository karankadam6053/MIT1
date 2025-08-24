import requests
import trafilatura
import ssl
import socket
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
import time
import re
from typing import Dict, List, Any


class WebsiteMonitor:
    """Website security monitoring and analysis"""
    
    def __init__(self):
        self.monitored_sites = {}
        self.scan_history = []
        
    def add_website(self, url: str, name: str = None) -> bool:
        """Add a website to monitoring"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed_url = urlparse(url)
            site_name = name or (parsed_url.netloc if parsed_url.netloc else "unknown")
            
            self.monitored_sites[url] = {
                'name': site_name,
                'url': url,
                'added': datetime.now(),
                'last_scan': None,
                'status': 'pending'
            }
            return True
        except Exception as e:
            print(f"Error adding website: {e}")
            return False
    
    def scan_website(self, url: str) -> Dict[str, Any]:
        """Comprehensive website security scan"""
        results = {
            'url': url,
            'timestamp': datetime.now(),
            'availability': {},
            'ssl_security': {},
            'headers': {},
            'content_analysis': {},
            'vulnerabilities': [],
            'performance': {},
            'security_score': 0
        }
        
        try:
            # Availability check
            results['availability'] = self._check_availability(url)
            
            # SSL/TLS security
            results['ssl_security'] = self._check_ssl_security(url)
            
            # Security headers
            results['headers'] = self._check_security_headers(url)
            
            # Content analysis
            results['content_analysis'] = self._analyze_content(url)
            
            # Vulnerability scan
            results['vulnerabilities'] = self._scan_vulnerabilities(url)
            
            # Performance metrics
            results['performance'] = self._check_performance(url)
            
            # Calculate security score
            results['security_score'] = self._calculate_security_score(results)
            
            # Update scan history
            self.scan_history.append(results)
            
            # Update monitored site status
            if url in self.monitored_sites:
                self.monitored_sites[url]['last_scan'] = datetime.now()
                self.monitored_sites[url]['status'] = 'scanned'
                
        except Exception as e:
            results['error'] = str(e)
            results['security_score'] = 0
            
        return results
    
    def _check_availability(self, url: str) -> Dict[str, Any]:
        """Check website availability and response time"""
        try:
            start_time = time.time()
            response = requests.get(url, timeout=10, allow_redirects=True)
            response_time = (time.time() - start_time) * 1000
            
            return {
                'status_code': response.status_code,
                'response_time': round(response_time, 2),
                'available': response.status_code == 200,
                'redirects': len(response.history),
                'final_url': response.url
            }
        except Exception as e:
            return {
                'status_code': None,
                'response_time': None,
                'available': False,
                'error': str(e)
            }
    
    def _check_ssl_security(self, url: str) -> Dict[str, Any]:
        """Check SSL/TLS security configuration"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if parsed_url.scheme != 'https':
                return {
                    'https_enabled': False,
                    'security_level': 'Low',
                    'issues': ['Website not using HTTPS']
                }
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
            # Analyze certificate
            cert_issues = []
            cert_expires = None
            days_until_expiry = None
            subject_dict = {}
            issuer_dict = {}
            
            if cert:
                # Safe certificate date parsing
                try:
                    not_after = cert.get('notAfter')
                    if not_after and isinstance(not_after, str):
                        cert_expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (cert_expires - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            cert_issues.append(f"Certificate expires in {days_until_expiry} days")
                except Exception:
                    cert_issues.append("Could not parse certificate expiration date")
                
                # Safe subject/issuer parsing
                try:
                    subject = cert.get('subject')
                    if subject:
                        subject_dict = {}
                        for item in subject:
                            if isinstance(item, tuple) and len(item) >= 2:
                                subject_dict[item[0]] = item[1]
                    
                    issuer = cert.get('issuer')
                    if issuer:
                        issuer_dict = {}
                        for item in issuer:
                            if isinstance(item, tuple) and len(item) >= 2:
                                issuer_dict[item[0]] = item[1]
                except Exception:
                    pass
            
            return {
                'https_enabled': True,
                'certificate': {
                    'subject': subject_dict,
                    'issuer': issuer_dict,
                    'expires': cert_expires.isoformat() if cert_expires else None,
                    'days_until_expiry': days_until_expiry
                },
                'cipher_suite': cipher[0] if cipher else None,
                'protocol_version': cipher[1] if cipher else None,
                'security_level': 'High' if not cert_issues else 'Medium',
                'issues': cert_issues
            }
            
        except Exception as e:
            return {
                'https_enabled': False,
                'error': str(e),
                'security_level': 'Unknown'
            }
    
    def _check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers"""
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy')
            }
            
            missing_headers = [k for k, v in security_headers.items() if v is None]
            header_score = ((7 - len(missing_headers)) / 7) * 100
            
            return {
                'headers': security_headers,
                'missing_headers': missing_headers,
                'security_score': round(header_score, 1),
                'recommendations': self._get_header_recommendations(missing_headers)
            }
            
        except Exception as e:
            return {'error': str(e), 'security_score': 0}
    
    def _analyze_content(self, url: str) -> Dict[str, Any]:
        """Analyze website content for security issues"""
        try:
            # Extract text content
            downloaded = trafilatura.fetch_url(url)
            text_content = trafilatura.extract(downloaded)
            
            # Get HTML for additional analysis
            response = requests.get(url, timeout=10)
            html_content = response.text
            
            # Security analysis
            security_issues = []
            
            # Check for common vulnerabilities in content
            if re.search(r'<script[^>]*src=["\']https?://[^"\']*["\'][^>]*></script>', html_content, re.IGNORECASE):
                external_scripts = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', html_content, re.IGNORECASE)
                security_issues.append(f"External scripts detected: {len(external_scripts)} sources")
            
            # Check for inline scripts
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)
            if inline_scripts:
                security_issues.append(f"Inline scripts detected: {len(inline_scripts)} instances")
            
            # Check for form submissions
            forms = re.findall(r'<form[^>]*>', html_content, re.IGNORECASE)
            if forms:
                http_forms = [f for f in forms if 'method="post"' in f.lower() and url.startswith('http://')]
                if http_forms:
                    security_issues.append("Forms submitting over HTTP (insecure)")
            
            return {
                'text_length': len(text_content) if text_content else 0,
                'html_length': len(html_content),
                'external_scripts': len(re.findall(r'<script[^>]*src=', html_content, re.IGNORECASE)),
                'inline_scripts': len(inline_scripts),
                'forms_count': len(forms),
                'security_issues': security_issues,
                'content_preview': text_content[:200] if text_content else None
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _scan_vulnerabilities(self, url: str) -> List[Dict[str, Any]]:
        """Scan for common web vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            # Check server disclosure
            server_header = headers.get('Server', '').lower()
            if server_header:
                if any(server in server_header for server in ['apache/', 'nginx/', 'iis/']):
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': f'Server information disclosed: {headers.get("Server")}',
                        'recommendation': 'Configure server to hide version information'
                    })
            
            # Check for X-Powered-By header
            if 'X-Powered-By' in headers:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low', 
                    'description': f'Technology stack disclosed: {headers.get("X-Powered-By")}',
                    'recommendation': 'Remove X-Powered-By header'
                })
            
            # Check for common paths
            common_paths = ['/admin', '/wp-admin', '/.git', '/backup', '/config']
            for path in common_paths:
                try:
                    test_response = requests.get(url.rstrip('/') + path, timeout=5)
                    if test_response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Exposed Path',
                            'severity': 'Medium',
                            'description': f'Accessible path found: {path}',
                            'recommendation': 'Restrict access to sensitive paths'
                        })
                except:
                    pass
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Unknown',
                'description': f'Error during vulnerability scan: {str(e)}'
            })
            
        return vulnerabilities
    
    def _check_performance(self, url: str) -> Dict[str, Any]:
        """Check website performance metrics"""
        try:
            start_time = time.time()
            response = requests.get(url, timeout=30)
            total_time = time.time() - start_time
            
            content_length = len(response.content)
            
            return {
                'load_time': round(total_time * 1000, 2),
                'content_size': content_length,
                'compression': 'gzip' in response.headers.get('Content-Encoding', '').lower(),
                'caching': bool(response.headers.get('Cache-Control')),
                'performance_grade': self._grade_performance(total_time * 1000, content_length)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_security_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall security score"""
        score = 0
        max_score = 100
        
        # Availability (10 points)
        if results['availability'].get('available'):
            score += 10
        
        # SSL Security (25 points)
        ssl_security = results['ssl_security']
        if ssl_security.get('https_enabled'):
            score += 15
            if ssl_security.get('security_level') == 'High':
                score += 10
            elif ssl_security.get('security_level') == 'Medium':
                score += 5
        
        # Security Headers (30 points)
        headers_score = results['headers'].get('security_score', 0)
        score += (headers_score / 100) * 30
        
        # Vulnerabilities (20 points - deducted)
        vuln_deduction = 0
        for vuln in results['vulnerabilities']:
            if vuln['severity'] == 'Critical':
                vuln_deduction += 10
            elif vuln['severity'] == 'High':
                vuln_deduction += 6
            elif vuln['severity'] == 'Medium':
                vuln_deduction += 3
            elif vuln['severity'] == 'Low':
                vuln_deduction += 1
        
        score = max(0, score - vuln_deduction)
        
        # Content Security (15 points)
        content_issues = len(results['content_analysis'].get('security_issues', []))
        content_score = max(0, 15 - (content_issues * 3))
        score += content_score
        
        return min(max_score, max(0, score))
    
    def _get_header_recommendations(self, missing_headers: List[str]) -> List[str]:
        """Get recommendations for missing security headers"""
        recommendations = []
        header_advice = {
            'Content-Security-Policy': 'Implement CSP to prevent XSS attacks',
            'X-Content-Type-Options': 'Add "nosniff" to prevent MIME type sniffing',
            'X-Frame-Options': 'Add "DENY" or "SAMEORIGIN" to prevent clickjacking',
            'X-XSS-Protection': 'Enable XSS protection (though CSP is preferred)',
            'Strict-Transport-Security': 'Implement HSTS to enforce HTTPS',
            'Referrer-Policy': 'Control referrer information sent to other sites',
            'Permissions-Policy': 'Control access to browser features'
        }
        
        for header in missing_headers:
            if header in header_advice:
                recommendations.append(header_advice[header])
                
        return recommendations
    
    def _grade_performance(self, load_time: float, content_size: int) -> str:
        """Grade website performance"""
        if load_time < 1000:
            return 'A'
        elif load_time < 2000:
            return 'B'
        elif load_time < 3000:
            return 'C'
        elif load_time < 5000:
            return 'D'
        else:
            return 'F'
    
    def get_monitored_websites(self) -> Dict[str, Any]:
        """Get all monitored websites"""
        return self.monitored_sites
    
    def get_scan_history(self, url: str = None) -> List[Dict[str, Any]]:
        """Get scan history for a specific site or all sites"""
        if url:
            return [scan for scan in self.scan_history if scan['url'] == url]
        return self.scan_history
    
    def get_security_trends(self, url: str) -> Dict[str, Any]:
        """Get security trends for a website"""
        scans = self.get_scan_history(url)
        if len(scans) < 2:
            return {'error': 'Not enough scan history'}
        
        scores = [scan['security_score'] for scan in scans[-10:]]  # Last 10 scans
        timestamps = [scan['timestamp'] for scan in scans[-10:]]
        
        return {
            'scores': scores,
            'timestamps': timestamps,
            'current_score': scores[-1] if scores else 0,
            'trend': 'improving' if len(scores) >= 2 and scores[-1] > scores[-2] else 'declining' if len(scores) >= 2 and scores[-1] < scores[-2] else 'stable'
        }
    
    def remove_website(self, url: str) -> bool:
        """Remove website from monitoring"""
        if url in self.monitored_sites:
            del self.monitored_sites[url]
            return True
        return False