## ManageEngine SQLI to RCE
In this module we have demonstrated how to discover an unauthenticated SQL injection vulnerability using source code audit in a Java-based web application.
We then showed how to use time-based blind SQL injection payloads along with stack queries in order to exfiltrate database information.
Finally, we developed an exploit that utilized Postgres User Defined Functions and Large Objects to gain a fully functional reverse shell.
## Vulnerability Discovery
By browsing through the ManageEngine’s Application Manager web interface, we can see that most URLs contain the `.do` extension. `.do` extension is typically used in a URL mapping scheme for **compiled Java code**.
Java web applications use a deployment descriptor file named **`web.xml`** to determine how URLs map to servlets, which URLs require authentication, and other information.
### Source COde Analysis
- Search for SQL queries in the source decompiled code in notepad++ using regx: `^.*?query.*?select.*?` (this expression basically says: Look for any line that begins with any number of alphanumeric characters which is followed by the string `query` which is followed by a number of any characters which is followed by the string `select` which is followed by a number of any characters.)
