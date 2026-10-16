/**
 * Preloaded Sample Datasets for Instant 1-Click Evaluation
 */

export const ENTERPRISE_CSV = `library,version,cve_id,severity,cvss,fix_version,fix_available,exposure,description
log4j-core,2.14.1,CVE-2021-44228,CRITICAL,10.0,2.17.1,True,DIRECT / PRODUCTION,Remote Code Execution via JNDI LDAP lookup in Log4j 2.x
spring-beans,5.3.17,CVE-2022-22965,CRITICAL,9.8,5.3.18,True,DIRECT / PRODUCTION,Spring4Shell Remote Code Execution via Data Binding ClassLoader
lodash,4.17.15,CVE-2020-8203,HIGH,7.4,4.17.21,True,DIRECT / PRODUCTION,Prototype Pollution via zipObjectDeep allowing property injection
axios,0.21.0,CVE-2020-28168,MEDIUM,5.9,0.21.1,True,DIRECT / PRODUCTION,Server-Side Request Forgery (SSRF) bypass through relative URL handling
pillow,8.1.0,CVE-2021-25290,HIGH,7.5,8.1.2,True,DIRECT / PRODUCTION,Buffer Overflow in TIFF processing leading to potential code execution
pyyaml,5.3.1,CVE-2020-14343,CRITICAL,9.8,5.4.0,True,TRANSITIVE / PRODUCTION,Arbitrary Code Execution through FullLoader deserialization
openssl,1.1.1k,CVE-2022-0778,HIGH,7.5,1.1.1n,True,DIRECT / PRODUCTION,Infinite loop in BN_mod_sqrt() leading to Denial of Service (DoS)
express,4.16.0,CVE-2022-24999,MEDIUM,5.3,4.17.3,True,DIRECT / PRODUCTION,QS module prototype pollution within body parsing
mocha,7.0.0,CVE-2020-36632,MEDIUM,4.3,8.0.0,True,DIRECT / DEV,Prototype pollution in test runner reporter helper
jsonwebtoken,8.5.1,CVE-2022-23529,HIGH,7.6,9.0.0,True,DIRECT / PRODUCTION,Insecure key retrieval allowing arbitrary file write via crafted secret
minimist,1.2.0,CVE-2020-7598,HIGH,7.5,1.2.6,True,TRANSITIVE / DEV,Prototype Pollution through parse method in CLI argument parser
jackson-databind,2.9.8,CVE-2019-12384,HIGH,8.8,2.9.10.8,True,TRANSITIVE / PRODUCTION,Polymorphic typing flaw allowing Server-Side Request Forgery / RCE
urllib3,1.26.4,CVE-2021-33503,MEDIUM,5.3,1.26.5,True,DIRECT / PRODUCTION,ReDoS vulnerability in URL parser regex matching
redis-py,3.5.3,CVE-2023-28859,MEDIUM,5.5,,False,DIRECT / PRODUCTION,Race condition leading to unauthorized connection reuse (No patch yet)
eslint,7.32.0,CVE-2021-23450,LOW,3.3,8.0.0,True,TRANSITIVE / DEV,Regex denial of service in linter rule utility`;

export const OWASP_JSON = {
  reportSchema: "1.1",
  dependencies: [
    {
      isVirtual: false,
      fileName: "log4j-core-2.14.1.jar",
      filePath: "/app/lib/log4j-core-2.14.1.jar",
      packages: [{ id: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }],
      vulnerabilities: [
        {
          name: "CVE-2021-44228",
          severity: "CRITICAL",
          cvssv3: { baseScore: 10.0, attackVector: "NETWORK" },
          description: "Apache Log4j2 JNDI features used in configuration do not protect against attacker controlled LDAP endpoints (Log4Shell).",
          notes: "Fixed in version 2.17.1"
        }
      ]
    },
    {
      isVirtual: false,
      fileName: "spring-webmvc-5.3.16.jar",
      filePath: "/app/lib/spring-webmvc-5.3.16.jar",
      packages: [{ id: "pkg:maven/org.springframework/spring-webmvc@5.3.16" }],
      vulnerabilities: [
        {
          name: "CVE-2022-22965",
          severity: "CRITICAL",
          cvssv3: { baseScore: 9.8, attackVector: "NETWORK" },
          description: "Spring MVC remote code execution via data binding ClassLoader access (Spring4Shell).",
          notes: "Patched in Spring Framework 5.3.18"
        }
      ]
    },
    {
      isVirtual: false,
      fileName: "h2-1.4.199.jar",
      filePath: "/app/lib/h2-1.4.199.jar",
      packages: [{ id: "pkg:maven/com.h2database/h2@1.4.199" }],
      vulnerabilities: [
        {
          name: "CVE-2021-23463",
          severity: "HIGH",
          cvssv3: { baseScore: 7.5, attackVector: "NETWORK" },
          description: "H2 database engine console allows remote code execution when org.h2.tools.Server is launched without credentials.",
          notes: "Compensating controls: disable web console"
        }
      ]
    },
    {
      isVirtual: true,
      fileName: "commons-compress-1.19.jar",
      filePath: "/app/lib/commons-compress-1.19.jar",
      packages: [{ id: "pkg:maven/org.apache.commons/commons-compress@1.19" }],
      vulnerabilities: [
        {
          name: "CVE-2021-35515",
          severity: "MEDIUM",
          cvssv3: { baseScore: 5.5, attackVector: "LOCAL" },
          description: "Denial of service through excessive memory allocation when reading crafted 7z archive.",
          notes: "Patched in 1.21"
        }
      ]
    }
  ]
};

export const SNYK_JSON = {
  vulnerabilities: [
    {
      id: "SNYK-JS-LODASH-567746",
      title: "Prototype Pollution in lodash",
      packageName: "lodash",
      version: "4.17.15",
      severity: "high",
      cvssScore: 7.4,
      fixedIn: ["4.17.21"],
      identifiers: { CVE: ["CVE-2020-8203"] },
      from: ["app@1.0.0", "lodash@4.17.15"],
      description: "Prototype pollution vulnerability affecting lodash functions zipObjectDeep."
    },
    {
      id: "SNYK-JS-AXIOS-1038255",
      title: "Server-Side Request Forgery (SSRF)",
      packageName: "axios",
      version: "0.21.0",
      severity: "medium",
      cvssScore: 5.9,
      fixedIn: ["0.21.1"],
      identifiers: { CVE: ["CVE-2020-28168"] },
      from: ["app@1.0.0", "axios@0.21.0"],
      description: "Axios follows insecure redirects allowing attackers to perform SSRF attacks."
    },
    {
      id: "SNYK-JS-JSONWEBTOKEN-3180014",
      title: "Arbitrary File Write / Insecure Verification",
      packageName: "jsonwebtoken",
      version: "8.5.1",
      severity: "high",
      cvssScore: 7.6,
      fixedIn: ["9.0.0"],
      identifiers: { CVE: ["CVE-2022-23529"] },
      from: ["app@1.0.0", "jsonwebtoken@8.5.1"],
      description: "jsonwebtoken verifies secrets unsafely allowing prototype modification and potential arbitrary code execution."
    }
  ]
};

export const BLANK_CSV_TEMPLATE = `library,version,cve_id,severity,cvss,fix_version,fix_available,exposure,description
example-package,1.0.0,CVE-2024-0001,CRITICAL,9.8,1.2.0,True,DIRECT / PRODUCTION,Sample remote execution vulnerability
auth-helper,2.1.0,CVE-2024-0002,HIGH,7.5,2.1.4,True,DIRECT / PRODUCTION,Authentication bypass in token parser
logger-tool,0.9.1,CVE-2024-0003,MEDIUM,5.4,1.0.0,True,TRANSITIVE / PRODUCTION,Information disclosure in verbose log mode
test-mock,3.0.0,CVE-2024-0004,LOW,3.1,,False,DIRECT / DEV,Resource leak in mock teardown (non-production)`;
