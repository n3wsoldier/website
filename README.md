# 14. Pentesting
*A penetration test, colloquially known as a pen test, pentest or ethical hacking, is an authorized simulated cyberattack on a computer system, performed to evaluate the security of the system.*

### Security Assessments:

- **Security Assessment** - Test performed in order to assess the level of security on a network or system.

- **Security Audit** - Policy and procedure focused; tests whether organization is following specific standards and policies; look on compliances only.

- **Vulnerability Assessment** - Scans and tests for vulnerabilities but does not intentionally exploit them.

- **Penetration Test** - Looks for vulnerabilities and actively seeks to exploit them.

### InfoSec Teams 🗡🛡
- 🔵 **Blue Team** *(defenders)*
  - Implement security policy
  - Implement technical controls
  - Detect and defend against Red Team
- 🔴 **Red Team** *(attackers)*
  - Perform penetration testing
  - Act as any true outside threat in an attempt to gain unauthorized access to client's system(s)

## <u>Types of Pen Tests</u>
**External assessment** - Analyzes publicly available information; conducts network scanning, enumeration and testing from the network perimeter.

**Internal Assessment** - Performed from within the organization, from various network access points.

### Pentesting boxes:
> - **Black Box** - Done **without any knowledge** of the system or network.
> - **White Box** - When the attacker **have complete knowledge** of the system provided by the owner/target.
> - **Gray Box** - When the attacker has **some knowledge** of the system and/or network

- **Automated Testing Tools**
  - **Codenomicon** - utilizes fuzz testing that learns the tested system automatically; allows for pen testers to enter new domains such as VoIP assessment, etc.
  - **Core Impact Pro** - best known, all-inclusive automated testing framework; tests everything from web applications and individual systems to network devices and wireless
  - **Metasploit** - framework for developing and executing code against a remote target machine
  - **CANVAS** - hundreds of exploits, automated exploitation system and extensive exploit development framework

### <u>Pen test Phases</u>
1. **Pre-Attack Phase** - Reconnaissance and data-gathering.
2. **Attack Phase** - Attempts to penetrate the network and execute attacks.
3. **Post-Attack Phase** - Cleanup to return a system to the pre-attack condition and deliver reports.

> ⚠️ For the exam, EC-Council brings his own methodology and that's all you need for the exam; you can check another pentesting methodologies [here](https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies) if you are interested; In case you are studying to become a professional pentester besides certification content, I recommend the [OSSTMM](https://www.isecom.org/research.html) (Open Source Security Testing Methodology Manual).

## <u>Security Assessment Deliverables</u>

- Usually begins with a brief to management
  - Provides information about your team and the overview of the original agreement
  - Explain what tests were done and the results of them
- **Comprehensive Report Parts**
  - Executive summary of the organization's security posture
  - Names of all participants and dates of tests
  - List of all findings, presented in order of risk
  - Analysis of each finding and recommended mitigation steps
  - Log files and other evidence (screenshots, etc.)
- Example reports and methodology can be found in the **Open Source Testing Methodology Manual** (OSSTMM)

## <u>Terminology</u>

- **Types of Insiders**
  - **Pure Insider** - employee with all rights and access associated with being an employee
    - **Elevated Pure Insider** - employee who has admin privileges
  - **Insider Associate** - someone with limited authorized access such as a contractor, guard or cleaning service person
  - **Insider Affiliate** - spouse, friend or client of an employee who uses the employee's credentials to gain access
  - **Outside Affiliate** - someone outside the organization who uses an open access channel to gain access to an organization's resources

## <u>Vulnerabilities</u>

- **CVSS - Common Vulnerability Scoring System** - places numerical score based on severity;

  - **Qualitative severity rating scale:**

    Rating | CVSS Score
    --|--
    None |	0.0
    Low |	0.1 - 3.9
    Medium |	4.0 - 6.9
    High |	7.0 - 8.9
    Critical |	9.0 - 10.0

- **CVE – Common Vulnerabilities and Exposures** 
  - Is a list of publicly disclosed vulnerabilities and exposures that is maintained by MITRE.
- **NVD - National Vulnerability Database** 
  -  is a database, maintained by NIST, that is fully synchronized with the MITRE CVE list; US Gov. vulnerabilities repository.
