The Findings section of our report is the "meat." At a minimum, the following information should be included for each finding:

    Description of the finding and what platform(s) the vulnerability affects
    Impact if the finding is left unresolved
    Affected systems, networks, environments, or applications
    Recommendation for how to address the problem
    Reference links with additional information about the finding and resolving it
    Steps to reproduce the issue and the evidence that you collected
#### Show Finding Reproduction Steps Adequately

Some guidelines

	Break each step into its own figure
	If setup is required (e.g., Metasploit modules), capture the full configuration
	Write a narrative between figures describing what is happening
	Offer alternatives if possilbe (such as different tools)

Examples
![[evidence_example.webp]]

#### Effective Remediation Recommendations

Example 
- `Bad`: Reconfigure your registry settings to harden against X.
- `Good`: To fully remediate this finding, the following registry hives should be updated with the specified values. Note that changes to critical components like the registry should be approached with caution and tested in a small group prior to making large-scale changes.
    - `[list the full path to the affected registry hives]`
        - Change value X to value Y