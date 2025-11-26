package report

// OWASP Top 10 2021 mappings
// https://owasp.org/Top10/
var OWASPMappings = map[string]string{
	// A01:2021 - Broken Access Control
	"exposed_admin":     "A01:2021",
	"directory_listing": "A01:2021",
	"path_traversal":    "A01:2021",
	"unprotected_api":   "A01:2021",

	// A02:2021 - Cryptographic Failures
	"exposed_credentials": "A02:2021",
	"exposed_keys":        "A02:2021",
	"exposed_config":      "A02:2021",
	"unencrypted_service": "A02:2021",

	// A03:2021 - Injection
	"sql_injection":     "A03:2021",
	"command_injection": "A03:2021",

	// A04:2021 - Insecure Design
	"debug_enabled":   "A04:2021",
	"verbose_errors":  "A04:2021",
	"exposed_swagger": "A04:2021",

	// A05:2021 - Security Misconfiguration
	"default_credentials":  "A05:2021",
	"unnecessary_features": "A05:2021",
	"exposed_backup":       "A05:2021",
	"exposed_git":          "A05:2021",
	"server_status":        "A05:2021",
	"phpinfo":              "A05:2021",
	"docker_exposed":       "A05:2021",
	"redis_noauth":         "A05:2021",
	"mongodb_noauth":       "A05:2021",

	// A06:2021 - Vulnerable and Outdated Components
	"outdated_software": "A06:2021",

	// A07:2021 - Identification and Authentication Failures
	"weak_auth":       "A07:2021",
	"anonymous_ftp":   "A07:2021",
	"weak_password":   "A07:2021",
	"no_auth":         "A07:2021",

	// A08:2021 - Software and Data Integrity Failures
	"ci_cd_exposed": "A08:2021",

	// A09:2021 - Security Logging and Monitoring Failures
	"exposed_logs": "A09:2021",

	// A10:2021 - Server-Side Request Forgery
	"ssrf_potential": "A10:2021",
}

// CWE mappings for common vulnerabilities
// https://cwe.mitre.org/
var CWEMappings = map[string]string{
	// Exposure issues
	"exposed_credentials": "CWE-312",  // Cleartext Storage of Sensitive Information
	"exposed_keys":        "CWE-321",  // Use of Hard-coded Cryptographic Key
	"exposed_config":      "CWE-200",  // Exposure of Sensitive Information
	"exposed_git":         "CWE-538",  // Insertion of Sensitive Information into Externally-Accessible File
	"exposed_backup":      "CWE-530",  // Exposure of Backup File to an Unauthorized Control Sphere
	"exposed_logs":        "CWE-532",  // Insertion of Sensitive Information into Log File
	"exposed_swagger":     "CWE-200",  // Exposure of Sensitive Information
	"phpinfo":             "CWE-200",  // Exposure of Sensitive Information
	"server_status":       "CWE-200",  // Exposure of Sensitive Information
	"directory_listing":   "CWE-548",  // Exposure of Information Through Directory Listing

	// Authentication issues
	"default_credentials": "CWE-798",  // Use of Hard-coded Credentials
	"weak_password":       "CWE-521",  // Weak Password Requirements
	"weak_auth":           "CWE-287",  // Improper Authentication
	"no_auth":             "CWE-306",  // Missing Authentication for Critical Function
	"anonymous_ftp":       "CWE-284",  // Improper Access Control

	// Access control
	"exposed_admin":     "CWE-284",  // Improper Access Control
	"unprotected_api":   "CWE-284",  // Improper Access Control
	"path_traversal":    "CWE-22",   // Improper Limitation of a Pathname

	// Service exposure
	"docker_exposed":  "CWE-284",  // Improper Access Control
	"redis_noauth":    "CWE-306",  // Missing Authentication for Critical Function
	"mongodb_noauth":  "CWE-306",  // Missing Authentication for Critical Function
	"debug_enabled":   "CWE-489",  // Active Debug Code

	// Injection
	"sql_injection":     "CWE-89",   // SQL Injection
	"command_injection": "CWE-78",   // OS Command Injection
}

// NIST 800-53 Rev 5 Control mappings
// https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
var NISTMappings = map[string]string{
	// Access Control (AC)
	"exposed_admin":      "AC-3",   // Access Enforcement
	"unprotected_api":    "AC-3",   // Access Enforcement
	"directory_listing":  "AC-3",   // Access Enforcement
	"path_traversal":     "AC-6",   // Least Privilege
	"docker_exposed":     "AC-3",   // Access Enforcement
	"redis_noauth":       "AC-3",   // Access Enforcement
	"mongodb_noauth":     "AC-3",   // Access Enforcement

	// Audit and Accountability (AU)
	"exposed_logs":       "AU-9",   // Protection of Audit Information

	// Configuration Management (CM)
	"exposed_config":     "CM-6",   // Configuration Settings
	"debug_enabled":      "CM-7",   // Least Functionality
	"server_status":      "CM-7",   // Least Functionality
	"phpinfo":            "CM-7",   // Least Functionality
	"exposed_swagger":    "CM-7",   // Least Functionality
	"exposed_backup":     "CM-7",   // Least Functionality

	// Identification and Authentication (IA)
	"default_credentials": "IA-5",   // Authenticator Management
	"weak_password":       "IA-5",   // Authenticator Management
	"weak_auth":           "IA-2",   // Identification and Authentication
	"no_auth":             "IA-2",   // Identification and Authentication
	"anonymous_ftp":       "IA-2",   // Identification and Authentication

	// System and Communications Protection (SC)
	"exposed_credentials": "SC-28",  // Protection of Information at Rest
	"exposed_keys":        "SC-12",  // Cryptographic Key Establishment and Management
	"unencrypted_service": "SC-8",   // Transmission Confidentiality and Integrity

	// System and Information Integrity (SI)
	"exposed_git":         "SI-7",   // Software, Firmware, and Information Integrity
	"ci_cd_exposed":       "SI-7",   // Software, Firmware, and Information Integrity
}

// VulnerabilityType identifies the type of vulnerability based on findings
type VulnerabilityType string

const (
	VulnExposedCredentials VulnerabilityType = "exposed_credentials"
	VulnExposedKeys        VulnerabilityType = "exposed_keys"
	VulnExposedConfig      VulnerabilityType = "exposed_config"
	VulnExposedGit         VulnerabilityType = "exposed_git"
	VulnExposedBackup      VulnerabilityType = "exposed_backup"
	VulnExposedLogs        VulnerabilityType = "exposed_logs"
	VulnExposedSwagger     VulnerabilityType = "exposed_swagger"
	VulnExposedAdmin       VulnerabilityType = "exposed_admin"
	VulnPhpinfo            VulnerabilityType = "phpinfo"
	VulnServerStatus       VulnerabilityType = "server_status"
	VulnDirectoryListing   VulnerabilityType = "directory_listing"
	VulnDefaultCredentials VulnerabilityType = "default_credentials"
	VulnWeakPassword       VulnerabilityType = "weak_password"
	VulnWeakAuth           VulnerabilityType = "weak_auth"
	VulnNoAuth             VulnerabilityType = "no_auth"
	VulnAnonymousFTP       VulnerabilityType = "anonymous_ftp"
	VulnDockerExposed      VulnerabilityType = "docker_exposed"
	VulnRedisNoAuth        VulnerabilityType = "redis_noauth"
	VulnMongoDBNoAuth      VulnerabilityType = "mongodb_noauth"
	VulnDebugEnabled       VulnerabilityType = "debug_enabled"
	VulnUnprotectedAPI     VulnerabilityType = "unprotected_api"
	VulnCICDExposed        VulnerabilityType = "ci_cd_exposed"
)

// GetCompliance returns OWASP, CWE, and NIST mappings for a vulnerability type
func GetCompliance(vulnType string) (owasp, cwe, nist string) {
	owasp = OWASPMappings[vulnType]
	cwe = CWEMappings[vulnType]
	nist = NISTMappings[vulnType]

	// Provide defaults if not found
	if owasp == "" {
		owasp = "A05:2021" // Default to Security Misconfiguration
	}
	if cwe == "" {
		cwe = "CWE-200" // Default to Information Exposure
	}
	if nist == "" {
		nist = "CM-6" // Default to Configuration Settings
	}

	return
}

// ClassifyPathVulnerability determines the vulnerability type from a path
func ClassifyPathVulnerability(path string) VulnerabilityType {
	switch {
	case contains(path, ".env", "credentials", "secrets", ".aws"):
		return VulnExposedCredentials
	case contains(path, "id_rsa", ".pem", ".key", ".ssh"):
		return VulnExposedKeys
	case contains(path, "config", "settings", "application.yml"):
		return VulnExposedConfig
	case contains(path, ".git"):
		return VulnExposedGit
	case contains(path, "backup", ".bak", ".sql", ".zip", ".tar"):
		return VulnExposedBackup
	case contains(path, ".log", "error_log", "access_log"):
		return VulnExposedLogs
	case contains(path, "swagger", "openapi", "api-docs"):
		return VulnExposedSwagger
	case contains(path, "admin", "administrator", "phpmyadmin"):
		return VulnExposedAdmin
	case contains(path, "phpinfo"):
		return VulnPhpinfo
	case contains(path, "server-status", "server-info"):
		return VulnServerStatus
	case contains(path, "debug", "trace", "profiler"):
		return VulnDebugEnabled
	case contains(path, "jenkins", "gitlab-ci", "travis", "circleci"):
		return VulnCICDExposed
	default:
		return VulnExposedConfig
	}
}

// ClassifyServiceVulnerability determines the vulnerability type from a service
func ClassifyServiceVulnerability(service string, hasAuth bool) VulnerabilityType {
	switch service {
	case "Docker", "Docker-TLS", "Docker-Swarm":
		return VulnDockerExposed
	case "Redis":
		if !hasAuth {
			return VulnRedisNoAuth
		}
		return VulnWeakAuth
	case "MongoDB":
		if !hasAuth {
			return VulnMongoDBNoAuth
		}
		return VulnWeakAuth
	case "FTP":
		if !hasAuth {
			return VulnAnonymousFTP
		}
		return VulnWeakAuth
	default:
		if !hasAuth {
			return VulnNoAuth
		}
		return VulnWeakAuth
	}
}

// helper function
func contains(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
