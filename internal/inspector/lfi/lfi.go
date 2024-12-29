package lfi

import "regexp"

var (
	sensitiveFilePaths = []string{
		"/.aws/credentials",
		"/.git",
		"/.svn",
		"/.env",
		".ssh/",
		".bash_history",
		"etc/passwd",
		"etc/shadow",
		"etc/hosts",
		"etc/hostname",
		"etc/nginx/",
		"etc/httpd/",
		"etc/apache/",
		"etc/apache2/",
		"etc/cron.d",
		"etc/cron.daily",
		"etc/cron.hourly",
		"etc/cron.monthly",
		"etc/cron.weekly",
		"etc/crontab",
		"etc/fstab",
		"/proc/self",
		"/proc/cmdline",
		"/proc/environ",
		"/root/",
		"var/log/",
		"var/www/",
		"var/run/secrets/",
	}
)

func IsAttemptDirectoryTraversal(path string) bool {
	regexp := regexp.MustCompile(`\.\./`)
	return regexp.MatchString(path)
}

func IsSensitiveFilePath(path string) bool {
	for _, p := range sensitiveFilePaths {
		regexp := regexp.MustCompile(p)
		if regexp.MatchString(path) {
			return true
		}
	}

	return false
}
