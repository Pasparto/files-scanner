import virustotal

v = virustotal.VirusTotal("Enter your API key")
report = v.get("path for suspicious files")

print "Report"
print "- Resource's UID:" + report.id
print "- Scan's UID:" + report.scan_id
print "- Permalink:" + report.permalink
print "- Resource's SHA1:" + report.sha1
print "- Resource's SHA256:" + report.sha256
print "- Resource's MD5:" + report.md5
print "- Resource's status:" + report.status
print "- Antivirus' total:" + str(report.total)
print "- Antivirus's positives:" + str(report.positives)
for antivirus, malware in report:
    if malware is not None:
        print
        print "Antivirus:" + antivirus[0]
        print "Antivirus' version:" + antivirus[1]
        print "Antivirus' update:" + antivirus[2]
        print "Malware:" + malware