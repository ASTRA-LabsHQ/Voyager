package extract

import "testing"

func TestExtract(t *testing.T) {
	strs := []string{
		// genuine candidates, mixed in with realistic noise
		"connecting to http://evil-c2-panel.xyz/beacon/checkin",
		"C2 fallback IP is 203.0.113.77 with backup 10.0.0.5",
		"loopback test against 127.0.0.1 should be ignored as internal",
		"update-server.evil-actor.top",
		// noise that should NOT show up as domains
		"kernel32.dll",
		"System.Windows.Forms",
		"schemas.microsoft.com/2003/10/Serialization/", // real TLD but legitimate MS namespace — still extracted, filtering false positives entirely is out of scope
		"mscorlib.resources",
		"just.a.version.string.1.2.3.4.5",
	}

	iocs := Extract(strs)

	byValue := map[string]IOC{}
	for _, i := range iocs {
		byValue[i.Value] = i
	}

	if ioc, ok := byValue["http://evil-c2-panel.xyz/beacon/checkin"]; !ok || ioc.Type != TypeURL {
		t.Errorf("expected URL candidate for evil-c2-panel.xyz, got %+v (ok=%v)", ioc, ok)
	}

	if ioc, ok := byValue["203.0.113.77"]; !ok || ioc.Class != "public" {
		t.Errorf("expected public IPv4 203.0.113.77, got %+v (ok=%v)", ioc, ok)
	}
	if ioc, ok := byValue["10.0.0.5"]; !ok || ioc.Class != "private" {
		t.Errorf("expected private IPv4 10.0.0.5, got %+v (ok=%v)", ioc, ok)
	}
	if ioc, ok := byValue["127.0.0.1"]; !ok || ioc.Class != "loopback" {
		t.Errorf("expected loopback IPv4 127.0.0.1, got %+v (ok=%v)", ioc, ok)
	}

	if ioc, ok := byValue["update-server.evil-actor.top"]; !ok || ioc.Type != TypeDomain {
		t.Errorf("expected domain candidate update-server.evil-actor.top, got %+v (ok=%v)", ioc, ok)
	}

	for _, noise := range []string{"kernel32.dll", "mscorlib.resources"} {
		if _, ok := byValue[noise]; ok {
			t.Errorf("expected %q to be filtered out as a non-TLD suffix, but it was extracted", noise)
		}
	}
}

func TestExtract_Dedupes(t *testing.T) {
	strs := []string{
		"http://evil.example.com/a",
		"http://evil.example.com/a",
		"repeated IP 8.8.8.8 and 8.8.8.8 again",
	}
	iocs := Extract(strs)

	counts := map[string]int{}
	for _, i := range iocs {
		counts[i.Value]++
	}
	if counts["http://evil.example.com/a"] != 1 {
		t.Errorf("expected URL to be deduped to 1, got %d", counts["http://evil.example.com/a"])
	}
	if counts["8.8.8.8"] != 1 {
		t.Errorf("expected IP to be deduped to 1, got %d", counts["8.8.8.8"])
	}
}

func TestIOC_Defang(t *testing.T) {
	cases := []struct {
		ioc  IOC
		want string
	}{
		{IOC{Type: TypeIPv4, Value: "185.220.101.45"}, "185[.]220[.]101[.]45"},
		{IOC{Type: TypeDomain, Value: "evil-actor.top"}, "evil-actor[.]top"},
		{
			IOC{Type: TypeURL, Value: "https://updates.acelauncher.com/dock/"},
			"https[:]//updates.acelauncher[.]com/dock/",
		},
	}
	for _, c := range cases {
		if got := c.ioc.Defang(); got != c.want {
			t.Errorf("Defang(%+v) = %q, want %q", c.ioc, got, c.want)
		}
	}
}
