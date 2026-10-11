package firewall

import "testing"

func TestCountUFWRules(t *testing.T) {
	out := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere
[ 3] 8080/tcp                   ALLOW IN    100.107.0.0/16             # admin
`
	if got := countUFWRules(out); got != 3 {
		t.Fatalf("countUFWRules = %d, want 3", got)
	}
	if got := countUFWRules("Status: inactive\n"); got != 0 {
		t.Fatalf("inactive ufw = %d rules, want 0", got)
	}
}
