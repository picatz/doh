package serve

import (
	"testing"
	"time"

	"github.com/picatz/doh/internal/blocklist"
)

func TestBlocklistConfig_RefreshSchedule(t *testing.T) {
	threat := blocklist.Source{Name: blocklist.ThreatIntelPreset, Location: blocklist.Presets[blocklist.ThreatIntelPreset]}
	ads := blocklist.Source{Name: blocklist.DefaultPreset, Location: blocklist.Presets[blocklist.DefaultPreset]}

	s := BlocklistConfig{}.RefreshSchedule()
	if s.Interval(threat) != DefaultSecurityRefresh || s.Interval(ads) != DefaultBlocklistRefresh || s.Jitter == 0 {
		t.Errorf("default schedule = %+v", s)
	}

	s = BlocklistConfig{Refresh: Duration(12 * time.Hour), RefreshCategories: map[string]Duration{"security": Duration(30 * time.Minute)}}.RefreshSchedule()
	if s.Interval(threat) != 30*time.Minute || s.Interval(ads) != 12*time.Hour {
		t.Errorf("configured schedule = %+v", s)
	}
}
