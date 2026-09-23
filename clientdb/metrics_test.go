package clientdb

import (
	"testing"

	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/prometheus/client_golang/prometheus"
)

// bindsCountMetric читает текущее значение rad_clientdb_binds_count{source=...}
// из глобального реестра prometheus (метрики регистрируются через promauto)
func bindsCountMetric(t *testing.T, source string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "rad_clientdb_binds_count" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "source" && l.GetValue() == source {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("metric rad_clientdb_binds_count{source=%q} not found", source)
	return 0
}

func TestLiveUpdateRefreshesBindsCountMetric(t *testing.T) {
	prev := prom.Enabled
	prom.Enabled = true
	defer func() { prom.Enabled = prev }()

	srv := testServer(t, devicesSample, clientsSample, smartSample)
	defer srv.Close()

	s, err := New(testConfig(srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if got := bindsCountMetric(t, "clients"); got != 4 {
		t.Fatalf("after reload: clients=%v, want 4", got)
	}
	if got := bindsCountMetric(t, "smart"); got != 2 {
		t.Fatalf("after reload: smart=%v, want 2", got)
	}

	// add новой записи - счётчик растёт
	if err := s.ApplyBindEvent(BindEvent{DBType: "smart", Action: "add",
		Object: BindEventObject{ID: "99", IP: "123456789", Mac: "AA11BB22CC33"}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := bindsCountMetric(t, "smart"); got != 3 {
		t.Errorf("after add: smart=%v, want 3", got)
	}

	// update существующей записи - счётчик не меняется
	if err := s.ApplyBindEvent(BindEvent{DBType: "clients", Action: "update",
		Object: BindEventObject{ID: "1", IP: "33686018", Mac: "744D280EE846", DeviceMac: "085A119465E0", Port: "42"}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := bindsCountMetric(t, "clients"); got != 4 {
		t.Errorf("after update: clients=%v, want 4", got)
	}

	// delete - счётчик уменьшается; повторный delete того же id ничего не меняет
	for i := 0; i < 2; i++ {
		if err := s.ApplyBindEvent(BindEvent{DBType: "clients", Action: "delete",
			Object: BindEventObject{ID: "2"}}); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if got := bindsCountMetric(t, "clients"); got != 3 {
			t.Errorf("after delete #%v: clients=%v, want 3", i+1, got)
		}
	}

	// другой источник не затронут
	if got := bindsCountMetric(t, "smart"); got != 3 {
		t.Errorf("smart changed by clients events: %v, want 3", got)
	}
}
