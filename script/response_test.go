package script

import (
	"testing"

	"github.com/meklis/dhcp-radius-server/radius/events"
	lua "github.com/yuin/gopher-lua"
)

func TestTableToAuthResponse(t *testing.T) {
	ls := lua.NewState()
	defer ls.Close()

	t.Run("success", func(t *testing.T) {
		tbl := ls.NewTable()
		tbl.RawSetString("ip_address", lua.LString("1.2.3.4"))
		resp, err := tableToAuthResponse(tbl)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.IpAddress != "1.2.3.4" {
			t.Errorf("expected ip_address=1.2.3.4, got %+v", resp)
		}
	})

	t.Run("error is KindInvalid", func(t *testing.T) {
		tbl := ls.NewTable()
		tbl.RawSetString("error", lua.LString("circuit_id parse failed"))
		_, err := tableToAuthResponse(tbl)
		if err == nil {
			t.Fatal("expected error")
		}
		if kind := events.ClassifyAuthError(err); kind != events.KindInvalid {
			t.Errorf("expected KindInvalid, got %v", kind)
		}
	})

	t.Run("reject is KindReject", func(t *testing.T) {
		tbl := ls.NewTable()
		tbl.RawSetString("reject", lua.LString("device blacklisted"))
		_, err := tableToAuthResponse(tbl)
		if err == nil {
			t.Fatal("expected error")
		}
		if kind := events.ClassifyAuthError(err); kind != events.KindReject {
			t.Errorf("expected KindReject, got %v", kind)
		}
		if err.Error() != "device blacklisted" {
			t.Errorf("expected error message %q, got %q", "device blacklisted", err.Error())
		}
	})

	t.Run("empty response is KindInvalid", func(t *testing.T) {
		tbl := ls.NewTable()
		_, err := tableToAuthResponse(tbl)
		if err == nil {
			t.Fatal("expected error")
		}
		if kind := events.ClassifyAuthError(err); kind != events.KindInvalid {
			t.Errorf("expected KindInvalid, got %v", kind)
		}
	})

	t.Run("reject takes priority over error", func(t *testing.T) {
		tbl := ls.NewTable()
		tbl.RawSetString("error", lua.LString("parse failed"))
		tbl.RawSetString("reject", lua.LString("blacklisted"))
		_, err := tableToAuthResponse(tbl)
		if kind := events.ClassifyAuthError(err); kind != events.KindReject {
			t.Errorf("expected KindReject to win, got %v", kind)
		}
	})
}
