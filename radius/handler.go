package radius

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/meklis/dhcp-radius-server/macaddr"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius/events"
	"github.com/meklis/dhcp-radius-server/radius/redback"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
)

func (s *Server) serve(w radius.ResponseWriter, r *radius.Request) {
	nasIP := rfc2865.NASIPAddress_Get(r.Packet).String()
	nasName := rfc2865.NASIdentifier_GetString(r.Packet)
	// NAS vendors format User-Name differently, normalize it once here
	deviceMac := macaddr.Normalize(rfc2865.UserName_GetString(r.Packet))
	serverName := rfc2865.CalledStationID_GetString(r.Packet)
	serverID := rfc2865.CallingStationID_GetString(r.Packet)

	switch r.Code {
	case radius.CodeAccessRequest:
	case radius.CodeAccountingRequest:
		acct := events.AcctRequest{
			NasIp:           nasIP,
			NasName:         nasName,
			DeviceMac:       deviceMac,
			DhcpServerName:  serverName,
			DhcpServerId:    serverID,
			FramedIpAddress: rfc2865.FramedIPAddress_Get(r.Packet).String(),
			AuthType:        rfc2866.AcctAuthentic_Strings[rfc2866.AcctAuthentic_Get(r.Packet)],
			Class:           rfc2865.Class_GetString(r.Packet),
			StatusType:      rfc2866.AcctStatusType_Strings[rfc2866.AcctStatusType_Get(r.Packet)],
			SessionTime:     int64(rfc2866.AcctSessionTime_Get(r.Packet)),
			TerminateCause:  rfc2866.AcctTerminateCause_Strings[rfc2866.AcctTerminateCause_Get(r.Packet)],
			InputOctets:     int64(rfc2866.AcctInputOctets_Get(r.Packet)),
			OutputOctets:    int64(rfc2866.AcctOutputOctets_Get(r.Packet)),
			PoolName:        rfc2869.FramedPool_GetString(r.Packet),
		}
		data, _ := json.Marshal(&acct)
		s.lg.DebugF("%v %x: %s", r.Code, r.Authenticator, data)
		prom.IncAcctRequest(nasIP, serverName)
		s.processor.SendAcct(&acct)
		r.Code = radius.CodeAccountingResponse
		w.Write(r.Packet)
		return
	default:
		s.lg.CriticalF("Unknown request type from radius-client - %v", r.Code)
		return
	}

	// the time the NAS actually waits, including silent drops
	start := time.Now()
	defer func() { prom.ObserveRequestDuration(nasIP, time.Since(start).Seconds()) }()

	req := events.AuthRequest{
		NasIp:          nasIP,
		NasName:        nasName,
		DeviceMac:      deviceMac,
		DhcpServerName: serverName,
		DhcpServerId:   serverID,
		Class:          strconv.FormatInt(s.classID.Add(1), 10),
		AgentOption: &events.AuthRequestOption{
			RemoteId: macaddr.FromRemoteID(redback.AgentRemoteID_Get(r.Packet)),
		},
	}
	// circuit_id format depends on the switch vendor and is parsed by the processor
	if circuitID := redback.AgentCircuitID_Get(r.Packet); len(circuitID) > 0 {
		req.AgentOption.RawCircuitId = fmt.Sprintf("%X", circuitID)
	}
	s.lg.DebugF("%v %x: nasName=%v, nasIpAddr=%v, deviceMac=%v, dhcpServerName=%v, dhcpServerId=%v, agentRemoteId=%v",
		r.Code, r.Authenticator, nasName, nasIP, deviceMac, serverName, serverID, req.AgentOption.RemoteId)

	resp, err := s.processor.Get(&req)
	switch {
	case err != nil:
		// KindError is an infrastructure failure: stay silent so the NAS retries.
		// Invalid/reject are decisions about this device and get Access-Reject.
		kind := events.ClassifyAuthError(err)
		if kind == events.KindError {
			prom.IncError(nasIP, prom.Critical, "processor_error")
			s.lg.CriticalF("error get answer from processor: client_mac=%v %v", deviceMac, err)
		} else {
			prom.IncError(nasIP, prom.Warning, "auth_rejected")
			s.lg.WarningF("request rejected: client_mac=%v %v", deviceMac, err)
			var authErr *events.AuthError
			errors.As(err, &authErr)
			s.respond(w, r, &events.AuthResponse{Class: req.Class, ExtraAttributes: authErr.ExtraAttributes}, false)
		}
		resp = &events.AuthResponse{Status: string(kind), Error: err.Error()}

	case resp.IpAddress == "" && resp.PoolName == "":
		prom.IncError(nasIP, prom.Warning, "empty_response")
		s.lg.WarningF("processor returned empty ip_address and pool_name: client_mac=%v", deviceMac)
		s.respond(w, r, &events.AuthResponse{Class: req.Class, ExtraAttributes: resp.ExtraAttributes}, false)
		resp = &events.AuthResponse{Status: string(events.KindInvalid), Error: "pool_name and ip_address is empty"}

	default:
		prom.IncRequest(nasIP)
		if resp.PoolName != "" {
			prom.IncPoolRequest(nasIP, resp.PoolName)
			prom.IncMacRequest(nasIP, serverName, deviceMac, "pool")
		}
		if resp.IpAddress != "" {
			prom.IncIPRequest(nasIP)
			prom.IncMacRequest(nasIP, serverName, deviceMac, "ip")
		}
		resp.Class = req.Class
		if !s.respond(w, r, resp, true) {
			resp = &events.AuthResponse{Status: string(events.KindError), Error: "failed to write response"}
		}
	}
	resp.Class = req.Class
	s.processor.SendPostAuth(req, *resp)
}

// respond writes Access-Accept or Access-Reject. Attribute encoding errors are
// logged and skipped; the return value reports whether the packet was sent.
func (s *Server) respond(w radius.ResponseWriter, r *radius.Request, resp *events.AuthResponse, accept bool) bool {
	nasIP := rfc2865.NASIPAddress_Get(r.Packet).String()
	prefix := "reject_"
	r.Code = radius.CodeAccessReject
	if accept {
		prefix = "accept_"
		r.Code = radius.CodeAccessAccept
	}
	fail := func(reason string, err error) {
		prom.IncError(nasIP, prom.Error, prefix+reason)
		s.lg.ErrorF("%v: %v", reason, err)
	}

	r.Attributes = make(radius.Attributes)
	if resp.Class != "" {
		if err := rfc2865.Class_SetString(r.Packet, resp.Class); err != nil {
			fail("class_encode_failed", err)
		}
	}
	if accept {
		if resp.IpAddress != "" {
			if err := rfc2865.FramedIPAddress_Set(r.Packet, net.ParseIP(resp.IpAddress)); err != nil {
				fail("ip_encode_failed", err)
			}
		} else if err := rfc2869.FramedPool_SetString(r.Packet, resp.PoolName); err != nil {
			fail("pool_encode_failed", err)
		}
		if resp.LeaseTimeSec != 0 {
			if err := rfc2865.SessionTimeout_Set(r.Packet, rfc2865.SessionTimeout(resp.LeaseTimeSec)); err != nil {
				fail("session_timeout_encode_failed", err)
			}
		}
	}
	for name, value := range resp.ExtraAttributes {
		if err := setExtraAttribute(r.Packet, name, value); err != nil {
			fail("attr_encode_failed", fmt.Errorf("%v=%v: %w", name, value, err))
		}
	}
	s.lg.DebugF("%v %x: ipAddress='%v', poolName='%v', lease_time='%v', extraAttrs='%v'",
		r.Code, r.Authenticator, resp.IpAddress, resp.PoolName, resp.LeaseTimeSec, resp.ExtraAttributes)

	if err := w.Write(r.Packet); err != nil {
		level := prom.Error
		if accept {
			level = prom.Critical
		}
		prom.IncError(nasIP, level, "write_response_failed")
		s.lg.CriticalF("error write response: %v", err)
		return false
	}
	return true
}
