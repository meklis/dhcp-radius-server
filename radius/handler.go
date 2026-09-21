package radius

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/meklis/all-ok-radius-server/prom"
	"github.com/meklis/all-ok-radius-server/radius/events"
	extraAttributes "github.com/meklis/all-ok-radius-server/radius/extra_attributes"
	"github.com/meklis/all-ok-radius-server/radius/redback"
	"github.com/meklis/all-ok-radius-server/radius/redback_agent_parsers"
	"github.com/ztrue/tracerr"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
)

func (rad *Radius) handler(w radius.ResponseWriter, r *radius.Request) {
	switch r.Code.String() {
	case "Access-Request":
		rad._handleAuthRequest(w, r)
	case "Accounting-Request":
		rad._handleAccountingRequest(w, r)
	default:
		rad.lg.CriticalF("Unknown request type from radius-client - %v", r.Code.String())
	}
}

func (rad *Radius) _handlerProccessApi(request events.AuthRequest) (*events.AuthResponse, error) {
	resp, err := rad.processor.Get(&request)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return resp, nil
}
func (rad *Radius) _handleAuthRequest(w radius.ResponseWriter, r *radius.Request) {
	classId := rad.getClassId()
	req, err := rad._parseAuthRequest(r)
	if err != nil {
		prom.ErrorsInc(prom.Critical, "radius")
		rad.lg.Criticalf("response from radius-server: %v", err.Error())
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: "ERROR",
			Error:  fmt.Sprintf("%v", err),
			Class:  classId,
		})
		return
	}
	req.Class = classId
	resp, err := rad._handlerProccessApi(req)
	if err != nil {
		prom.ErrorsInc(prom.Critical, "radius")
		rad.lg.CriticalF("error get answer from processor: client_mac=%v %v", req.DeviceMac, err.Error())
		rad.lg.DebugF("%v", tracerr.Sprint(err))
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: "ERROR",
			Error:  fmt.Sprintf("%v", err),
			Class:  classId,
		})
		return
	} else if resp.IpAddress == "" && resp.PoolName == "" {
		prom.ErrorsInc(prom.Critical, "radius")
		rad.lg.CriticalF("error get answer from processor: client_mac=%v pool_name and ip_address is empty", req.DeviceMac)
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: "ERROR",
			Error:  fmt.Sprintf("%v", err),
			Class:  classId,
		})
		return
	}
	prom.RadRequestsInc(req.NasIp)
	if resp.PoolName != "" {
		prom.RadRequestsPoolInc(req.NasIp)
		prom.RadRequestsByPoolInc(req.NasIp, resp.PoolName)
		prom.RadDetailedRequest(req.NasIp, req.DhcpServerName, req.DeviceMac, "pool")
	}
	if resp.IpAddress != "" {
		prom.RadRequestsIpAddressInc(req.NasIp)
		prom.RadDetailedRequest(req.NasIp, req.DhcpServerName, req.DeviceMac, "ip")
	}

	resp.Class = classId
	err = rad._respondAuthAccept(*resp, w, r)

	if err != nil {
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: "ERROR",
			Error:  fmt.Sprintf("%v", err),
			Class:  classId,
		})
		prom.ErrorsInc(prom.Critical, "radius")
		rad.lg.CriticalF("error write response: %v", err.Error())
		rad.lg.DebugF("%v", tracerr.Sprint(err))
		return
	} else {
		rad.processor.SendPostAuth(req, *resp)
	}
}
func (rad *Radius) _parseAuthRequest(r *radius.Request) (events.AuthRequest, error) {
	nasName := rfc2865.NASIdentifier_GetString(r.Packet)
	nasIpAddr := rfc2865.NASIPAddress_Get(r.Packet).String()
	deviceMAC := rfc2865.UserName_GetString(r.Packet)
	dhcpServerName := rfc2865.CalledStationID_GetString(r.Packet)
	dhcpServerId := rfc2865.CallingStationID_GetString(r.Packet)
	rad.lg.DebugF("%v %x: nasName=%v, nasIpAddr=%v, deviceMac=%v, dhcpServerName=%v, dhcpServerId=%v", r.Code.String(), r.Authenticator, nasName, nasIpAddr, deviceMAC, dhcpServerName, dhcpServerId)
	agent := new(events.AuthRequestOption)
	remoteId := redback_agent_parsers.ParseRemoteId(redback.AgentRemoteID_Get(r.Packet))

	agent.RemoteId = remoteId
	rad.lg.DebugF("%v %x: agentRemoteId=%v", r.Code.String(), r.Authenticator, agent.RemoteId)
	// байты отдаются как есть - формат содержимого зависит от вендора свитча
	// и разбирается уже в скрипте/api по db.devices.parse_type, не здесь
	if bts := redback.AgentCircuitID_Get(r.Packet); len(bts) > 0 {
		agent.RawCircuitId = fmt.Sprintf("%X", bts)
	}
	request := events.AuthRequest{
		NasIp:          nasIpAddr,
		NasName:        nasName,
		DeviceMac:      deviceMAC,
		DhcpServerName: dhcpServerName,
		DhcpServerId:   dhcpServerId,
		AgentOption:    agent,
	}
	return request, nil
}

func (rad *Radius) _handleAccountingRequest(w radius.ResponseWriter, r *radius.Request) {
	req, _ := rad._parseAccountingRequest(r)
	prom.RadAcctRequestsInc(req.NasIp, req.DhcpServerName)

	rad.processor.SendAcct(&req)
	r.Code = radius.CodeAccountingResponse
	w.Write(r.Packet)
}

func (rad *Radius) _parseAccountingRequest(r *radius.Request) (events.AcctRequest, error) {
	nasName := rfc2865.NASIdentifier_GetString(r.Packet)
	nasIpAddr := rfc2865.NASIPAddress_Get(r.Packet).String()
	deviceMAC := rfc2865.UserName_GetString(r.Packet)
	dhcpServerName := rfc2865.CalledStationID_GetString(r.Packet)
	dhcpServerId := rfc2865.CallingStationID_GetString(r.Packet)
	ipAddr := rfc2865.FramedIPAddress_Get(r.Packet)
	classId := rfc2865.Class_GetString(r.Packet)
	poolName := rfc2869.FramedPool_GetString(r.Packet)
	authenticType := rfc2866.AcctAuthentic_Strings[rfc2866.AcctAuthentic_Get(r.Packet)]
	statusType := rfc2866.AcctStatusType_Strings[rfc2866.AcctStatusType_Get(r.Packet)]
	sessionTime := int64(rfc2866.AcctSessionTime_Get(r.Packet))
	terminateCause := rfc2866.AcctTerminateCause_Strings[rfc2866.AcctTerminateCause_Get(r.Packet)]
	inOctets := int64(rfc2866.AcctInputOctets_Get(r.Packet))
	outOctets := int64(rfc2866.AcctOutputOctets_Get(r.Packet))

	request := events.AcctRequest{
		NasIp:           nasIpAddr,
		NasName:         nasName,
		DeviceMac:       deviceMAC,
		DhcpServerName:  dhcpServerName,
		DhcpServerId:    dhcpServerId,
		FramedIpAddress: ipAddr.String(),
		AuthType:        authenticType,
		Class:           classId,
		StatusType:      statusType,
		SessionTime:     sessionTime,
		TerminateCause:  terminateCause,
		InputOctets:     inOctets,
		OutputOctets:    outOctets,
		PoolName:        poolName,
	}
	d, _ := json.Marshal(&request)
	rad.lg.DebugF("%v %x: %v", r.Code.String(), r.Authenticator, string(d))
	return request, nil
}

func (rad *Radius) _respondAuthAccept(response events.AuthResponse, w radius.ResponseWriter, r *radius.Request) error {
	r.Attributes = make(radius.Attributes)
	if response.Class != "" {
		if err := rfc2865.Class_SetString(r.Packet, response.Class); err != nil {
			prom.ErrorsInc(prom.Error, "radius")
			rad.lg.ErrorF("error generate response packet for pool with className=%v", response.Class)
		}
	}

	switch response.GetRadiusResponseType() {
	case events.SetPool:
		if err := rfc2869.FramedPool_Set(r.Packet, []byte(response.PoolName)); err != nil {
			prom.ErrorsInc(prom.Error, "radius")
			rad.lg.ErrorF("error generate response packet for pool with poolName=%v", response.PoolName)
		}
	case events.SetIpAddress:
		if err := rfc2865.FramedIPAddress_Set(r.Packet, response.GetIp()); err != nil {
			prom.ErrorsInc(prom.Error, "radius")
			rad.lg.ErrorF("error generate response packet for ip=%v", response.IpAddress)
		}
	default:
		rad.lg.ErrorF("unknown type of response set with id: %v", response.GetRadiusResponseType())
		prom.ErrorsInc(prom.Error, "radius")
		return errors.New(fmt.Sprintf("unknown type of response set with id: %v", response.GetRadiusResponseType()))
	}

	if response.LeaseTimeSec != 0 {
		if err := rfc2865.SessionTimeout_Set(r.Packet, rfc2865.SessionTimeout(response.LeaseTimeSec)); err != nil {
			prom.ErrorsInc(prom.Error, "radius")
			rad.lg.ErrorF("error set response SessionTimeOut=%v", response.LeaseTimeSec)
		}
	}
	for name, value := range response.ExtraAttributes {
		if err := extraAttributes.SetString(r.Packet, name, value); err != nil {
			prom.ErrorsInc(prom.Error, "radius")
			rad.lg.ErrorF("error set response %v=%v: %v", name, value, err)
		}
	}
	r.Code = radius.CodeAccessAccept
	rad.lg.DebugF("%v %x: ipAddress='%v', poolName='%v', lease_time='%v', extraAttrs='%v'", r.Code, r.Authenticator, response.IpAddress, response.PoolName, response.LeaseTimeSec, response.ExtraAttributes)

	err := w.Write(r.Packet)
	if err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}
