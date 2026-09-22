package radius

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/meklis/dhcp-radius-server/macaddr"
	"github.com/meklis/dhcp-radius-server/prom"
	"github.com/meklis/dhcp-radius-server/radius/events"
	extraAttributes "github.com/meklis/dhcp-radius-server/radius/extra_attributes"
	"github.com/meklis/dhcp-radius-server/radius/redback"
	"github.com/meklis/dhcp-radius-server/radius/redback_agent_parsers"
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
	// от получения запроса до конца обработки (записи ответа или решения
	// промолчать) - именно столько реально ждёт NAS. Мерим независимо от того,
	// как разбор пакета в дальнейшем разрешится (см. rfc2865.NASIPAddress_Get
	// вместо req.NasIp - тот доступен только после успешного _parseAuthRequest)
	start := time.Now()
	nasIp := rfc2865.NASIPAddress_Get(r.Packet).String()
	defer func() {
		prom.ObserveRequestDuration(nasIp, time.Since(start).Seconds())
	}()

	classId := rad.getClassId()
	req, err := rad._parseAuthRequest(r)
	if err != nil {
		// разбор самого RADIUS-пакета - инфраструктурная проблема (KindError), а не
		// решение по конкретному устройству: молчим, NAS переспросит
		prom.ErrorsInc(nasIp, prom.Critical, "parse_request_failed")
		rad.lg.Criticalf("response from radius-server: %v", err.Error())
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: string(events.KindError),
			Error:  fmt.Sprintf("%v", err),
			Class:  classId,
		})
		return
	}
	req.Class = classId
	resp, err := rad._handlerProccessApi(req)
	if err != nil {
		// KindInvalid/KindReject - скрипт/api приняли решение об этом конкретном
		// запросе (не распарсился circuit_id, явный бизнес-отказ) -> Access-Reject,
		// это ожидаемое поведение, не ошибка сервера - WARNING, не CRITICAL.
		// KindError (в т.ч. любая необёрнутая ошибка) - инфраструктурная проблема,
		// не связанная с этим устройством -> молчим, см. events.AuthErrorKind
		kind := events.ClassifyAuthError(err)
		if kind == events.KindError {
			prom.ErrorsInc(nasIp, prom.Critical, "processor_error")
			rad.lg.CriticalF("error get answer from processor: client_mac=%v %v", req.DeviceMac, err.Error())
		} else {
			prom.ErrorsInc(nasIp, prom.Warning, "auth_rejected")
			rad.lg.WarningF("request rejected: client_mac=%v %v", req.DeviceMac, err.Error())
			if rejErr := rad._respondAuthReject(w, r, classId, events.ExtractExtraAttributes(err)); rejErr != nil {
				rad.lg.ErrorF("error write reject response: %v", rejErr.Error())
			}
		}
		rad.lg.DebugF("%v", tracerr.Sprint(err))
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: string(kind),
			Error:  fmt.Sprintf("%v", err),
			Class:  classId,
		})
		return
	} else if resp.IpAddress == "" && resp.PoolName == "" {
		// ответ структурно получен, но обслужить нечем - это решение по конкретному
		// запросу (KindInvalid), а не инфраструктурная проблема - WARNING
		prom.ErrorsInc(nasIp, prom.Warning, "empty_response")
		rad.lg.WarningF("processor returned empty ip_address and pool_name: client_mac=%v", req.DeviceMac)
		if rejErr := rad._respondAuthReject(w, r, classId, resp.ExtraAttributes); rejErr != nil {
			rad.lg.ErrorF("error write reject response: %v", rejErr.Error())
		}
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: string(events.KindInvalid),
			Error:  "pool_name and ip_address is empty",
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
		// сбой записи ответа в сокет - транспортная проблема (KindError), не решение
		// по устройству; повторная попытка Write с reject тут не поможет (сокет/пакет
		// уже показали проблему) - молчим, NAS переспросит
		rad.processor.SendPostAuth(req, events.AuthResponse{
			Status: string(events.KindError),
			Error:  fmt.Sprintf("%v", err),
			Class:  classId,
		})
		prom.ErrorsInc(nasIp, prom.Critical, "write_response_failed")
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
	// User-Name приходит в формате конкретного вендора NAS (с разделителями/без,
	// в разном регистре) - приводим к единому виду здесь, на границе разбора пакета,
	// чтобы дальше (script/api, логи, метрики) везде был один и тот же формат мака
	// и его можно было сравнивать как обычную строку, не нормализуя на месте
	deviceMAC := macaddr.Normalize(rfc2865.UserName_GetString(r.Packet))
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
	deviceMAC := macaddr.Normalize(rfc2865.UserName_GetString(r.Packet))
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

// _respondAuthReject sends an explicit Access-Reject. Used for events.KindInvalid/
// KindReject failures (see radius/events/auth_error.go) - a decision about this
// specific request, not an infrastructure problem. Before commit b89eb33 (2020) an
// equivalent reject was sent on every error path including infrastructure failures;
// that was dropped in favor of always staying silent, which turned out to diverge
// from the legacy Perl/FreeRADIUS script still running in production (see
// script.pl:authenticate - RLM_MODULE_INVALID there reliably produces a real
// Access-Reject, confirmed by replaying a real production capture through this
// server, see tools/pcapreplay) - restored for the request-specific cases only
func (rad *Radius) _respondAuthReject(w radius.ResponseWriter, r *radius.Request, classId string, extraAttrs map[string]string) error {
	nasIp := rfc2865.NASIPAddress_Get(r.Packet).String()
	r.Attributes = make(radius.Attributes)
	if classId != "" {
		if err := rfc2865.Class_SetString(r.Packet, classId); err != nil {
			prom.ErrorsInc(nasIp, prom.Error, "reject_class_encode_failed")
			rad.lg.ErrorF("error generate reject response packet with className=%v", classId)
		}
	}
	for name, value := range extraAttrs {
		if err := extraAttributes.SetString(r.Packet, name, value); err != nil {
			prom.ErrorsInc(nasIp, prom.Error, "reject_attr_encode_failed")
			rad.lg.ErrorF("error set reject response %v=%v: %v", name, value, err)
		}
	}
	r.Code = radius.CodeAccessReject
	rad.lg.DebugF("%v %x: rejected", r.Code, r.Authenticator)
	if err := w.Write(r.Packet); err != nil {
		return tracerr.Wrap(err)
	}
	return nil
}

func (rad *Radius) _respondAuthAccept(response events.AuthResponse, w radius.ResponseWriter, r *radius.Request) error {
	nasIp := rfc2865.NASIPAddress_Get(r.Packet).String()
	r.Attributes = make(radius.Attributes)
	if response.Class != "" {
		if err := rfc2865.Class_SetString(r.Packet, response.Class); err != nil {
			prom.ErrorsInc(nasIp, prom.Error, "accept_class_encode_failed")
			rad.lg.ErrorF("error generate response packet for pool with className=%v", response.Class)
		}
	}

	switch response.GetRadiusResponseType() {
	case events.SetPool:
		if err := rfc2869.FramedPool_Set(r.Packet, []byte(response.PoolName)); err != nil {
			prom.ErrorsInc(nasIp, prom.Error, "accept_pool_encode_failed")
			rad.lg.ErrorF("error generate response packet for pool with poolName=%v", response.PoolName)
		}
	case events.SetIpAddress:
		if err := rfc2865.FramedIPAddress_Set(r.Packet, response.GetIp()); err != nil {
			prom.ErrorsInc(nasIp, prom.Error, "accept_ip_encode_failed")
			rad.lg.ErrorF("error generate response packet for ip=%v", response.IpAddress)
		}
	default:
		rad.lg.ErrorF("unknown type of response set with id: %v", response.GetRadiusResponseType())
		prom.ErrorsInc(nasIp, prom.Error, "accept_unknown_response_type")
		return errors.New(fmt.Sprintf("unknown type of response set with id: %v", response.GetRadiusResponseType()))
	}

	if response.LeaseTimeSec != 0 {
		if err := rfc2865.SessionTimeout_Set(r.Packet, rfc2865.SessionTimeout(response.LeaseTimeSec)); err != nil {
			prom.ErrorsInc(nasIp, prom.Error, "accept_session_timeout_encode_failed")
			rad.lg.ErrorF("error set response SessionTimeOut=%v", response.LeaseTimeSec)
		}
	}
	for name, value := range response.ExtraAttributes {
		if err := extraAttributes.SetString(r.Packet, name, value); err != nil {
			prom.ErrorsInc(nasIp, prom.Error, "accept_attr_encode_failed")
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
