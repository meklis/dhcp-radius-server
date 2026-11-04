-- Подключается через script.acct. Вызывается вместо HTTP-запроса на acct.addresses.
-- Fire-and-forget - возвращаемое значение не используется.
--
-- request:
--   nas_ip, nas_name, device_mac, dhcp_server_name, dhcp_server_id,
--   ip_address, auth_type, class_id, status_type, session_time,
--   terminate_cause, input_octets, output_octets, pool_name, session_id
--
-- Публикует событие в redis.main как JSON: {time, request}.
local CHANNEL = "radius-acct-events"

function accounting(request)
    log.info("accounting: device_mac=" .. request.device_mac ..
        " status_type=" .. request.status_type ..
        " ip_address=" .. request.ip_address)

    local receivers, err = redis.main:publish(CHANNEL, {
        time = os.time(),
        request = request,
    })
    if not receivers then
        log.error("accounting: publish to " .. CHANNEL .. " failed: " .. err)
    end
end
