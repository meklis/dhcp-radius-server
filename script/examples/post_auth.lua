-- Подключается через script.post_auth. Вызывается вместо HTTP-запроса на postauth.addresses,
-- после того как ответ фактически отправлен NAS-у, в том числе при отказе. Fire-and-forget.
--
-- Публикует событие в redis.main как JSON: {time, request, response}.
--   response.status           - ACCEPT, REJECT, INVALID или ERROR (ответа NAS-у не было)
--   response.error            - причина, если запрос не принят
--   response.extra_attributes - отправленные атрибуты, включая Reply-Message
--
-- HTTP-запросы:
--   local resp, err = http:post("https://example.com/lease", json.encode({ip = response.ip_address}),
--       {headers = {["Content-Type"] = "application/json"}})
--   if not resp then log.error("http: " .. err) end
local CHANNEL = "radius-post-auth-events"

function post_auth(request, response)
    if response.status == "" then
        response.status = "ACCEPT"
    end
    log.info("post_auth: device_mac=" .. request.device_mac ..
        " status=" .. response.status ..
        " ip_address=" .. response.ip_address ..
        " pool_name=" .. response.pool_name)

    local receivers, err = redis.main:publish(CHANNEL, {
        time = os.time(),
        request = request,
        response = response,
    })
    if not receivers then
        log.error("post_auth: publish to " .. CHANNEL .. " failed: " .. err)
    end
end
