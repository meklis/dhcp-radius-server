-- Обработчик auth-запросов (script.auth) - вызывается на каждый Access-Request,
-- должен определять function authorize(request) -> table.
--
-- ПОЛЯ request:
--   request.nas_ip            - NAS-IP-Address (IP свитча/relay, приславшего запрос)
--   request.nas_name          - NAS-Identifier
--   request.device_mac        - мак абонентского устройства (User-Name)
--   request.dhcp_server_name  - Called-Station-Id
--   request.dhcp_server_id    - Calling-Station-Id
--   request.ip_address        - Framed-IP-Address из запроса, если был
--   request.class_id          - Class
--   request.option            - таблица (пустая, если в пакете нет option82)
--   request.option.remote_id  - мак свитча/OLT из option82 Agent-Remote-Id (AA:BB:CC:DD:EE:FF) или nil
--   request.option.circuit_id - option82 Agent-Circuit-Id, hex-строка без "0x", или nil
--
-- ВОЗВРАТ authorize():
--   ip_address           - выдать конкретный IP (приоритетнее pool_name, если заданы оба)
--   pool_name            - выдать имя пула (DHCP-сервер сам берёт IP из пула)
--   lease_time_sec       - время аренды в секундах (Session-Timeout)
--   extra_attributes     - таблица {["Mikrotik-Address-List"]="...", ...} с
--                          дополнительными RADIUS-атрибутами в ответ (полное имя ->
--                          значение, включая стандартный "Reply-Message" - см.
--                          replyMessage()/attach() ниже), список поддерживаемых
--                          имён см. attrTypes на стороне Go. Единственное поле,
--                          которое применяется даже вместе с error/reject
--   error                - ip_address/pool_name/lease_time_sec игнорируются. Значит
--                          "этот конкретный запрос не может быть обслужен" (например
--                          не распарсился circuit_id) - клиенту отправляется явный
--                          Access-Reject
--   reject               - как error, приоритетнее него, если заданы оба. Явное
--                          бизнес-решение отказать этому устройству (например
--                          заблокировано) - клиенту отправляется явный Access-Reject.
--                          Сейчас нигде не используется - задел под будущие правила
--
-- ГЛОБАЛЬНЫЕ ОБЪЕКТЫ:
--   db:getDeviceByMac(mac) -> table{ip, mac, parse_type} | nil
--       поиск в script.database.devices_url по мак-адресу свитча/OLT
--   db:getBind(source, mac, device_mac, port) -> array of table{ip, port, client_mac, device_mac}
--       source - имя источника из script.database.binds (например "clients"/"smart")
--       mac/device_mac/port - опциональны ("" или не передавать), но нужен либо mac,
--       либо пара device_mac+port - иначе вернётся пустой массив
--   log.debug(msg) / log.info(msg) / log.notice(msg) / log.warning(msg) / log.error(msg)
--       пишут в общий лог сервера с соответствующим уровнем
--
-- db обязателен при processor: script (см. script.database.devices_url в конфиге)

local CREDIT_HOUR = 6      -- час, после которого лиз считается "до утра"
local TIMEOUT_WIFI = 1800  -- незарегистрированный wifi-мак (66:99:...)
local TIMEOUT_FAKE = 120   -- совсем неизвестное устройство

-- лиз INET считается до ближайших CREDIT_HOUR по местному времени, минимум 120с
local function leaseTime()
    local hour = tonumber(os.date("%H"))
    local lease
    if hour >= CREDIT_HOUR then
        lease = (24 - hour + CREDIT_HOUR) * 3600
    else
        lease = (CREDIT_HOUR - hour) * 3600
    end
    if lease < 120 then
        lease = 120
    end
    return lease
end

local function hexByte(hex, pos, len)
    if pos + len - 1 > #hex then
        return nil
    end
    return tonumber(hex:sub(pos, pos + len - 1), 16)
end

-- hex-строка -> «сырые» байты как текст (для ZTE, где значения зашиты ascii-строкой s=..;p=..)
local function hexToStr(hex)
    if #hex % 2 == 1 then
        hex = hex .. "0"
    end
    local chars = {}
    for i = 1, #hex - 1, 2 do
        chars[#chars + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
    end
    return table.concat(chars)
end

local circuitParsers = {}

circuitParsers["zte"] = function(circuit)
    local raw = hexToStr((circuit:gsub("^0[xX]", "")))
    local vlan = tonumber(raw:match("v=(%d+)"))
    if not vlan then
        return nil
    end
    local stack = tonumber(raw:match("s=(%d+)")) or 0
    local p = tonumber(raw:match("p=(%d+)")) or 0
    local o = tonumber(raw:match("o=(%d+)")) or 0
    return vlan, stack, stack * 100000 + p * 1000 + o
end

circuitParsers["edgecore"] = function(circuit)
    local stack, port, vlan = hexByte(circuit, 1, 2), hexByte(circuit, 3, 2), hexByte(circuit, 5, 4)
    if not vlan or not stack or not port then
        return nil
    end
    return vlan, stack, port
end

circuitParsers["bdcom"] = function(circuit)
    if #circuit == 8 then
        local stack, port, vlan = hexByte(circuit, 1, 2), hexByte(circuit, 3, 2), hexByte(circuit, 5, 4)
        if not vlan or not stack or not port then
            return nil
        end
        return vlan, stack, port
    end
    local vlan, stack, portRaw = hexByte(circuit, 1, 4), hexByte(circuit, 7, 2), hexByte(circuit, 9, 2)
    if not vlan or not stack or not portRaw then
        return nil
    end
    return vlan, stack, stack * 1000 + portRaw
end

circuitParsers["cdata"] = function(circuit)
    local vlan, stack, portRaw = hexByte(circuit, 1, 4), hexByte(circuit, 7, 2), hexByte(circuit, 9, 2)
    if not vlan or not stack or not portRaw then
        return nil
    end
    return vlan, stack, stack * 1000 + portRaw
end

circuitParsers["dlink"] = function(circuit)
    local vlan, stack, port = hexByte(circuit, 5, 4), hexByte(circuit, 9, 2), hexByte(circuit, 11, 2)
    if not vlan or not stack or not port then
        return nil
    end
    return vlan, stack, port
end

local function circuitReader(circuit, parseType)
    if not circuit or circuit == "" or not parseType or parseType == "" then
        return nil
    end
    local parser = circuitParsers[parseType:lower()]
    if not parser then
        return nil
    end
    local vlan, stack, port = parser(circuit)
    if not vlan then
        return nil
    end
    return vlan, stack, port
end

-- IP-заглушки в binds - не настоящие адреса, а маркеры "весь порт отдан под
-- общий сервисный пул". 2.2.2.2/4.4.4.4/5.5.5.5 включают соответствующий флаг,
-- 1.1.1.1/3.3.3.3 зарезервированы под будущие сервисы - сейчас ни на что не
-- влияют, только исключаются из списка реальных привязок
local FLAG_BY_IP = { ["2.2.2.2"] = "iptv", ["4.4.4.4"] = "wifi", ["5.5.5.5"] = "youtube" }
local RESERVED_IPS = { ["1.1.1.1"] = true, ["3.3.3.3"] = true }

local function getPortBinds(macSw, port)
    local all = db:getBind("clients", "", macSw, port)
    local binds, flags = {}, {}
    for _, b in ipairs(all) do
        local flag = FLAG_BY_IP[b.ip]
        if flag then
            flags[flag] = true
        elseif not RESERVED_IPS[b.ip] then
            binds[#binds + 1] = b
        end
    end
    return binds, flags
end

-- Reply-Message (через extra_attributes, см. attrTypes в radius/extra_attributes) -
-- диагностическая строка, формат идентичен legacy script.pl (authenticate():
-- $RAD_REPLY{'Reply-Message'}), чтобы её мог разобрать тот же парсер, что уже
-- читает Reply-Message прод-сервера (см. tools/pcapreplay) - не влияет на выдачу
-- IP/пула, только для сверки парсинга circuit_id. Отправляется клиенту на Accept
-- и на Reject одинаково (см. radius/handler.go)
local function replyMessage(vlan, stack, port, macSw, parseType)
    local function s(v)
        if v == nil then return "" end
        return tostring(v)
    end
    return "vlan=" .. s(vlan) .. ";stack=" .. s(stack) .. ";port=" .. s(port) ..
        ";macSw=" .. s(macSw) .. ";parse-type=" .. s(parseType)
end

-- attach добавляет Reply-Message в extra_attributes возвращаемой таблицы, не
-- затирая уже выставленные там ключи (например Mikrotik-Address-List)
local function attach(rm, t)
    t.extra_attributes = t.extra_attributes or {}
    t.extra_attributes["Reply-Message"] = rm
    return t
end

function authorize(request)
    local macAbon = request.device_mac
    local macSw = request.option.remote_id or ""
    local circuitId = request.option.circuit_id or ""

    local parseType
    if macSw ~= "" then
        local device = db:getDeviceByMac(macSw)
        if not device then
            log.warning("authorize: mac=" .. macAbon .. " mac_sw=" .. macSw .. " reject: device not found")
            return { reject = "device not found: mac_sw=" .. macSw }
        end
        parseType = device.parse_type
    elseif hexToStr(circuitId):match("^s=%d") then
        -- ZTE OLT (l2-relay-agent) иногда не шлёт remote-id вовсе, но circuit_id
        -- в этом случае самоописываемый текстовый формат (s=..;p=..;o=..;v=..) -
        -- тип парсера тут однозначен и без похода в db, в отличие от остальных
        -- вендоров (там определение по длине убрано - см. parseTypeByUnknownDevice
        -- в истории этого файла, не подтвердилось трафиком). Подтверждено сверкой
        -- через tools/pcapreplay: без этой ветки реджектились 30/31
        -- сессий, которые прод реально принимает
        parseType = "zte"
    else
        log.warning("authorize: mac=" .. macAbon .. " mac_sw=<UNKNOWN> reject: no remote_id")
        return { reject = "no remote_id: circuit_id=" .. circuitId }
    end

    local vlan, stack, port = circuitReader(circuitId, parseType)

    log.debug("authorize: mac=" .. macAbon .. " mac_sw=" .. macSw ..
        " parse_type=" .. tostring(parseType) .. " vlan=" .. tostring(vlan) .. " port=" .. tostring(port))

    -- vlan=0 - тоже "не распарсилось": в legacy Perl-скрипте (script.pl:authenticate)
    -- проверка "if(!$vlan)" ловит и undef, и 0 (в Perl 0 - falsy), а Lua 0 - truthy,
    -- поэтому голым "if not vlan" эта ветка не отлавливалась - подтверждено сверкой
    -- через tools/pcapreplay на реальном трафике: vlan=0 из circuit_id всегда даёт
    -- Access-Reject на проде, мы же ошибочно выдавали Accept на бессмысленный
    -- "INET-0-FAKE" пул
    if not vlan or vlan == 0 then
        log.warning("authorize: mac=" .. macAbon .. " mac_sw=" .. macSw .. " parse_type=" .. tostring(parseType) .. " vlan=" .. tostring(vlan) .. " reject: circuit_id parse failed")
        return {
            error = "circuit_id parse failed: mac_sw=" .. macSw .. " parse_type=" .. tostring(parseType) .. " circuit_id=" .. circuitId,
            extra_attributes = { ["Reply-Message"] = replyMessage(vlan, stack, port, macSw, parseType) },
        }
    end

    local rm = replyMessage(vlan, stack, port, macSw, parseType)
    local leaseInet = leaseTime()

    local portBinds, flags = getPortBinds(macSw, port)

    -- portBinds содержит таблицу всех привязок на порту.
    -- если на порту только 1 привязка - не смотрим на мак, сразу же устанавливаем IP и возвращаем клиенту
    -- если привязок >1, то ищем точное совпадение по маку, иначе - ничего не выдаем
    local ipAddress = nil
    if #portBinds == 1 then
        ipAddress = portBinds[1].ip
    elseif #portBinds > 1 then
        for _, b in ipairs(portBinds) do
            if b.client_mac == macAbon then
                ipAddress = b.ip
                break
            end
        end
    end
    if ipAddress then
        return attach(rm, { ip_address = ipAddress, lease_time_sec = leaseInet })
    end

    -- шаг 2: свою привязку не выдали - порт целиком под общим сервисным пулом?
    -- порядок приоритета фиксирован: youtube, потом wifi, потом iptv
    if flags.youtube then
        return attach(rm, { pool_name = "YOUTUBE-" .. vlan, lease_time_sec = leaseInet, extra_attributes = { ["Mikrotik-Address-List"] = "Triolan.Youtube" } })
    end
    if flags.wifi then
        return attach(rm, { pool_name = "INET-" .. vlan .. "-FAKE", lease_time_sec = leaseInet, extra_attributes = { ["Mikrotik-Address-List"] = "Triolan.Wifi" } })
    end
    if flags.iptv then
        return attach(rm, { pool_name = "INET-" .. vlan .. "-FAKE", lease_time_sec = leaseInet, extra_attributes = { ["Mikrotik-Address-List"] = "Triolan.IPTV" } })
    end

    -- шаг 3: smart-устройство (абонентский wifi-роутер и т.п.) по мак абонента,
    -- затем незарегистрированный wifi-мак (66:99:...), и в самом конце - совсем
    -- неизвестное устройство
    local smart = db:getBind("smart", macAbon)
    if #smart > 0 then
        return attach(rm, { ip_address = smart[1].ip, lease_time_sec = leaseInet })
    end

    if macAbon:match("^66:99:") then
        return attach(rm, { pool_name = "INET-" .. vlan .. "-WIFI", lease_time_sec = TIMEOUT_WIFI })
    end

    return attach(rm, { pool_name = "INET-" .. vlan .. "-FAKE", lease_time_sec = TIMEOUT_FAKE })
end
