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
--                          значение), список поддерживаемых имён см. attrTypes на
--                          стороне Go
--   error                - если задано, остальные поля игнорируются: клиенту не отвечаем
--                          вовсе (RADIUS-таймаут на NAS, а не Access-Reject)
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

-- парсеры circuit-id по db.devices.parse_type. circuit_id - сырые байты сабопции
-- option82 как есть (без срезов на стороне Go) - смещения свои под каждый вендор свитча
local circuitParsers = {}

-- ZTE OLT: текстовый s=slot p=port o=onu v=vlan m=src-mac (подтверждено трафиком и
-- конфигом устройства). m= не используется - macSw для этого формата определяется
-- отдельно, см. authorize()
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

-- BDCOM: два варианта длины (оба подтверждены трафиком/реальными данными):
--   10 hex (5 байт) - vlan(2Б), неиспользуемый байт, stack(1Б), port_raw(1Б)
--   8 hex (4 байта) - vlan(2Б), stack(1Б), port_raw(1Б), без неиспользуемого байта
circuitParsers["bdcom"] = function(circuit)
    local vlan, stack, portRaw
    if #circuit == 8 then
        vlan, stack, portRaw = hexByte(circuit, 1, 4), hexByte(circuit, 5, 2), hexByte(circuit, 7, 2)
    else
        vlan, stack, portRaw = hexByte(circuit, 1, 4), hexByte(circuit, 7, 2), hexByte(circuit, 9, 2)
    end
    if not vlan or not stack or not portRaw then
        return nil
    end
    return vlan, stack, stack * 1000 + portRaw
end

-- C-Data: те же смещения, что и bdcom (по perl-скрипту - общее семейство BDcom-cicrNN),
-- НЕ подтверждено трафиком этого сервера
circuitParsers["cdata"] = circuitParsers["bdcom"]

-- D-Link: 6 байт - 2 байта заголовка, vlan, module/stack, port (подтверждено трафиком)
circuitParsers["dlink"] = function(circuit)
    local vlan, stack, port = hexByte(circuit, 5, 4), hexByte(circuit, 9, 2), hexByte(circuit, 11, 2)
    if not vlan or not stack or not port then
        return nil
    end
    return vlan, stack, port
end

-- Edgecore: смещения из perl-скрипта минус 1 байт заголовка (по аналогии с dlink/bdcom),
-- НЕ подтверждено трафиком этого сервера
circuitParsers["edgecore"] = function(circuit)
    local stack, port, vlan = hexByte(circuit, 1, 2), hexByte(circuit, 3, 2), hexByte(circuit, 5, 4)
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

-- Определение parse_type без похода в db - применяется когда remote-id отсутствует
-- и искать устройство по мак-адресу свитча не по чему. Пробует по очереди:
--   1. самоописываемый текстовый ZTE-формат (s=.. p=.. o=.. v=.. m=..)
--   2. длину circuit_id, как в perl-скрипте: dlink - 6 байт (12 hex), bdcom - 5 байт
--      (10 hex), обе длины подтверждены реальным трафиком. Для cdata/edgecore
--      подтверждённой длины нет - по длине их не различаем
local function parseTypeByUnknownDevice(circuit)
    if hexToStr(circuit):match("^s=%d") then
        return "zte"
    end
    local len = #circuit
    if len == 12 then
        return "dlink"
    elseif len == 10 then
        return "bdcom"
    end
    return nil
end

function authorize(request)
    local macAbon = request.device_mac
    local macSw = request.option.remote_id or ""
    local circuitId = request.option.circuit_id or ""

    -- без remote-id нет мака свитча - ни db:getDeviceByMac, ни привязки по устройству+порту
    -- недоступны в принципе. К базе вообще не обращаемся - определяем vlan прямо из
    -- circuit_id (текстовый ZTE-формат или по длине) и выдаём общий "серый" пул
    if macSw == "" then
        local parseType = parseTypeByUnknownDevice(circuitId)
        local vlan = circuitReader(circuitId, parseType)

        log.debug("authorize: mac=" .. macAbon .. " mac_sw= parse_type=" .. tostring(parseType) .. " vlan=" .. tostring(vlan))

        if not vlan then
            return { error = "circuit_id parse failed: mac_sw= parse_type=" .. tostring(parseType) .. " circuit_id=" .. circuitId }
        end
        return { pool_name = "INET-" .. vlan .. "-FAKE", lease_time_sec = TIMEOUT_FAKE }
    end

    local parseType = nil
    local device = db:getDeviceByMac(macSw)
    if device then
        parseType = device.parse_type
    end

    local vlan, stack, port = circuitReader(circuitId, parseType)

    log.debug("authorize: mac=" .. macAbon .. " mac_sw=" .. macSw ..
        " parse_type=" .. tostring(parseType) .. " vlan=" .. tostring(vlan) .. " port=" .. tostring(port))

    if not vlan then
        return { error = "circuit_id parse failed: mac_sw=" .. macSw .. " parse_type=" .. tostring(parseType) .. " circuit_id=" .. circuitId }
    end

    local leaseInet = leaseTime()

    -- один запрос всех привязок на этом порту устройства (мак не задаём)
    local portBinds = db:getBind("clients", "", macSw, port)

    -- если привязка ровно одна - она и есть ответ для этого порта, независимо
    -- от того, чей мак в ней записан. Если их несколько - ищем свою по мак-адресу.
    -- Оба значения (macAbon и b.client_mac) уже приведены к единому формату
    -- AA:BB:CC:DD:EE:FF на стороне Go (см. macaddr.Normalize - применяется и к
    -- request.device_mac при разборе RADIUS-пакета, и к client_mac при загрузке
    -- clientdb), поэтому их можно сравнивать как обычные строки без нормализации здесь
    local candidate = nil
    if #portBinds == 1 then
        candidate = portBinds[1]
    elseif #portBinds > 1 then
        for _, b in ipairs(portBinds) do
            if b.client_mac == macAbon then
                candidate = b
                break
            end
        end
    end

    if candidate then
        if candidate.ip == "5.5.5.5" then
            return { pool_name = "YOUTUBE-" .. vlan, lease_time_sec = leaseInet, extra_attributes = { ["Mikrotik-Address-List"] = "Triolan.Youtube" } }
        elseif candidate.ip ~= "2.2.2.2" and candidate.ip ~= "4.4.4.4" then
            return { ip_address = candidate.ip, lease_time_sec = leaseInet }
        end
    end

    -- порт целиком отдан под общий пул IPTV/WIFI - срабатывает и когда своя
    -- привязка не найдена среди нескольких на порту
    for _, b in ipairs(portBinds) do
        if b.ip == "4.4.4.4" then
            return { pool_name = "INET-" .. vlan .. "-FAKE", lease_time_sec = leaseInet, extra_attributes = { ["Mikrotik-Address-List"] = "Triolan.Wifi" } }
        end
    end
    for _, b in ipairs(portBinds) do
        if b.ip == "2.2.2.2" then
            return { pool_name = "INET-" .. vlan .. "-FAKE", lease_time_sec = leaseInet, extra_attributes = { ["Mikrotik-Address-List"] = "Triolan.IPTV" } }
        end
    end

    -- smart-устройство (абонентский wifi-роутер и т.п.) - привязка по мак абонента
    local smart = db:getBind("smart", macAbon)
    if #smart > 0 then
        return { ip_address = smart[1].ip, lease_time_sec = leaseInet }
    end

    -- ничего не найдено - выдаём "серый" пул
    if macAbon:match("^66:99:") then
        return { pool_name = "INET-" .. vlan .. "-WIFI", lease_time_sec = TIMEOUT_WIFI }
    end

    return { pool_name = "INET-" .. vlan .. "-FAKE", lease_time_sec = TIMEOUT_FAKE }
end
