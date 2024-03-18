#!/usr/bin/env lua

--[[
Luadrop HTTPS and WebSocket server.
]]

local io = require "io"
local cerr = require "cqueues.errno"
local monotime = require "cqueues".monotime
local lpeg = require "lpeg"
local patterns = require "lpeg_patterns.uri"
local basexx = require "basexx"
local json = require "cjson"
local syslog = require "posix.syslog"
local signal = require "posix.signal"
local stat = require "posix.sys.stat"

local rand = require "openssl.rand"
local pkey = require "openssl.pkey"
local x509 = require "openssl.x509"
local chain = require "openssl.x509.chain"
local sslctx = require "openssl.ssl.context"

local b = require "http.bit"
local http_util = require "http.util"
local http_version = require "http.version"
local http_headers = require "http.headers"
local http_server = require "http.server"
local http_ws = require "http.websocket"

-- constants
local server_info = string.format("%s/%s", http_version.name, http_version.version)
local uri_pattern = patterns.uri_reference * lpeg.P(-1)
local path_pattern = patterns.path * lpeg.P(-1)
local start_page = "/index.html"
local net_timeout = 10
local ping_timeout = 40

-- options
local debug_flag = false
local port = 443
local www_dir = "/opt/share/www"
local cert_file = "/opt/etc/ssl/certs/server.crt"
local chain_file = "/opt/etc/ssl/certs/ca.crt"
local key_file = "/opt/etc/ssl/private/server.key"
local ca_file = "/opt/etc/ssl/certs/ca-certificates.crt"
local log_file = "/tmp/luadrop.log"

-- common list of rooms and peers in every room
local room_list = {}

-- For compatibility with __ipairs() from Lua 5.2
local _source_ipairs = ipairs
ipairs = function(t)
	local metatable = getmetatable(t)
	if metatable and metatable.__ipairs then
		return metatable.__ipairs(t)
	end
	return _source_ipairs(t)
end

local function log(err, errno, msg, ...)
	local out = string.format(msg, ...)

	if err or errno then
		out = out .. string.format(" {%d, %s}", errno or 0, err or "*")
	end

	io.stderr:write(os.date("[%H:%M:%S] "), out, "\n")

	syslog.openlog("luadrop")
	syslog.syslog(syslog.LOG_USER + syslog.LOG_NOTICE, out)
	syslog.closelog()

	local fd = io.open(log_file, "a")
	if fd then
		fd:write(os.date("[%H:%M:%S] "), out, "\n")
		fd:close()
	end
end

local function gethostname(mode)
	local fd = assert(io.popen("/bin/hostname -" .. mode or "s"))
	local hostname = assert(fd:read("*a"))
	fd:close()
	return hostname:match("^%s*(.-)%s*$")
end

local function read_all(filename)
	local fd = assert(io.open(filename, "rb"))
	local data = assert(fd:read("*a"))
	fd:close()
	return data
end

local function check_dir(path)
	assert(path_pattern:match(path), "invalid path")
	local dir = http_util.resolve_relative_path(",/", path)
	assert(b.band(assert(stat.stat(dir)).st_mode, stat.S_IFDIR) ~= 0, dir .." not directory")
	return dir
end

local function check_file(path)
	assert(path_pattern:match(path), "invalid path")
	local file = http_util.resolve_relative_path(",/", path)
	assert(b.band(assert(stat.stat(file)).st_mode, stat.S_IFREG) ~= 0, file .. "not file")
	return file
end

local function get_options()
	for _, a in ipairs(arg) do
		if a:sub(1, 1) ~= "-" then
			www_dir = check_dir(a)
		elseif a:sub(2, 3) == "p=" then
			port = assert(tonumber(a:match("-p=(%d-)$")))
			assert(port > 0 and port < 65536)
		elseif a:sub(2, 3) == "c=" then
			cert_file = check_file(a:sub(4))
		elseif a:sub(2, 3) == "n=" then
			chain_file = check_file(a:sub(4))
		elseif a:sub(2, 3) == "k=" then
			key_file = check_file(a:sub(4))
		elseif a:sub(2, 3) == "a=" then
			ca_file = check_file(a:sub(4))
		elseif a:sub(2, 3) == "l=" then
			log_file = check_file(a:sub(4))
		elseif a:sub(2, 2) == "d" then
			debug_flag = true
		end
	end
end

local function read_key(filename)
	return assert(pkey.new(read_all(filename), "pem", "pr"))
end

local function read_crt(filename)
	return assert(x509.new(read_all(filename), "pem"))
end

local function alpn_select(ssl, protos, version)
	for _, proto in ipairs(protos) do
		if proto == "http/1.1" then
			return proto
		end
	end
	log(nil, nil, "ALPN selection failed")
	return nil
end

local function create_ctx(verify)
	local cert = read_crt(cert_file)
	local key = read_key(key_file)

	local chn
	if chain_file then
		chn = chain.new()
		local ca = read_crt(chain_file)
		chn:add(ca)
	end

	if ca_file then
		local store = require "openssl.x509.store"
		local st = store.new()
		st:add(ca_file)

		local ok, err, errno = st:verify(cert, chn)
		if not ok then
			log(err, errno, "Verification failed")
			return nil
		end

		log(nil, nil, "Verification successful")
		if debug_flag then
			for _, val in ipairs(err) do
				log(nil, nil, val:text())
			end
		end
	end

	local ctx = sslctx.new("TLS", true)
	if ctx.setAlpnSelect ~= nil then
		ctx:setAlpnSelect(alpn_select, 1.1)
	end
	ctx:setOptions(sslctx.OP_NO_COMPRESSION +
		sslctx.OP_NO_SSLv2 +
		sslctx.OP_NO_SSLv3 +
		sslctx.OP_NO_TLSv1 +
		sslctx.OP_NO_TLSv1_1)
	ctx:setCipherList("aECDSA:+AES256:+SHA384:!NULL")

	ctx:setPrivateKey(key)
	ctx:setCertificate(cert)
	ctx:setCertificateChain(chn)

	return ctx
end

----------------------------------------------------

-- return uuid of form xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
local function uuid_v4()
	return basexx.to_hex(rand.bytes(4)) .. "-" ..
		basexx.to_hex(rand.bytes(2)) .. "-4" ..
		basexx.to_hex(rand.bytes(2)):sub(1, 3) .. "-" ..
		string.format("%1X", rand.uniform(4) + 8) ..
		basexx.to_hex(rand.bytes(2)):sub(1, 3) .. "-" ..
		basexx.to_hex(rand.bytes(6))
end

local function unique_name_generator(room)
	local name
	local adjective_dict = { "Jamaican", "Afghan", "Nepalese", "Thai", "Space", "Moon",
		"African", "Colombian", "Mexican", "Hawaiian", "Northern", "Southern", "Western",
		"Eastern", "Sour", "Sweet", "Bitter", "Pungent", "Vanilla", "Sugar", "Exotic",
		"Unusual", "Colorful", "Glamorous", "Mysterious", "Strange", "Antic", "Dapper",
		"Graceful", "Jovial", "Quirky", "Witty" }
	local noun_dict = { "Fruit", "Berry", "Peanut", "Cherry", "Pineapple", "Banana",
		"Apple", "Pear", "Tangerine", "Orange", "Lemon", "Lime", "Cookies", "Cake", "Bread",
		"Pudding", "Gelato", "Cream", "Candy", "Fudge", "Chocolate", "Punch", "Pie", "Cereal",
		"Bubble", "Gum", "Cheese", "Coffe", "Mimosa", "Zkittlez", "Snack", "Munchie" }
	repeat
		name = adjective_dict[rand.uniform(#adjective_dict) + 1] .. " " ..
			noun_dict[rand.uniform(#noun_dict) + 1]
		for _, p in pairs(room_list[room] or {}) do
			if name == p.name.displayName then
				name = nil
				break
			end
		end
	until name

	return name
end

local function make_peer_name(agent, room)
	local type = "desktop"

	if agent:find("%sMobile") then
		type = "mobile"
	end
	if agent:find("iP[ao]d") or (type ~= "mobile" and agent:find("%sAndroid")) then
		type = "tablet"
	end

	local dict = { "compatible;", " Mobile[/%w%.]*", " Version/[%d%.]*", " Gecko[/%w%.]*",
		"%s[%w]-_[_%w]*", "%s[%w]-:[%w%.]*", "%s%a%a[%-]%a%a[^%a]", "%sCPU", "%sIntel",
		"%sBuild.-[%s;]", "%slike", "%sOS%s", "%s;", "%s+" }
	for _, i in ipairs(dict) do
		agent = agent:gsub("%s*" .. i .. "%s*", " ")
	end

	local model = agent:match("^.-%(%s*([%w%-%.]*)")
	local browser = agent:match("^.*%)%s*(%w*)")
	local os = agent:match("^.-%s*([_%-%w%s]-)%s*%)")

	local device
	if type == "desktop" and os and #os > 0 and browser and #browser > 0 then
		device = os .. " " .. browser
	else
		device = model or "Unknown device"
	end

	if debug_flag then
		log(nil, nil, "Type='%s' os='%s' model='%s' browser='%s' device='%s'",
			type, os or "", model or "", browser or "", device)
	end

	return {
		type = type,
		model = model,
		os = os,
		browser = browser,
		deviceName = device,
		displayName = unique_name_generator(room)
	}
end

local function create_peer(ws, stream, headers)
	local room

	-- try to get room name from request query
	local path = headers:get(":path")
	local uri = uri_pattern:match(path)
	if uri and uri.query then
		for name, val in http_util.query_args(uri.query) do
			if name == "room" then
				room = basexx.from_url64(val, false)
				break
			end
		end
	end

	if not room then
		-- by default we try to get room name from IP address
		local forward = headers:get("x-forwarded-for")
		if forward then
			room = forward:match("^%s*(%.%d)+%s*,")
		else
			room = select(2, stream:peername())
		end

		-- special hack for handling public IPv4
		if http_util.is_ip(room) and (room:find("^10%.%d+%.%d+%.%d+$") or
		room:find("^172%.%d+%.%d+%.%d+$") or room:find("^192%.168%.%d+%.%d+$")) then
			room = room:match("^(%d+%.%d+%.%d+%.)") .. "255"
		end
	end

	local cookie = headers:get("cookie")
	local id = select(3, string.find(cookie or "", "peerid=([%-%x]+)"))
	if not id or (room_list[room] and room_list[room][id]) then
		id = uuid_v4()
	end

	return {
		ws = ws,
		id = id,
		room = room,
		rtc = string.find(headers:get(":path"), "webrtc") ~= nil,
		name = make_peer_name(tostring(headers:get("user-agent")), room),
		get_info = function(self)
			return {
				id = self.id,
				name = self.name,
				rtcSupported = self.rtc
			}
		end
        }
end

local function send_msg(peer, msg)
	if peer.ws.readyState < 1 or peer.ws.readyState > 2 then
        	log("error", 0, "WebSocket for %s already closed", peer.id:sub(1, 8))
		return nil
	end

	local json_msg = json.encode(msg)
	if debug_flag then
		log(nil, nil, "send_msg(%s): %s", peer.id:sub(1, 8), json_msg)
	end

	local ok, err, errno = peer.ws:send(json_msg, "text", net_timeout)
	if not ok then
		log(err, errno, "Sending by WebSocket failed")
		return nil
	end
	return true
end

local function add_peer_to_room(peer)
	log(nil, nil, "Peer %s adding to room %s", peer.id:sub(1, 8), peer.room)

	local room = room_list[peer.room]
	if room then
		-- notify all other peers in the room
		for _, p in pairs(room) do
			send_msg(p, {
				type = "peer-joined",
				peer = peer:get_info()
			})
		end

		-- notify peer about the other peers in the room
		local peers = {}
		for _, p in pairs(room) do
			table.insert(peers, p:get_info())
		end
		if not send_msg(peer, {
			type = "peers",
			peers = peers
		}) then
			return nil
		end
	end

	-- if room does not exist yet, create it
	if not room_list[peer.room] then
		room_list[peer.room] = {}
	end

	-- add peer to room
	room_list[peer.room][peer.id] = peer

	-- send to peer its device and display names
	return send_msg(peer, {
		type = "display-name",
		message = {
			deviceName = peer.name.deviceName,
			displayName = peer.name.displayName,
			room = basexx.to_url64(peer.room)
		}
	})
end

local function remove_peer_from_room(peer)
	log(nil, nil, "Peer %s removing from room %s", peer.id:sub(1, 8), peer.room)

	-- room does not exist already
	if not room_list[peer.room] then
		return
	end

	-- remove the peer
	room_list[peer.room][peer.id] = nil

	-- if room is empty, also delete the whole room
	local room = room_list[peer.room]
	if not next(room) then
		room_list[peer.room] = nil
	else
		-- notify all other peers in the room
		for _, p in pairs(room) do
			send_msg(p, {
				type = "peer-left",
				peerId = peer.id
			})
		end
	end
end

local function serve_peer(peer)
	local last_beat = monotime()
	local ok, err, errno

	-- the loop handles all WebSocket activity
	repeat
		-- exit from loop on disappirance peer in common list
		if not room_list[peer.room] or not room_list[peer.room][peer.id] then
			return
		end

		-- do ping-pong for keeping WebSocket connection alive
		ok, err, errno = peer.ws:send_ping("Are you alive?")
		if not ok then
			log(err, errno, "Pinging WebSocket connection failed")
			return
		end

		-- keeping connection with browser application
		if monotime() > (last_beat + ping_timeout * 2) then
			log(nil, nil, "Timeout for answer from %s expired", peer.id:sub(1, 8))
			return
		elseif monotime() > (last_beat + ping_timeout) then
			if not send_msg(peer, { type = "ping" }) then
				return
			end
		end

		-- timeout for WebSocket ping-pong decreased to 10 sec 
		ok, err, errno = peer.ws:receive(net_timeout)
		if ok and err == "text" then
			local msg = assert(json.decode(ok))
			if type(msg) == "table" and msg["type"] then
				if msg.type == "disconnect" then
					-- peer left the room
					return
				elseif msg.type == "pong" then
					-- save time of answer from peer
					last_beat = monotime()
				elseif msg["to"] then
					-- try to relay the message to recipient
					local to = msg.to
					if room_list[peer.room] and room_list[peer.room][to] then
						msg.to = nil
						msg.sender = peer.id
						send_msg(room_list[peer.room][to], msg)
					end
				end
			end
		end
	until peer.ws.readyState < 1 or peer.ws.readyState > 2
		or (not ok and errno ~= cerr.ETIMEDOUT)

	log(err, errno, "WebSocket connection was lost")
end

local function accept_ws_connection(ws, stream, req_headers, res_headers)
	local peer = create_peer(ws, stream, req_headers)

	local cookie = req_headers:get("cookie")
	if not cookie or not cookie:find("peerid=") then
		res_headers:append("set-cookie", "peerid=" .. peer.id .. "; SameSite=Strict; Secure")
	end

	local ok, err, errno = ws:accept({ headers = res_headers }, net_timeout)
	if not ok then
		log(err, errno, "WebSocket connection not accepted")
		return
	end

	if add_peer_to_room(peer) then
		serve_peer(peer)
	end
	ws:close(nil, "end of work", net_timeout)

	remove_peer_from_room(peer)
end

----------------------------------------------------

local function get_mime_type(filename)
	local ext = filename:match("^.+%.(%w+)$")
	if not ext or ext == "" then
		return nil
	elseif ext == "html" or ext == "htm" then
		return "text/html"
	elseif ext == "css" then
		return "text/css"
	elseif ext == "js" then
		return "text/javascript"
	elseif ext == "json" then
		return "application/json"
	elseif ext == "jpg" or ext == "jpeg" then
		return "image/jpeg"
	elseif ext == "png" then
		return "image/png"
	elseif ext == "svg" then
		return "image/svg+xml"
	elseif ext == "mp3" then
		return "audio/mpeg"
	elseif ext == "ogg" then
		return "audio/ogg"
	end
	return nil
end

local function write_headers(stream, headers, eos)
	if debug_flag then
		local ip = select(2, stream:peername())
		for name, val in headers:each() do
			log(nil, nil, "%s %s: %s", ip, name, val)
		end
	end

	local ok, err, errno = stream:write_headers(headers, eos, net_timeout)
	if not ok then
		log(err, errno, "Writing headers failed")
		return true, true
	end
	return true
end

local function on_stream(server, stream) -- luacheck: ignore 212
	local req_headers, err, errno = stream:get_headers(net_timeout)
	if not req_headers then
		log(err, errno, "Reading headers failed")
		return true
	end

	if debug_flag then
		local ip = select(2, stream:peername())
		for name, val in req_headers:each() do
			log(nil, nil, "%s %s: %s", ip, name, val)
		end
	end
	
	local res_headers = http_headers.new()
	res_headers:append(":status", nil)
	res_headers:append("server", server_info)
	res_headers:append("date", http_util.imf_date())

	local req_method = req_headers:get(":method")
	if req_method == "OPTIONS" then
		res_headers:upsert(":status", "204")
		if req_headers:has("access-control-request-method") then
			res_headers:append("access-control-allow-methods", "OPTIONS, HEAD, GET")
			res_headers:append("access-control-allow-origin", "*")
			res_headers:append("access-control-allow-headers", "*")
			res_headers:append("access-control-max-age", "86400")
		else
			res_headers:append("allow", "OPTIONS, HEAD, GET")
			res_headers:append("cache-control", "max-age=86400")
		end
		return write_headers(stream, res_headers, true)
	end

	if req_method == "GET" then
		local ws_conn = http_ws.new_from_stream(stream, req_headers)
		if ws_conn then
			accept_ws_connection(ws_conn, stream, req_headers, res_headers)
			return true
		end
	end

	res_headers:append("cache-control", "max-age=86400")
	if req_method ~= "GET" and req_method ~= "HEAD" then
		res_headers:upsert(":status", "405")
		res_headers:append("allow", "OPTIONS, HEAD, GET")
		return write_headers(stream, res_headers, true)
	end

	local path = req_headers:get(":path")
	local uri = uri_pattern:match(path)
	if not uri then
		res_headers:upsert(":status", "404")
		return write_headers(stream, res_headers, true)
	end

	path = http_util.resolve_relative_path("/", uri.path)
	if path == "/" then
		path = start_page
		res_headers:append("content-location", path)
	end

	local mime_type = get_mime_type(path)
	if not mime_type then
		res_headers:upsert(":status", "415")
		return write_headers(stream, res_headers, true)
	end

	local real_path = www_dir .. path
	local fd, err, errno = io.open(real_path, "rb")
	if not fd then
		if errno == cerr.ENOENT then
			code = "404"
		elseif errno == cerr.EACCES then
			code = "403"
		else
			code = "422"
		end
		res_headers:upsert(":status", code)
		return write_headers(stream, res_headers, true)
	end

	res_headers:upsert(":status", "200")
	res_headers:append("content-type", mime_type)
	res_headers:append("access-control-allow-origin", "*")
	if req_method == "HEAD" then
		res_headers:append("content-length", tostring(fd:seek("end")))
	end
	_, err = write_headers(stream, res_headers, req_method == "HEAD")
	if not err and req_method == "GET" then
		local ok, err, errno = stream:write_body_from_file(fd, net_timeout)
		if not ok then
			log(err, errno, "Writing body failed")
		end
	end

	fd:close()
	return true
end

get_options()

local luadrop_server = assert(http_server.listen {
	tls = true,
	ctx = assert(create_ctx()),
	host = "0.0.0.0",
	port = port,
	version = 1.1,
	max_concurrent = 32,
	connection_setup_timeout = net_timeout,
	intra_stream_timeout = net_timeout,
	onstream = on_stream,
	onerror = function(server, context, op, err, errno) -- luacheck: ignore 212
		-- ignore this often error
		if op ~= "wrap" or not string.find(err or "", "starttls") or errno ~= cerr.EPIPE then
			local msg = string.format("%s on %s failed {%d, %s}",
				tostring(op), tostring(context), errno or 0, err or "")
			local tb = debug.traceback(msg, 2) .. "\n"
			for line in string.gfind(tb, ".-\n") do
				log(nil, nil, line)
			end
		end
	end
})

local function signal_handler(signum)
	local signame = ""

	-- get name of received signal
	for name, val in pairs(signal) do
		if type(val) == "number" and signum == val then
			signame = name
			break
		end
	end

	log(nil, nil, "Received signal %s, stopping server", signame)
	luadrop_server:pause()

	-- all peers will be removed from rooms
	room_list = {}

	luadrop_server:close()
end

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGQUIT, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

-- Manually call listen() so that we are bound before calling localname()
do
	local ok, err, errno = luadrop_server:listen(net_timeout)
	if not ok then
		log(err, errno, "Initialization failed")
		os.exit(1)
	end

	log(nil, nil, "Server '%s' started and listening on port %d",
		tostring(gethostname("d")),
		select(3, luadrop_server:localname()))
end

-- Start the main server loop
assert(luadrop_server:loop())

log(nil, nil, "Server terminated")
