package = "luadrop"
version = "0.1-1"

description = {
	summary = "Luadrop HTTPS and WebSocket server",
	homepage = "https://github.com/worknd/Luadrop",
	license = "MIT"
}

source = {
	dir = "Luadrop-0.1/server",
	url = "https://github.com/worknd/Luadrop/archive/refs/tags/0.1.zip",
	tag = "v0.1"
}

dependencies = {
	"lua >= 5.1",
	"http >= 0.4",
	"luaposix >= 36",
	"lua-cjson >= 2.1"
}

build = {
	type = "builtin",
	install = {
		lua = {
			luadrop = "luadrop.lua";
		}
	}
}
