global codeTable: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string){
	# 如果table中相同addr的User-Agent在set中存在多个，则说明使用了代理
	if (c$id$orig_h in codeTable){
		if( c$http ?$ user_agent ){
			add codeTable[c$id$orig_h][to_lower(c$http$user_agent)];
		}
	}else {
		codeTable[c$id$orig_h] = set();
		if( c$http ?$ user_agent ){
			add codeTable[c$id$orig_h][to_lower(c$http$user_agent)];
		}
	}
}

event zeek_done(){
	for( address in codeTable){
		if (|codeTable[address]| >= 2){
			print fmt("%s is a proxy", address);
		}
	}
}
