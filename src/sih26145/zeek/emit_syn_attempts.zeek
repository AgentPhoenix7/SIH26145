## Emit originator TCP SYN observations as a bounded versioned JSONL stream.

module SIH26145;

global emitted_events: count = 0;
global last_event_ts: time = double_to_time(0.0);

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	if ( ! pkt$is_orig )
		return;

	local ts = network_time();
	local entry: table[string] of any = {
		["schema_version"] = "tcp_syn_attempt_v1",
		["event_type"] = "tcp_syn_attempt",
		["ts"] = ts,
		["uid"] = c$uid,
		["src_ip"] = c$id$orig_h,
		["src_port"] = port_to_count(c$id$orig_p),
		["dst_ip"] = c$id$resp_h,
		["dst_port"] = port_to_count(c$id$resp_p),
		["transport"] = "tcp"
	} &ordered;

	print to_json(entry);
	flush_all();
	emitted_events += 1;
	last_event_ts = ts;
	}

event zeek_done() &priority=-100
	{
	local entry: table[string] of any = {
		["schema_version"] = "control_v1",
		["event_type"] = "end_of_stream",
		["emitted_events"] = emitted_events
	} &ordered;

	if ( emitted_events > 0 )
		entry["last_event_ts"] = last_event_ts;

	print to_json(entry);
	flush_all();
	}
