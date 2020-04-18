@load base/frameworks/sumstats

global a:set[addr];
global b:set[addr];
global all: table[addr] of double;
global err: table[addr] of double;
global uri: table[addr] of set[string];
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream = "all response", $apply = set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream = "404 response", $apply = set(SumStats::SUM));
    SumStats::create([$name="all response",
                      $epoch=10mins,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["all response"];
                        if (!(key$host in a))
						{
							add a[key$host];
							all[key$host] = r$sum;
							uri[key$host] = set();
						}
						else
							all[key$host] = all[key$host] + r$sum;
						if (!(key$str in uri[key$host]))
							add uri[key$host][key$str];
                        }]);
    
    SumStats::create([$name="404 response",
                      $epoch=10mins,
                      $reducers=set(r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["404 response"];
                        if (!(key$host in b))
						{
							add b[key$host];
							err[key$host] = r$sum;
						}
						else
							err[key$host] = err[key$host] + r$sum;
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason:string)
	{
	SumStats::observe("all response", SumStats::Key($host=c$id$orig_h, $str=c$http$uri), SumStats::Observation($num=1));
	if (code == 404)
		SumStats::observe("404 response", SumStats::Key($host=c$id$orig_h, $str=c$http$uri), SumStats::Observation($num=1));
	}

event zeek_done()
	{
	for (i in a)
	{
		if (err[i] > 2)
			if (err[i] / all[i] > 0.2)
				if (|uri[i]|/err[i] > 0.5)
					print fmt("%s is a scanner with %.0f scan attemps on %d urls", i, err[i], |uri[i]|);
	}
	}
