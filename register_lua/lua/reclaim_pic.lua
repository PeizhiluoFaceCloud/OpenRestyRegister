#!/usr/local/openresty/luajit/bin/luajit-2.1.0-alpha

--(һ��=3600*24=)
local delay_interval = 86400 

local handler = nil
handler = function ()
	--���մ���
	os.execute("find /xm_workspace/xmcloud3.0/_images/ -atime -3 | xargs rm -rf")

	--������ʱ��
	local ok, err = ngx.timer.at(delay_interval, handler)
	if not ok then
		ngx.log(ngx.ERR, "failed to startup reclaim alarm timer...", err)
	end
	print("----------------------restart timer--------------------------->")
end

--�������(����ʱִֻ��һ��)
--��ֻ֤��һ������ʵ��
local ok = ngx.shared.shared_data:add("start_timer_flag",1)
if ok then
	print("start_timer_flag")
	local ok, err = ngx.timer.at(delay_interval, handler)
	if not ok then
		ngx.log(ngx.ERR, "failed to start_timer_flag...", err)
	end
else
	print("do not start timer")
end

