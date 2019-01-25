function FindProxyForURL(url,host)
{
	if (isInNet(host, "{{ INTERNAL_NETWORK }}",  "{{ INTERNAL_LONGMASK }}") ||
	    isInNet(host, "127.0.0.1", "255.255.255.255") ||
	    dnsDomainIs(host, "{{ INTERNAL_DOMAIN }}") ||
	    (url.substring (0, 5) == "feed:"))
	{
	    return "DIRECT";
	}
	else{
	    return "PROXY {{ PROXY_HOST }}:{{ PROXY_HTTP_PORT }}";
	}
}
