defexception CookieJar.InvalidCookieError, [messages: "Unknown"] do
  def message(exception) do
    if is_list(exception.messages) do
      if Enum.empty?(exception.messages) do
        "Unknown"
      else
        Enum.join exception.messages, ", "
      end
    else
      if is_binary(exception.messages) do
        exception.messages
      else
        "Unknown"
      end
    end
  end
end

defmodule CookieJar.Validation do
  token = "[^(),\\/<>@;:\\\\\"\\[\\]?={}\\s]+"
  value1 = "([^;]*)"
  ipv4addr = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
  ipv6addr = "(?:(?:[a-fA-F\\d]{1,4}:)*(?:[a-fA-F\\d]{1,4}|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(?:(?:[a-fA-F\\d]{1,4}:)*[a-fA-F\\d]{1,4})?::(?:(?:[a-fA-F\\d]{1,4}:)*(?:[a-fA-F\\d]{1,4}|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}))?)"
  ipaddr = "(?:#{ipv4addr}|#{ipv6addr})"
  domlabel = "(?:[a-zA-Z\\d](?:[-a-zA-Z\\d]*[a-zA-Z\\d])?)"
  toplabel = "(?:[a-zA-Z](?:[-a-zA-Z\\d]*[a-zA-Z\\d])?)"

  quoted_pair = "\\\\[\\x00-\\x7F]"
  lws = "\\r\\n(?:[ \\t]+)"
  qdtext = "[\\t\\x20-\\x21\\x23-\\x7E\\x80-\\xFF]|(?:#{lws})"
  quoted_text = "\\\"(?:#{qdtext}|#{quoted_pair})*\\\""
  value2 = "#{token}|#{quoted_text}"

  base_hostname = Macro.escape %r/(?:#{domlabel}\.)(?:((?:(?:#{domlabel}\.)+(?:#{toplabel}\.?))|local))/
  base_path = Macro.escape %r/\A((?:[^\/?#]*\/)*)/
  ipaddr = Macro.escape %r/\A#{ipaddr}\Z/
  param1 = Macro.escape %r/\A(#{token})(?:=#{value1})?\Z/
  param2 = Macro.escape %r/(#{token})(?:=(#{value2}))?(?:\Z|;)/

  use DateTime

  def to_uri(uri) when is_record(uri, URI.Info) do
    uri.path(uri.path || "/")
  end

  def to_uri(request_uri) do
    to_uri URI.parse request_uri
  end

  def to_path(uri) when is_record(uri, URI.Info) or is_record(uri, CookieJar.Cookie) do
    uri.path
  end

  def to_path(path) do
    path
  end

  def to_domain(uri) when is_record(uri, URI.Info) do
    uri.host
  end

  def to_domain(cookie) when is_record(cookie, CookieJar.Cookie) do
    cookie.domain
  end

  def to_domain(domain), do: domain

  def effective_host(host_or_uri) do
    hostname = String.downcase to_domain host_or_uri

    if hostname =~ %r/.[\.:]./ || hostname == ".local" do
      hostname
    else
      hostname <> ".local"
    end
  end

  def hostname_reach(hostname) do
    host = String.downcase to_domain hostname
    match = Regex.run(unquote(base_hostname), host)
    if match do
      Enum.at match, 1
    end
  end

  def compute_search_domain_for_host(host) do
    host = effective_host host
    result = [host]

    if !(host =~ unquote(ipaddr)) do
      result = [".#{host}" | result]

      base = hostname_reach host
      if base do
        result = [".#{base}" | result]
      end
    end

    result
  end

  def domains_match(tested_domain, base_domain) do
    Enum.find compute_search_domain_for_host(effective_host base_domain), fn(domain) -> domain == tested_domain end
  end

  def cookie_base_path(path) do
    Enum.at Regex.run(unquote(base_path), to_path path), 1
  end

  def determine_cookie_path(request_uri, cookie_path) do
    uri = to_uri request_uri
    cookie_path = to_path cookie_path

    if nil?(cookie_path) || String.length(cookie_path) == 0 do
      cookie_path = cookie_base_path uri.path
    end
    cookie_path
  end

  def compute_search_domains(request_uri) do
    compute_search_domain_for_host to_uri(request_uri).host
  end

  def determine_cookie_domain(request_uri, cookie_domain) do
    uri = to_uri request_uri
    domain = to_domain cookie_domain

    if nil?(domain) || String.length(domain) == 0 do
      effective_host uri.host
    else
      domain = String.downcase domain
      if domain =~ unquote(ipaddr) || String.starts_with? domain, "." do
        domain
      else
        ".#{domain}"
      end
    end
  end

  def validate_cookie(request_uri, cookie) do
    uri = to_uri request_uri
    request_path = uri.path
    cookie_host = cookie.domain
    cookie_path = cookie.path

    errors = []

    unless cookie.version do
      errors = ["Version missing" | errors]
    end

    unless String.starts_with? request_path, cookie_path do
      errors = ["Path is not a prefix of the request uri path" | errors]
    end

    unless cookie_host =~ unquote(ipaddr) || cookie_host =~ %r/.\../ || cookie_host == ".local" do
      errors = ["Domain format is illegal" | errors]
    end

    unless domains_match cookie_host, uri do
      errors = ["Domain is inappropriate based on request URI hostname" | errors]
    end

    unless nil?(cookie.ports) || Enum.count(cookie.ports) != 0 do
      unless Enum.find_index cookie.ports, uri.port do
        errors = ["Ports list does not contain request URI port" | errors]
      end
    end

    unless Enum.empty? errors do
      raise CookieJar.InvalidCookieError, messages: errors
    end

    true
  end

  def value_to_string(value) when is_binary(value) do
    matches = Regex.run(%r/\A"(.*)"\Z/, value)
    if matches do
      value = Enum.at matches, 1
      Regex.replace(%r/\\(.)/, value, "\\1")
    else
      value
    end
  end

  def value_to_string(x), do: x

  def decode_value(value) do
    if value =~ %r/\A"(.*)"\Z/ do
      value_to_string value
    else
      URI.decode value
    end
  end

  def parse_set_cookie(set_cookie_value) do
    [kv | params] = Regex.split(%r/;\s*/, set_cookie_value)
    [_, name, value] = Regex.run(unquote(param1), kv)

    args = Enum.reduce params, [name: name, value: value], fn(param, args) ->
      result = Regex.run(unquote(param1), param)

      unless result do
        raise CookieJar.InvalidCookieError, messages: "Invalid cookie parameter in cookie '#{set_cookie_value}'"
      end

      key = String.downcase(Enum.at result, 1)
      value = Enum.at result, 2

      case key do
        "expires" ->
          Keyword.put args, :expires_at, DateTime.timezone(%t"#{value}", "UTC")
        "domain" ->
          Keyword.put args, :domain, value
        "path" ->
          Keyword.put args, :path, value
        "secure" ->
          Keyword.put args, :secure, true
        "httponly" ->
          Keyword.put args, :http_only, true
        _ ->
          raise CookieJar.InvalidCookieError, messages: "Unknown cookie parameters '#{key}'"
      end
    end

    Keyword.put args, :version, 0
  end

  defp split_set_cookie2(set_cookie_value) do
    split_set_cookie2(set_cookie_value, [])
  end

  defp split_set_cookie2("", res), do: Enum.reverse res

  defp split_set_cookie2(set_cookie_value, args) do
    md = Regex.run(unquote(param2), set_cookie_value, return: :index)

    if nil?(md) || elem(Enum.first(md), 0) != 0 do
      raise CookieJar.InvalidCookieError, messages: "Invalid Set-Cookie2 header '#{set_cookie_value}'"
    end

    matches = Regex.run(unquote(param2), set_cookie_value)
    key = Enum.at matches, 1
    value = Enum.at(matches, 2) || Enum.at(matches, 3)
    index = elem(Enum.first(md), 1)
    split_set_cookie2(String.slice(set_cookie_value, index, String.length(set_cookie_value) - index), [{key, value} | args])
  end

  def parse_set_cookie2(set_cookie_value) do
    [{name, value} | params] = split_set_cookie2(set_cookie_value)
    args = Enum.reduce params, [name: name, value: value], fn({ key, value }, args) ->
      value = value_to_string value

      case String.downcase key do
        x when x in ["comment", "commenturl", "domain", "path"] ->
          Keyword.put args, binary_to_atom(x), value
        x when x in ["discard", "secure"] ->
          Keyword.put args, binary_to_atom(x), true
        "httponly" ->
          Keyword.put args, :http_only, true
        "max-age" ->
          Keyword.put args, :max_age, binary_to_integer(value)
        "version" ->
          Keyword.put args, :version, binary_to_integer(value)
        "port" ->
          ports = Regex.split(%r/,\s*/, value)
          Keyword.put args, :ports, Enum.map(ports, fn(port) -> binary_to_integer(port) end)
        _ ->
          raise CookieJar.InvalidCookieError, messages: "Unknown cookie parameter '#{key}'"
      end
    end

    if args[:version] != 1 do
      raise CookieJar.InvalidCookieError, messages: "Set-Cookie2 declares a non RFC2965 version cookie"
    end

    args
  end
end
