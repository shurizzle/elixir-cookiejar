defrecord CookieJar.Cookie, [name: nil, value: nil, domain: nil, path: nil,
  secure: false, http_only: false, version: nil, comment: nil, comment_url: nil,
  discard: nil, ports: nil, created_at: nil, expiry: nil] do

  alias CookieJar.Validation

  def expires_at(cookie) do
    if nil?(cookie.expiry) do
      cookie.expiry
    else
      case cookie.expiry do
        {{ _, _, _ }, { _, _, _ }} ->
          cookie.expiry
        _ ->
          DateTime.plus(cookie.created_at, second: cookie.expiry)
      end
    end
  end

  def expired?(time // DateTime.now, cookie) do
    expires_at = cookie.expires_at
    !nil?(expires_at) && time > expires_at
  end

  def session?(cookie) do
    !!(nil?(cookie.expiry) || cookie.discard)
  end

  def init(args) do
    created_at = Keyword.get args, :created_at, DateTime.now
    name = args[:name]
    value = args[:value]
    domain = args[:domain]
    path = args[:path]
    secure = Keyword.get args, :secure, false
    http_only = Keyword.get args, :http_only, false
    version = args[:version]
    comment = args[:comment]
    comment_url = args[:comment_url]
    discard = Keyword.get args, :discard, false
    ports = args[:ports]

    expiry = args[:max_age] || args[:expires_at]

    if is_integer(ports) do
      ports = [ports]
    end

    new(created_at: created_at, name: name, value: value, domain: domain,
      path: path, secure: secure, http_only: http_only, version: version,
      comment: comment, comment_url: comment_url, discard: discard,
      ports: ports, expiry: expiry)
  end

  def from_set_cookie(request_uri, set_cookie_value) do
    args = Validation.parse_set_cookie set_cookie_value
    args = Keyword.put args, :domain, Validation.determine_cookie_domain(request_uri, args[:domain])
    args = Keyword.put args, :path, Validation.determine_cookie_path(request_uri, args[:path])
    cookie = init(args)
    Validation.validate_cookie request_uri, cookie
    cookie
  end

  def from_set_cookie2(request_uri, set_cookie_value) do
    args = Validation.parse_set_cookie2 set_cookie_value
    args = Keyword.put args, :domain, Validation.determine_cookie_domain(request_uri, args[:domain])
    args = Keyword.put args, :path, Validation.determine_cookie_path(request_uri, args[:path])
    cookie = init(args)
    Validation.validate_cookie request_uri, cookie
    cookie
  end

  def should_send?(request_uri, script, cookie) do
    uri = Validation.to_uri request_uri

    String.starts_with?(uri.path, cookie.path) && !(cookie.secure && uri.scheme == "http") &&
      !(script && cookie.http_only) && !cookie.expired? &&
      (nil?(cookie.ports) || Enum.member?(cookie.ports, uri.port))
  end

  def decoded_value(cookie) do
    Validation.decode_value cookie.value
  end

  def to_string(ver // 0, prefix // true, cookie) do
    case ver do
      0 ->
        "#{cookie.name}=#{cookie.value}"
      1 ->
        str = if prefix, do: "$Version=#{cookie.version};", else: ""
        str = str <> "#{cookie.name}=#{cookie.value};$Path=\"#{cookie.path}\""
        if String.starts_with? cookie.domain, "." do
          str = str <> ";$Domain=#{cookie.domain}"
        end
        if cookie.ports do
          str = str <> ";$Port=\"#{Enum.join cookie.ports, ","}\""
        end
        str
    end
  end
end

defimpl String.Chars, for: CookieJar.Cookie do
  def to_string(cookie), do: cookie.to_string
end
