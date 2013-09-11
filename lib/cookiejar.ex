defrecord CookieJar, domains: HashDict.new do
  import CookieJar.Validation, only: [to_uri: 1]

  alias CookieJar.Validation
  alias CookieJar.Cookie
  alias CookieJar.InvalidCookieError

  defp find_or_add_domain_for_cookie(jar, cookie) do
    domains = Dict.put_new jar.domains, cookie.domain, HashDict.new
    jar.domains(domains)
  end

  defp add_cookie_to_path(jar, cookie) do
    paths = Dict.fetch!(jar.domains, cookie.domain)
    path_entry = Dict.get paths, cookie.path, HashDict.new
    path_entry = Dict.put path_entry, cookie.name, cookie
    paths = Dict.put paths, cookie.path, path_entry
    domains = Dict.put jar.domains, cookie.domain, paths
    jar.domains(domains)
  end

  def add_cookie(cookie, jar) do
    find_or_add_domain_for_cookie(jar, cookie) |> add_cookie_to_path(cookie)
  end

  def set_cookie(request_uri, cookie_header_values, jar) do
    Enum.reduce Regex.split(%r/, (?=[\w]+=)/, cookie_header_values), jar, fn(cookie_header_value, acc) ->
      acc.add_cookie(Cookie.from_set_cookie request_uri, cookie_header_value)
    end
  end

  def set_cookie2(request_uri, cookie_header_value, jar) do
    jar.add_cookie(Cookie.from_set_cookie2 request_uri, cookie_header_value)
  end

  def set_cookies_from_headers(request_uri, http_headers, jar) do
    jar2 = Enum.reduce http_headers, CookieJar.new, fn({ key, value }, acc) ->
      cond do
        key =~ %r/\ASet-Cookie\Z/i ->
          value = if is_list(value), do: value, else: [value]
          Enum.reduce value, acc, fn(value, acc) ->
            try do
              acc.add_cookie(Cookie.from_set_cookie request_uri, value)
            rescue
              InvalidCookieError ->
                acc
            end
          end
        key =~ %r/\ASet-Cookie2\Z/i ->
          value = if is_list(value), do: value, else: [value]
          Enum.reduce value, acc, fn(value, acc) ->
            try do
              acc.add_cookie(Cookie.from_set_cookie2 request_uri, value)
            rescue
              InvalidCookieError ->
                acc
            end
          end
        true ->
          acc
      end
    end

    Enum.reduce jar2, jar, fn(cookie, acc) ->
      acc.add_cookie cookie
    end
  end

  def from_list(cookies) do
    Enum.reduce cookies, new, fn(cookie, jar) ->
      jar.add_cookie cookie
    end
  end

  def get_cookies(request_uri, opts // [], jar) do
    uri = to_uri request_uri
    hosts = Validation.compute_search_domains uri

    res = Enum.reduce hosts, [], fn(host, acc1) ->
      Enum.reduce Dict.get(jar.domains, host, []), acc1, fn({ path, cookies }, acc2) ->
        if String.starts_with? uri.path, path do
          acc2 ++ Enum.filter Dict.values(cookies), fn(cookie) ->
            cookie.should_send? uri, opts[:script]
          end
        else
          acc2
        end
      end
    end
    Enum.sort res, fn(x, y) -> String.length(x.path) >= String.length(y.path) end
  end

  def get_cookie_header(request_uri, opts // [], jar) do
    cookies = jar.get_cookies request_uri, opts
    ver = Enum.partition cookies, fn(cookie) ->
      cookie.version == 0
    end

    case ver do
      { _, [] } ->
        Enum.map(cookies, &to_string/1) |> Enum.join ";"
      _ ->
        res = if Enum.empty? elem(ver, 0) do
          ""
        else
          "$Version=0;" <> Enum.join(Enum.map(elem(ver, 0), fn(cookie) ->
            cookie.to_string 1, false
          end), ";") <> ","
        end

        res = res <> "$Version=1;"

        res <> Enum.join(Enum.map(elem(ver, 1), fn(cookie) ->
          cookie.to_string 1, false
        end), "")
    end
  end

  def expire_cookies(session // false, jar) do
    domains = Enum.reduce jar.domains, jar.domains, fn({ domain, paths }, domains) ->
      paths = Enum.reduce paths, paths, fn({ path, cookies }, paths) ->
        cookies = Enum.reduce cookies, cookies, fn({ name, cookie }, cookies) ->
          if cookie.expired? || (session && cookie.session?) do
            Dict.delete cookies, name
          else
            cookies
          end
        end

        if Enum.empty? cookies do
          Dict.delete paths, path
        else
          Dict.put paths, path, cookies
        end
      end

      if Enum.empty? paths do
        Dict.delete domains, domain
      else
        Dict.put domains, domain, paths
      end
    end
    jar.domains(domains)
  end
end

defimpl Enumerable, for: CookieJar do
  def count(jar) do
    Enum.reduce jar, 0, fn(_, acc) ->
      acc + 1
    end
  end

  def member?(jar, value) do
    Enum.any? jar, fn(cookie) ->
      cookie == value
    end
  end

  def reduce(jar, acc, fun) do
    Enum.reduce Dict.values(jar.domains), acc, fn(paths, acc1) ->
      Enum.reduce Dict.values(paths), acc1, fn(cookies, acc2) ->
        Enum.reduce cookies, acc2, fn({ _, cookie }, acc3) ->
          fun.(cookie, acc3)
        end
      end
    end
  end
end
