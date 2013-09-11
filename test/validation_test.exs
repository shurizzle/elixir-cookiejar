defmodule ValidationTest do
  use ExUnit.Case

  alias CookieJar.Cookie
  alias CookieJar.Validation
  alias CookieJar.InvalidCookieError

  localaddr = "http://localhost/foo/bar/"

  test "should fail if version unset" do
    assert_raise InvalidCookieError, fn ->
      unversioned = Cookie.from_set_cookie unquote(localaddr), "foo=bar"
      unversioned = unversioned.version(nil)
      Validation.validate_cookie unquote(localaddr), unversioned
    end
  end

  test "should fail if the path is more specific" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie unquote(localaddr), "foo=bar;path=/foo/bar/baz"
    end
  end

  test "should fail if the path is different than the request" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie unquote(localaddr), "foo=bar;path=/baz/"
    end
  end

  test "should fail if the domain has no dots" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie "http://zero/", "foo=bar;domain=zero"
    end
  end

  test "should fail for explicit localhost" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie unquote(localaddr), "foo=bar;domain=localhost"
    end
  end

  test "should fail for mismatched domains" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie "http://www.foo.com/", "foo=bar;domain=bar.com"
    end
  end

  test "should fail for domains more than one level up" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie "http://x.y.z.com/", "foo=bar;domain=z.com"
    end
  end

  test "should fail for setting subdomain cookies" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie "http://foo.com/", "foo=bar;domain=auth.foo.com"
    end
  end

  test "should handle a normal implicit internet cookie" do
    normal = Cookie.from_set_cookie "http://foo.com/", "foo=bar"
    assert(Validation.validate_cookie "http://foo.com/", normal)
  end

  test "should handle a normal implicit localhost cookie" do
    localhost = Cookie.from_set_cookie "http://localhost/", "foo=bar"
    assert(Validation.validate_cookie "http://localhost/", localhost)
  end

  test "should handle an implicit IP address cookie" do
    ipaddr = Cookie.from_set_cookie "http://127.0.0.1/", "foo=bar"
    assert(Validation.validate_cookie "http://127.0.0.1/", ipaddr)
  end

  test "should handle an explicit domain on an internet site" do
    explicit = Cookie.from_set_cookie "http://foo.com/", "foo=bar;domain=.foo.com"
    assert(Validation.validate_cookie "http://foo.com/", explicit)
  end

  test "should handle setting a cookie explicitly on a superdomain" do
    superdomain = Cookie.from_set_cookie "http://auth.foo.com/", "foo=bar;domain=.foo.com"
    assert(Validation.validate_cookie "http://foo.com/", superdomain)
  end

  test "should handle explicitly setting a cookie" do
    explicit = Cookie.from_set_cookie "http://foo.com/bar/", "foo=bar;path=/bar/"
    assert(Validation.validate_cookie "http://foo.com/bar/", explicit)
  end

  test "should handle setting a cookie on a higher path" do
    higher = Cookie.from_set_cookie "http://foo.com/bar/baz/", "foo=bar;path=/bar/"
    assert(Validation.validate_cookie "http://foo.com/bar/baz/", higher)
  end

  test "should leave '/' alone" do
    assert(Validation.cookie_base_path("/") == "/")
  end

  test "should strip off everything after the last '/'" do
    assert(Validation.cookie_base_path("/foo/bar/baz") == "/foo/bar/")
  end

  test "should handle query parameters and fragments with slashes" do
    assert(Validation.cookie_base_path("/foo/bar?query=a/b/c#fragment/b/c") == "/foo/")
  end

  test "Validation.cookie_base_path should handle URI objects" do
    assert(Validation.cookie_base_path(URI.parse "http://www.foo.com/bar/") == "/bar/")
  end

  test "should preserve case" do
    assert(Validation.cookie_base_path("/BaR/") == "/BaR/")
  end

  test "should use the requested path when none is specified for the cookie" do
    assert(Validation.determine_cookie_path("http://foo.com/", nil) == "/")
    assert(Validation.determine_cookie_path("http://foo.com/bar/baz", "") == "/bar/")
  end

  test "Validation.determine_cookie_path should handle URI objects" do
    assert(Validation.determine_cookie_path(URI.parse("http://foo.com/bar/"), "") == "/bar/")
  end

  test "Validation.determine_cookie_path should handle Cookie objects" do
    cookie = Cookie.from_set_cookie("http://foo.com/", "name=value;path=/")
    assert(Validation.determine_cookie_path("http://foo.com/", cookie) == "/")
  end

  test "should ignore the request when a path is specified" do
    assert(Validation.determine_cookie_path("http://foo.com/ignorable/path", "/path/") == "/path/")
  end

  test "should handle subdomains" do
    assert(Validation.compute_search_domains("http://www.auth.foo.com/") == [".auth.foo.com", ".www.auth.foo.com", "www.auth.foo.com"])
  end

  test "should handle root domains" do
    assert(Validation.compute_search_domains("http://foo.com/") == [".foo.com", "foo.com"])
  end

  test "should handle hexadecimal TLDs" do
    assert(Validation.compute_search_domains("http://tiny.cc/") == [".tiny.cc", "tiny.cc"])
  end

  test "should handle IP addresses" do
    assert(Validation.compute_search_domains("http://127.0.0.1/") == ["127.0.0.1"])
  end

  test "should handle local addresses" do
    assert(Validation.compute_search_domains("http://zero/") == [".local", ".zero.local", "zero.local"])
  end

  test "should add a dot to the front of domains" do
    assert(Validation.determine_cookie_domain("http://foo.com/", "foo.com") == ".foo.com")
  end

  test "should not add a second dot if one present" do
    assert(Validation.determine_cookie_domain("http://foo.com/", ".foo.com") == ".foo.com")
  end

  test "Validation.determine_cookie_domain should handle Cookie objects" do
    cookie = Cookie.from_set_cookie("http://foo.com/", "foo=bar;domain=foo.com")
    assert(Validation.determine_cookie_domain("http://foo.com/", cookie) == ".foo.com")
  end

  test "Validation.determine_cookie_domain should handle URI objects" do
    assert(Validation.determine_cookie_domain(URI.parse("http://foo.com/"), ".foo.com") == ".foo.com")
  end

  test "should use an exact hostname when no domain specified" do
    assert(Validation.determine_cookie_domain("http://foo.com/", "") == "foo.com")
  end

  test "should leave IPv4 addresses alone" do
    assert(Validation.determine_cookie_domain("http://127.0.0.1/", "127.0.0.1") == "127.0.0.1")
  end

  test "should leave IPv6 addresses alone" do
    assert(Validation.determine_cookie_domain("http://[2001:db8:85a3::8a2e:370:7334]/", "2001:db8:85a3::8a2e:370:7334") == "2001:db8:85a3::8a2e:370:7334")
    assert(Validation.determine_cookie_domain("http://[::ffff:192.0.2.128]/", "::ffff:192.0.2.128") == "::ffff:192.0.2.128")
  end

  test "should leave proper domains the same" do
    assert(Validation.effective_host("google.com") == "google.com")
    assert(Validation.effective_host("www.google.com") == "www.google.com")
    assert(Validation.effective_host("google.com.") == "google.com.")
  end

  test "Validation.effective_host should handle a URI object" do
    assert(Validation.effective_host(URI.parse("http://example.com/")) == "example.com")
  end

  test "should add a local suffix on unqualified hosts" do
    assert(Validation.effective_host("localhost") == "localhost.local")
  end

  test "Validation.effective_host should leave IPv4 addresses alone" do
    assert(Validation.effective_host("127.0.0.1") == "127.0.0.1")
  end

  test "Validation.effective_host should leave IPv6 addresses alone" do
    assert(Validation.effective_host("2001:db8:85a3::8a2e:370:7334") == "2001:db8:85a3::8a2e:370:7334")
    assert(Validation.effective_host(":ffff:192.0.2.128") == ":ffff:192.0.2.128")
  end

  test "should lowercase addresses" do
    assert(Validation.effective_host("FOO.COM") == "foo.com")
  end

  test "should handle exact matches" do
    assert(Validation.domains_match("localhost.local", "localhost.local") == "localhost.local")
    assert(Validation.domains_match("foo.com", "foo.com") == "foo.com")
    assert(Validation.domains_match("127.0.0.1", "127.0.0.1") == "127.0.0.1")
    assert(Validation.domains_match("::ffff:192.0.2.128", "::ffff:192.0.2.128") == "::ffff:192.0.2.128")
  end

  test "should handle matching a superdomain" do
    assert(Validation.domains_match(".foo.com", "auth.foo.com") == ".foo.com")
    assert(Validation.domains_match(".y.z.foo.com", "x.y.z.foo.com") == ".y.z.foo.com")
  end

  test "should not match superdomains, or illegal domains" do
    assert(Validation.domains_match(".z.foo.com", "x.y.z.foo.com") == nil)
    assert(Validation.domains_match("foo.com", "com") == nil)
  end

  test "should not match domains with and without a dot suffix together" do
    assert(Validation.domains_match("foo.com.", "foo.com") == nil)
  end

  test "should find the nex highest subdomain" do
    assert(Validation.hostname_reach("www.google.com") == "google.com")
    assert(Validation.hostname_reach("auth.corp.companyx.com") == "corp.companyx.com")
  end

  test "should handle domains with suffixed dots" do
    assert(Validation.hostname_reach("www.google.com.") == "google.com.")
  end

  test "should return nil for a root domain" do
    assert(Validation.hostname_reach("github.com") == nil)
  end

  test "should return 'local' for a local domain" do
    assert(Validation.hostname_reach("foo.local") == "local")
    assert(Validation.hostname_reach("foo.local.") == "local")
  end

  test "should handle mixed-case '.local'" do
    assert(Validation.hostname_reach("foo.LOCAL") == "local")
  end

  test "should return nil for an IPv4 address" do
    assert(Validation.hostname_reach("127.0.0.1") == nil)
  end

  test "should return nil for IPv6 addresses" do
    assert(Validation.hostname_reach("2001:db8:85a3::8a2e:370:7334") == nil)
    assert(Validation.hostname_reach("::ffff:192.0.2.128") == nil)
  end
end
