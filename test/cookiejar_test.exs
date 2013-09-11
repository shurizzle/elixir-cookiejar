defmodule CookieJarTest do
  use ExUnit.Case

  test "should allow me to set a cookie" do
    CookieJar.new.set_cookie "http://foo.com/", "foo=bar"
  end

  test "should allow me to set multiple cookies" do
    jar = CookieJar.new

    jar = jar.set_cookie "http://foo.com/", "foo=bar"
    jar = jar.set_cookie "http://foo.com/", "bar=baz"
    jar = jar.set_cookie "http://auth.foo.com/", "foo=bar"
    jar.set_cookie "http://auth.foo.com/", "auth=135121...;domain=foo.com"
  end

  test "should allow me to set multiple cookies in 1 header" do
    jar = CookieJar.new
    jar.set_cookie "http://foo.com/", "my_cookie=123456; Domain=foo.com; expires=Thu, 31 Dec 2037 23:59:59 GMT; Path=/, other_cookie=helloworld; Domain=foo.com; expires=Thu, 31 Dec 2037 23:59:59 GMT, last_cookie=098765"
  end

  test "should let me read back cookies which are set" do
    jar = CookieJar.new
    jar = jar.set_cookie "http://foo.com/", "foo=bar"
    jar = jar.set_cookie "http://foo.com/", "bar=baz"
    jar = jar.set_cookie "http://auth.foo.com/", "foo=bar"
    jar = jar.set_cookie "http://auth.foo.com/", "auth=135121...;domain=foo.com"

    assert(Enum.count(jar.get_cookies("http://foo.com/")) == 3)
  end

  test "should let me read back a multiple cookies from 1 header" do
    jar = CookieJar.new
    jar = jar.set_cookie "http://foo.com/", "my_cookie=123456; Domain=foo.com; expires=Thu, 31 Dec 2037 23:59:59 GMT; Path=/, other_cookie=helloworld; Domain=foo.com; expires=Thu, 31 Dec 2037 23:59:59 GMT, last_cookie=098765"
    assert(jar.get_cookie_header("http://foo.com/") == "my_cookie=123456;other_cookie=helloworld;last_cookie=098765")
  end

  test "should return cookies longest path first" do
    jar = CookieJar.new
    uri = "http://foo.com/a/b/c/d"

    jar = jar.set_cookie uri, "a=bar"
    jar = jar.set_cookie uri, "b=baz;path=/a/b/c/d"
    jar = jar.set_cookie uri, "c=bar;path=/a/b"
    jar = jar.set_cookie uri, "d=bar;path=/a"

    cookies = jar.get_cookies(uri)

    assert(Enum.count(cookies) == 4)
    assert(Enum.at(cookies, 0).name == "b")
    assert(Enum.at(cookies, 1).name == "a")
    assert(Enum.at(cookies, 2).name == "c")
    assert(Enum.at(cookies, 3).name == "d")
  end

  test "should not return expired cookies" do
    jar = CookieJar.new
    uri = "http://localhost/"

    jar = jar.set_cookie uri, "foo=bar;expires=Wednesday, 09-Nov-99 23:12:40 GMT"

    assert(Enum.count(jar.get_cookies uri) == 0)
  end

  test "should return cookie headers" do
    jar = CookieJar.new
    uri = "http://foo.com/a/b/c/d"

    jar = jar.set_cookie uri, "a=bar"
    jar = jar.set_cookie uri, "b=baz;path=/a/b/c/d"

    assert(jar.get_cookie_header(uri) == "b=baz;a=bar")
  end

  test "should handle a version 1 cookie" do
    jar = CookieJar.new
    uri = "http://foo.com/a/b/c/d"

    jar = jar.set_cookie uri, "a=bar"
    jar = jar.set_cookie uri, "b=baz;path=/a/b/c/d"
    jar = jar.set_cookie2 uri, "c=baz;Version=1;path=\"/\""

    assert(jar.get_cookie_header(uri) == "$Version=0;b=baz;$Path=\"/a/b/c/d\";a=bar;$Path=\"/a/b/c/\",$Version=1;c=baz;$Path=\"/\"")
  end

  test "should let me add a pre-existing cookie" do
    CookieJar.new.add_cookie(CookieJar.Cookie.from_set_cookie "http://localhost/", "foo=bar")
  end

  test "should return me an array of all cookie objects" do
    jar = CookieJar.new
    uri = "http://foo.com/a/b/c/d"

    jar = jar.set_cookie uri, "a=bar;expires=Wednesday, 09-Nov-99 23:12:40 GMT"
    jar = jar.set_cookie uri, "b=baz;path=/a/b/c/d"
    jar = jar.set_cookie uri, "c=bar;path=/a/b"
    jar = jar.set_cookie uri, "d=bar;path=/a/"
    jar = jar.set_cookie "http://localhost/", "foo=bar"

    assert(Enum.count(jar) == 5)
  end

  test "should expire cookies which are no longer valid" do
    jar = CookieJar.new
    uri = "http://foo.com/a/b/c/d"

    jar = jar.set_cookie uri, "a=bar;expires=Wednesday, 09-Nov-99 23:12:40 GMT"
    jar = jar.set_cookie uri, "b=baz;path=/a/b/c/d;expires=Wednesday, 01-Nov-2028 12:00:00 GMT"
    jar = jar.set_cookie uri, "c=bar;path=/a/b"
    jar = jar.set_cookie uri, "d=bar;path=/a/"
    jar = jar.set_cookie "http://localhost/", "foo=bar"
    assert(Enum.count(jar) == 5)
    jar = jar.expire_cookies
    assert(Enum.count(jar) == 4)
  end

  test "should let me expire all session cookies" do
    jar = CookieJar.new
    uri = "http://foo.com/a/b/c/d"

    jar = jar.set_cookie uri, "a=bar;expires=Wednesday, 09-Nov-99 23:12:40 GMT"
    jar = jar.set_cookie uri, "b=baz;path=/a/b/c/d;expires=Wednesday, 01-Nov-2028 12:00:00 GMT"
    jar = jar.set_cookie uri, "c=bar;path=/a/b"
    jar = jar.set_cookie uri, "d=bar;path=/a/"
    jar = jar.set_cookie "http://localhost/", "foo=bar"

    assert(Enum.count(jar) == 5)
    jar = jar.expire_cookies true
    assert(Enum.count(jar) == 1)
  end

  test "should handle a Set-Cookie header" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "Set-Cookie", "foo=bar" }]

    assert(Enum.count(jar) == 1)
  end

  test "should handle a set-cookie header" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "set-cookie", "foo=bar" }]

    assert(Enum.count(jar) == 1)
  end

  test "should handle a Set-Cookie2 header" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "Set-Cookie2", "foo=bar;Version=1" }]

    assert(Enum.count(jar) == 1)
  end

  test "should handle a set-cookie2 header" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "set-cookie2", "foo=bar;Version=1" }]

    assert(Enum.count(jar) == 1)
  end

  test "should handle multiple Set-Cookie2 headers" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "Set-Cookie2", ["foo=bar;Version=1", "bar=baz;Version=1"] }]

    assert(Enum.count(jar) == 2)
  end

  test "should handle mixed distinct Set-Cookie and Set-Cookie2 headers" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "Set-Cookie", "foo=bar" }, { "Set-Cookie2", "bar=baz;Version=1" }]

    assert(Enum.count(jar) == 2)
  end

  test "should handle overlapping Set-Cookie and Set-Cookie2 headers" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "Set-Cookie", ["foo=bar", "bar=baz"] }, { "Set-Cookie2", "foo=bar;Version=1" }]

    assert(Enum.count(jar) == 2)
    assert(Enum.find(jar, &(&1.name == "foo")).version == 1)
  end

  test "should silently drop invalid cookies" do
    jar = CookieJar.new.set_cookies_from_headers "http://localhost/", [{ "Set-Cookie", ["foo=bar", "bar=baz;domain=.foo.com"] }]

    assert(Enum.count(jar) == 1)
  end
end
