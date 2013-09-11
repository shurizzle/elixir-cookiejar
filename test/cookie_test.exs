defmodule CookieTest do
  use ExUnit.Case

  alias CookieJar.Cookie
  alias CookieJar.InvalidCookieError

  foo_url = "http://localhost/foo"
  ammo_url = "http://localhost/ammo"
  netscape_spec_set_cookie_headers = [
    { "CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT", foo_url },
    { "PART_NUMBER=ROCKET_LAUNCHER_0001; path=/", foo_url },
    { "SHIPPING=FEDEX; path=/foo", foo_url },
    { "PART_NUMBER=ROCKET_LAUNCHER_0001; path=/", foo_url },
    { "PART_NUMBER=RIDING_ROCKET_0023; path=/ammo", ammo_url }
  ]

  test "should handle cookies from the netscape spec" do
    Enum.each unquote(netscape_spec_set_cookie_headers), fn({ header, url }) ->
      Cookie.from_set_cookie url, header
    end
  end

  test "should give back the input names and values" do
    cookie = Cookie.from_set_cookie "http://localhost/", "foo=bar"
    assert(cookie.name == "foo")
    assert(cookie.value == "bar")
  end

  test "should normalize domain names" do
    cookie = Cookie.from_set_cookie "http://localhost/", "foo=Bar;domain=LoCaLHoSt.local"
    assert(cookie.domain == ".localhost.local")
  end

  test "should accept non-normalized .local" do
    cookie = Cookie.from_set_cookie "http://localhost/", "foo=bar;domain=.local"
    assert(cookie.domain == ".local")
  end

  test "should accept secure cookies" do
    cookie = Cookie.from_set_cookie "https://www.google.com/a/blah", "GALX=RgmSftjnbPM;Path=/a/;Secure"
    assert(cookie.name == "GALX")
    assert(cookie.secure)
  end

  test "should give back the input names and values (2)" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "foo=bar;Version=1"
    assert(cookie.name == "foo")
    assert(cookie.value == "bar")
  end

  test "should normalize domain names (2)" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "foo=Bar;domain=LoCaLHoSt.local;Version=1"
    assert(cookie.domain == ".localhost.local")
  end

  test "should accept non-normalized .local (2)" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "foo=bar;domain=.local;Version=1"
    assert(cookie.domain == ".local")
  end

  test "should accept secure cookies (2)" do
    cookie = Cookie.from_set_cookie2 "https://www.google.com/a/blah", "GALX=RgmSftjnbPM;Path=\"/a/\";Secure;Version=1"
    assert(cookie.name == "GALX")
    assert(cookie.path == "/a/")
    assert(cookie.secure)
  end

  test "should fail on unquoted paths" do
    assert_raise InvalidCookieError, fn ->
      Cookie.from_set_cookie2 "https://www.google.com/a/blah", "GALX=RgmSftjnbPM;Path=/a/;Secure;Version=1"
    end
  end

  test "should accept quoted values" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "foo=\"bar\";Version=1"
    assert(cookie.name == "foo")
    assert(cookie.value == "\"bar\"")
  end

  test "should accept poorly chosen names" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "Version=mine;Version=1"
    assert(cookie.name == "Version")
    assert(cookie.value == "mine")
  end

  test "should accept quoted parameter values" do
    Cookie.from_set_cookie2 "http://localhost/", "foo=bar;Version=\"1\""
  end

  test "should honor the discard and max-age parameters" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=b;max-age=100;discard;Version=1"
    assert(cookie.session?)
    assert(!cookie.expired?)

    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=b;max-age=100;Version=1"
    assert(!cookie.session?)

    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=b;Version=1"
    assert(cookie.session?)
  end

  test "should handle quotable quotes" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=\"\\\"\";Version=1"
    assert(cookie.value == "\"\\\"\"")
  end

  test "should handle quotable apostrophes" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=\"\\;\";Version=1"
    assert(cookie.value == "\"\\;\"")
  end

  test "should leave normal values alone" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=b;Version=1"
    assert(cookie.decoded_value == "b")
  end

  test "should attempt to unencode quoted values" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=\"\\\"b\";Version=1"
    assert(cookie.value == "\"\\\"b\"")
    assert(cookie.decoded_value == "\"b")
  end

  test "should handle a simple cookie" do
    cookie = Cookie.from_set_cookie "http://localhost/", "f=b"
    assert(cookie.to_string == "f=b")
    assert(cookie.to_string(1) == "$Version=0;f=b;$Path=\"/\"")
  end

  test "should report an explicit domain" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=b;Version=1;Domain=.local"
    assert(cookie.to_string(1) == "$Version=1;f=b;$Path=\"/\";$Domain=.local")
  end

  test "should return specified ports" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=b;Version=1;Port=\"80,443\""
    assert(cookie.to_string(1) == "$Version=1;f=b;$Path=\"/\";$Port=\"80,443\"")
  end

  test "should handle specified paths" do
    cookie = Cookie.from_set_cookie "http://localhost/bar/", "f=b;path=/bar/"
    assert(cookie.to_string == "f=b")
    assert(cookie.to_string(1) == "$Version=0;f=b;$Path=\"/bar/\"")
  end

  test "should omit $Version header when asked" do
    cookie = Cookie.from_set_cookie "http://localhost/", "f=b"
    assert(cookie.to_string(1, false) == "f=b;$Path=\"/\"")
  end

  test "should not send if ports do not match" do
    cookie = Cookie.from_set_cookie2 "http://localhost/", "f=b;Version=1;Port=\"80\""
    assert(cookie.should_send?("http://localhost/", false) == true)
    assert(cookie.should_send?("https://localhost/", false) == false)
  end
end
