defmodule Cookiejar.Mixfile do
  use Mix.Project

  def project do
    [ app: :cookiejar,
      version: "0.0.1",
      elixir: "~> 0.10.3-dev",
      deps: deps ]
  end

  # Configuration for the OTP application
  def application do
    []
  end

  # Returns the list of dependencies in the format:
  # { :foobar, "~> 0.1", git: "https://github.com/elixir-lang/foobar.git" }
  defp deps do
    [{ :continuum, github: "meh/continuum" }]
  end
end
