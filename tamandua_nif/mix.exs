defmodule TamanduaNif.MixProject do
  use Mix.Project

  def project do
    [
      app: :tamandua_nif,
      version: "0.1.0",
      elixir: "~> 1.14",
      description: "Rust NIFs (YARA scanning and native helpers) for the Tamandua EDR server",
      package: package(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: [:rustler] ++ Mix.compilers(),
      rustler_crates: rustler_crates()
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/treant-lab/tamandua-server"}
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.31.0"},
      {:rustler_precompiled, "~> 0.7"},
      {:jason, "~> 1.4"}
    ]
  end

  defp rustler_crates do
    [
      tamandua_nif: [
        path: "native/tamandua_nif",
        mode: rustc_mode(Mix.env()),
        # Precompilation support
        targets: ~w(
          x86_64-unknown-linux-gnu
          x86_64-unknown-linux-musl
          x86_64-pc-windows-msvc
          x86_64-pc-windows-gnu
          x86_64-apple-darwin
          aarch64-apple-darwin
        ),
        # Feature flags
        default_features: true,
        features: ["yara"]
      ]
    ]
  end

  defp rustc_mode(:prod), do: :release
  defp rustc_mode(_), do: :debug
end
