# typed: strict
# frozen_string_literal: true

class Igropyr < Formula
  desc "High-concurrency HTTP server framework for Chez Scheme on libuv"
  homepage "https://github.com/guenchi/Igropyr"
  url "https://github.com/guenchi/Igropyr/archive/refs/tags/1.0.0.tar.gz"
  sha256 "b394ad0c3a25e244936dd83bf1d25ac549e6d661ab17aba2cda92b2833397989"
  license "MIT"

  depends_on "chezscheme"
  depends_on "libuv"

  def install
    # R6RS library sources; the library directory must be named
    # "igropyr" (lowercase) so (import (igropyr http)) resolves.
    (share/"igropyr-libs/igropyr").install Dir["*.sc"]
    (share/"igropyr-libs/igropyr").install "docs", "test", "public"
    Dir["*.ss"].each { |f| (share/"igropyr-libs/igropyr").install f }
    doc.install "README.md", "README.zh-CN.md"
  end

  def caveats
    <<~EOS
      Add the library path to your Chez Scheme environment:

        export CHEZSCHEMELIBDIRS=#{share}/igropyr-libs:.
        export CHEZSCHEMELIBEXTS=.chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so

      Then in your program:

        (import (chezscheme) (igropyr http) (igropyr express))

      Try the demo server:

        cd #{share}/igropyr-libs
        scheme --script igropyr/test/run-otp.sc
    EOS
  end

  test do
    ENV["CHEZSCHEMELIBDIRS"] = "#{share}/igropyr-libs:."
    ENV["CHEZSCHEMELIBEXTS"] =
      ".chezscheme.sls::.chezscheme.so:.ss::.so:.sls::.so:.scm::.so:.sch::.so:.sc::.so"
    (testpath/"t.sc").write <<~EOS
      (import (chezscheme) (igropyr http) (igropyr express) (igropyr json))
      (assert (procedure? start-scheduler))
      (assert (procedure? create-app))
      (assert (equal? (json->string (list (cons 'ok 1))) "{\\"ok\\":1}"))
      (display "igropyr ok\\n")
    EOS
    assert_match "igropyr ok", shell_output("scheme --script t.sc")
  end
end
