# Maintainer: Emil Renner Berthing <esmil@mailme.dk>

pkgname=lua-sha1
pkgver=1.0
pkgrel=1
pkgdesc="Small SHA1 library for Lua (compiled for LEM)"
arch=('i686' 'x86_64' 'armv5tel' 'armv7l')
url="https://github.com/esmil/lua-sha1"
license=('GPL')
depends=('lem')
source=()

build() {
  cd "$startdir"

  make NDEBUG=1 LUA_INCDIR='/usr/include/lem'
}

package() {
  cd "$startdir"

  make DESTDIR="$pkgdir/" PREFIX='/usr' \
    LUA_PATH="$(pkg-config --variable=path lem)" \
    LUA_CPATH="$(pkg-config --variable=cpath lem)" \
    install
}

# vim:set ts=2 sw=2 et:
