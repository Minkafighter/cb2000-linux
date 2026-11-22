project('cb2000-libfprint-tod', 'c',
  version: '0.1.0',
  license: 'MIT',
  default_options: [
    'warning_level=2',
    'c_std=c11',
  ],
  meson_version: '>= 0.56.0',
)

libfprint_tod_dep = dependency('libfprint-2-tod-1', version: '>= 1.94.0')
glib_dep = dependency('glib-2.0')
gobject_dep = dependency('gobject-2.0')
gio_dep = dependency('gio-2.0')
gusb_dep = dependency('gusb')

tod_driversdir = libfprint_tod_dep.get_variable(pkgconfig: 'tod_driversdir')

find_program('cargo')
cc = meson.get_compiler('c')
threads_dep = cc.find_library('pthread')
dl_dep = cc.find_library('dl')
m_dep = cc.find_library('m')

rust_staticlib = custom_target('cb2000-tod-staticlib',
  output: 'libcb2000_tod.a',
  command: [
    'sh', '-c',
    'cargo build --release --manifest-path "@0@/Cargo.toml" -p cb2000-tod && cp "@0@/target/release/libcb2000_tod.a" "@1@"'.format(
      meson.current_source_dir() / '..',
      '@OUTPUT@',
    ),
  ],
  build_by_default: true,
)

shared_module('fprint-2-tod-1-cb2000',
  sources: ['cb2000_tod.c', rust_staticlib],
  name_prefix: 'lib',
  include_directories: include_directories('../crates/cb2000-tod/include'),
  c_args: ['-fvisibility=hidden'],
  link_args: ['-Wl,--exclude-libs,ALL'],
  dependencies: [
    libfprint_tod_dep,
    glib_dep,
    gobject_dep,
    gio_dep,
    gusb_dep,
    threads_dep,
    dl_dep,
    m_dep,
  ],
  install: true,
  install_dir: tod_driversdir,
)
