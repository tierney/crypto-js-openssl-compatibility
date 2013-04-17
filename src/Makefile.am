bin_PROGRAMS = main
main_SOURCES = main.cc
main_LDADD = -lcrypto -ldl libbase64.a libcrypto.a

noinst_LIBRARIES =
noinst_LIBRARIES += libbase64.a
libbase64_a_SOURCES = base64.cc base64.h

noinst_LIBRARIES += libcrypto.a
libcrypto_a_SOURCES = crypto.cc crypto.h
libcrypto_a_SOURCES +=
libcrypto_a_SOURCES += base/basictypes.h
libcrypto_a_SOURCES += base/compiler_specific.h
libcrypto_a_SOURCES += base/memory/scoped_ptr.h
libcrypto_a_SOURCES += base/move.h
libcrypto_a_SOURCES += base/port.h
libcrypto_a_SOURCES += base/template_util.h
libcrypto_a_SOURCES += build/build_config.h

noinst_LIBRARIES += libfile_util.a
libfile_util_a_SOURCES = file_util.cc file_util.h
