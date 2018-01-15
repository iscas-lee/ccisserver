# Authors:
# *  Kobe Lee    lixiang@kylinos.cn/kobe24_lixiang@126.com

set(PKGBINDIR /usr/bin/)

set(SRC_SOURCES
    main.c
    ccis.h
    type.h
    camera/FaceMatcher.c
    camera/FaceMatcher.h
    camera/FaceMatcherDll.h
    camera/fdreadimage.h
    configure/configure.c
    configure/configure.h
    database/dbquery.c
    database/dbquery.h
    database/sql_pool.c
    database/sql_pool.h
    log/log.c
    log/ccis_log.h
    network/network.c
    network/network.h
    network/ssl/ssl.c
    network/ssl/ssl.h
    network/ssl/connect.c
    network/ssl/connect.h
    other/ccis_charset.c
    other/ccis_charset.h
    other/ccis_common.c
    other/ccis_common.h
    other/ccis_compress.c
    other/ccis_compress.h
    other/ccis_string.c
    other/ccis_string.h
    other/ccis_thread.c
    other/ccis_thread.h
    other/ccis_time.c
    other/ccis_time.h
    other/ccis_system.h
    other/ccis_system.c
    client/client_login.c
    client/client_login.h
    schedule/business_schedule.c
    schedule/flow_control.c
    schedule/flow_control.h
    schedule/global_schedule.c
    schedule/global_schedule.h
    schedule/client_schedule.c
    schedule/epoll/ccis_epoll.c
    schedule/epoll/ccis_epoll.h
    security/security.c
    security/security.h
    security/tpm/e_tpm_err.c
    security/tpm/tpmapi.c
    security/tpm/tpmapi.h
    security/struct/security_struct.h
    security/struct/security_struct.c
    security/ca/apps.c
    security/ca/apps.h
    security/ca/ca.c
    security/ca/e_os.h
    security/ca/ocsp.c
    server/server.c
    server/server.h
    server/online_charge.c
    server/online_charge.h
    server/pbc/pbc.c
    server/pbc/pbc.h
    server/pbc/agent/upload_agent.h
    server/pbc/agent/upload_agent.c
    server/struct/server_struct.c
    server/struct/server_struct.h
    plugins/monitor.c
    plugins/monitor.h
    plugins/ukey_register.c
    plugins/tpm_register.c
    plugins/register.h
    system/resource.c
    system/resource.h)

SET(SERVER_LIBS_PRIVATE "-ldl -lhtmlstreamparser -lm -lcrypto -llz4 -lpcre -lssl -lpthread -lcurl -lmysqlclient -lsystemd -ltspi -lFaceMatcherDll -lfdreadimage -l:libshuttle_p11v220.so.1.0.0")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

find_package (PkgConfig REQUIRED)
set(SERVER_SHARED_DEPS
    gthread-2.0
    glib-2.0
    libcurl
    libssl
    libcrypto
    libpcre
)

pkg_check_modules (CACHED_SERVER_SHARED_DEPS REQUIRED ${SERVER_SHARED_DEPS})

include_directories(${CACHED_SERVER_SHARED_DEPS_INCLUDE_DIRS})
link_directories(${CACHED_SERVER_SHARED_DEPS_LIBRARY_DIRS})
add_definitions(${CACHED_SERVER_SHARED_DEPS_CFLAGS_OTHER})

add_executable(CCISServer ${SRC_SOURCES})
#add link library
target_link_libraries(CCISServer ${CACHED_SERVER_SHARED_DEPS_LIBRARIES} ${SERVER_LIBS_PRIVATE})

install(TARGETS CCISServer RUNTIME DESTINATION ${PKGBINDIR})
