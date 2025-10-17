NULL =

PLUGIN_COMMON_DIR = $(srcdir)/../common

AM_CPPFLAGS =                                                   \
        -I$(srcdir)                                             \
        -I$(PLUGIN_COMMON_DIR)                                  \
        -DPREFIX=\""$(prefix)"\"                                \
        -DBINDIR=\""$(bindir)"\"                                \
        -DLIBDIR=\""$(libdir)"\"                                \
        -DLIBEXECDIR=\""$(libexecdir)"\"                        \
        -DDATADIR=\""$(datadir)"\"                              \
        $(DIRSRV_CFLAGS)                                        \
        $(LDAP_CFLAGS)                                          \
        $(WARN_CFLAGS)                                          \
        $(NULL)

plugindir = $(libdir)/dirsrv/plugins
plugin_LTLIBRARIES = \
        libipa-globalcatalog-plugin.la \
        $(NULL)

libipa_globalcatalog_plugin_la_SOURCES = \
        ipa_globalcatalog.c \
        $(NULL)

libipa_globalcatalog_plugin_la_LDFLAGS = -avoid-version

libipa_globalcatalog_plugin_la_LIBADD = \
        $(LDAP_LIBS) \
        $(NULL)

appdir = $(IPA_DATA_DIR)
app_DATA = \
        global-catalog-conf.ldif \
        $(NULL)

EXTRA_DIST = \
        README.md \
        $(app_DATA) \
        $(NULL)
