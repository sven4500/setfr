TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

INCLUDEPATH += \
    $$PWD/../../src

HEADERS += \
    $$PWD/../../src/headers.h

SOURCES += \
    $$PWD/../../src/main.cpp

LIBS += -lpthread
