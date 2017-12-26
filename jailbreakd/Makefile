ARCHS=arm64
GO_EASY_ON_ME=1
include $(THEOS)/makefiles/common.mk

TOOL_NAME = jailbreakd
jailbreakd_FILES = main.m patchfinder64.c kern_utils.m
jailbreakd_CFLAGS = -I.
jailbreakd_CODESIGN_FLAGS=-SEnt.plist

include $(THEOS_MAKE_PATH)/tool.mk
