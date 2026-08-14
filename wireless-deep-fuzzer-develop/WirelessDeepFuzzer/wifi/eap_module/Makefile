ALL=python_module
HOSTAP_PATH=hostap
HOSTAP_COMMIT=018edec9b2bd3db20605117c32ff79c1e625c432

all: $(ALL)

CONFIG_TLS_DEFAULT_CIPHERS = "DEFAULT:!EXP:!LOW"
CONFIG_TLS=openssl

ifndef CC
CC=gcc
endif

ifndef RANLIB
RANLIB=ranlib
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g -fPIC -lssl -lcrypto
endif

CFLAGS += -I.
CFLAGS += -I$(HOSTAP_PATH)/src
CFLAGS += -I$(HOSTAP_PATH)/src/utils


OBJS_both = $(HOSTAP_PATH)/src/utils/libutils.a
OBJS_both += $(HOSTAP_PATH)/src/crypto/tls_openssl.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/tls_openssl_ocsp.o
OBJS_both += $(HOSTAP_PATH)/src/common/dragonfly.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/crypto_openssl.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/ms_funcs.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/crypto_internal-cipher.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/random.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/aes-omac1.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/aes-eax.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/aes-ctr.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/aes-encblock.o
OBJS_both += $(HOSTAP_PATH)/src/crypto/sha256.o


CFLAGS += -DTLS_DEFAULT_CIPHERS=\"$(CONFIG_TLS_DEFAULT_CIPHERS)\"
CFLAGS += -DCONFIG_CRYPTO=\"openssl\"



OBJS_both += $(HOSTAP_PATH)/src/eap_common/eap_peap_common.o
OBJS_both += $(HOSTAP_PATH)/src/eap_common/eap_pwd_common.o
OBJS_both += $(HOSTAP_PATH)/src/eap_common/eap_psk_common.o
OBJS_both += $(HOSTAP_PATH)/src/eap_common/eap_pax_common.o
OBJS_both += $(HOSTAP_PATH)/src/eap_common/eap_sake_common.o
OBJS_both += $(HOSTAP_PATH)/src/eap_common/eap_gpsk_common.o
OBJS_both += $(HOSTAP_PATH)/src/eap_common/chap.o


OBJS_peer = $(HOSTAP_PATH)/src/eap_peer/eap_tls.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_peap.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_pwd.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_ttls.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_md5.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_mschapv2.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/mschapv2.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_otp.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_gtc.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_leap.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_psk.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_pax.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_sake.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_gpsk.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_common/eap_common.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_methods.o
OBJS_peer += $(HOSTAP_PATH)/src/eap_peer/eap_tls_common.o

CFLAGS += -DEAP_TLS
CFLAGS += -DEAP_PEAP
CFLAGS += -DEAP_TTLS
CFLAGS += -DEAP_MD5
CFLAGS += -DEAP_MSCHAPv2
CFLAGS += -DEAP_GTC
CFLAGS += -DEAP_OTP
CFLAGS += -DEAP_PWD -DCONFIG_ECC
CFLAGS += -DEAP_LEAP
CFLAGS += -DEAP_PSK
CFLAGS += -DEAP_PAX
CFLAGS += -DEAP_SAKE
CFLAGS += -DEAP_GPSK -DEAP_GPSK_SHA256

CFLAGS += -DEAP_SERVER_IDENTITY
CFLAGS += -DEAP_SERVER_TLS
CFLAGS += -DEAP_SERVER_PEAP
CFLAGS += -DEAP_SERVER_TTLS
CFLAGS += -DEAP_SERVER_MD5
CFLAGS += -DEAP_SERVER_MSCHAPV2
CFLAGS += -DEAP_SERVER_GTC
CFLAGS += -DEAP_SERVER_PWD
CFLAGS += -DEAP_SERVER_PSK
CFLAGS += -DEAP_SERVER_PAX
CFLAGS += -DEAP_SERVER_SAKE
CFLAGS += -DEAP_SERVER_GPSK -DEAP_SERVER_GPSK_SHA256

CFLAGS += -DIEEE8021X_EAPOL
CFLAGS += -DCONFIG_NO_WPA_MSG
CFLAGS += -DCONFIG_NO_STDOUT_DEBUG

# Optional components to add EAP server support
OBJS_server = $(HOSTAP_PATH)/src/eap_server/eap_server_tls.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_peap.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_ttls.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_md5.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_pwd.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_mschapv2.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_gtc.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_psk.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_pax.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_sake.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_gpsk.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_identity.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_methods.o
OBJS_server += $(HOSTAP_PATH)/src/eap_server/eap_server_tls_common.o
OBJS_server += $(HOSTAP_PATH)/src/utils/wpabuf.o
CFLAGS += -DEAP_SERVER




ifndef LDO
LDO=$(CC)
endif

Q=@
E=echo
ifeq ($(V), 1)
Q=
E=true
endif

%.o: %.c
	$(Q)$(CC) -c -o $@ $(CFLAGS) $<
	@$(E) "  CC " $<


OBJS_lib=$(OBJS_both) $(OBJS_peer) $(OBJS_server)

OBJS_ex = eap_example.o eap_peer.o eap_server.o


$(HOSTAP_PATH)/src/utils/libutils.a:
	$(MAKE) -C $(HOSTAP_PATH)/src/utils

$(HOSTAP_PATH)/src/crypto/libcrypto.a:
	$(MAKE) -C $(HOSTAP_PATH)/src/crypto

$(HOSTAP_PATH)/src/tls/libtls.a:
	$(MAKE) -C $(HOSTAP_PATH)/src/tls


ifneq ($(CONFIG_SOLIB), yes)
LIBEAP = libeap.a
libeap.a: $(OBJS_lib)
	$(AR) crT libeap.a $(OBJS_lib)
	$(RANLIB) libeap.a

else
CFLAGS  += -fPIC -DPIC
LDFLAGS += -shared

LIBEAP  = libeap.so
libeap.so: $(OBJS_lib)
	$(LDO) $(LDFLAGS) $(OBJS_lib) -o $(LIBEAP)

endif

eap_example: $(OBJS_ex) $(LIBEAP)
	$(LDO) $(LDFLAGS) -o eap_example $(OBJS_ex) -L. -leap

verify_hostap:
ifeq ($(wildcard ./hostap/src/.),)
		git clone git://w1.fi/hostap.git hostap
		cd hostap && git checkout $(HOSTAP_COMMIT)
		make clean
endif

python_module: verify_hostap libeap.a
	python setup.py build

install:
	python setup.py install

clean:
	$(MAKE) -C $(HOSTAP_PATH)/src clean
	rm -f core *~ *.o *.d libeap.a libeap.so $(ALL)
	rm -rdf dist
	rm -rdf build
	rm -rdf EAPModule.egg-info
	find . -type f -name '*.o' -delete
	find . -type f -name '*.a' -delete

-include $(OBJS:%.o=%.d)